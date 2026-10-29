package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"
)

var nativeEndian binary.ByteOrder = binary.LittleEndian

const (
	sofTimestampingRXSoftware = 1 << 3
	rxTimestampOOBLen         = 256
)

// recordRXTimestampReader receives the ordinary TCP byte stream together with
// the kernel RX timestamp attached to the last skb copied by each recvmsg.
// Timestamp generation happens on kernel ingress, so delaying recvmsg does not
// turn this into an application dequeue timestamp.
type recordRXTimestampReader struct {
	conn net.Conn
	raw  syscall.RawConn
}

func newRecordRXTimestampReader(conn net.Conn) (*recordRXTimestampReader, error) {
	if conn == nil {
		return nil, errors.New("nil RX timestamp connection")
	}
	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("RX connection %T does not expose syscall.Conn", conn)
	}
	raw, err := sysConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("get RX raw connection: %w", err)
	}
	flags := sofTimestampingRXSoftware | sofTimestampingSoftware
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		socketErr = syscall.SetsockoptInt(
			int(fd),
			syscall.SOL_SOCKET,
			syscall.SO_TIMESTAMPING,
			flags,
		)
	}); err != nil {
		return nil, err
	}
	if socketErr != nil {
		return nil, fmt.Errorf("enable RX software timestamping: %w", socketErr)
	}
	return &recordRXTimestampReader{conn: conn, raw: raw}, nil
}

func (r *recordRXTimestampReader) Read(p []byte) (int, error) {
	n, _, _, err := r.ReadWithRXTimestamp(p)
	return n, err
}

// ReadWithRXTimestamp returns the kernel timestamp for the last TCP skb that
// contributed bytes to this call. The boolean is false when the kernel did not
// attach a usable timestamp, which callers must not silently replace with a
// userspace dequeue time for adaptive timing decisions.
func (r *recordRXTimestampReader) ReadWithRXTimestamp(p []byte) (int, time.Time, bool, error) {
	if len(p) == 0 {
		return 0, time.Time{}, false, nil
	}
	if r == nil || r.raw == nil {
		if r == nil || r.conn == nil {
			return 0, time.Time{}, false, errors.New("nil RX timestamp reader")
		}
		n, err := r.conn.Read(p)
		return n, time.Time{}, false, err
	}

	for {
		var (
			n        int
			oobLen   int
			msgFlags int
			recvErr  error
			oob      [rxTimestampOOBLen]byte
		)
		err := r.raw.Read(func(fd uintptr) bool {
			n, oobLen, msgFlags, _, recvErr = syscall.Recvmsg(
				int(fd),
				p,
				oob[:],
				syscall.MSG_DONTWAIT,
			)
			if errors.Is(recvErr, syscall.EAGAIN) || errors.Is(recvErr, syscall.EWOULDBLOCK) {
				recvErr = nil
				return false
			}
			return true
		})
		if err != nil {
			return 0, time.Time{}, false, err
		}
		if errors.Is(recvErr, syscall.EINTR) {
			continue
		}
		if recvErr != nil {
			return n, time.Time{}, false, recvErr
		}
		if n == 0 {
			return 0, time.Time{}, false, io.EOF
		}
		if msgFlags&syscall.MSG_CTRUNC != 0 {
			// The stream bytes are still valid and cannot be read again. Treat a
			// damaged ancillary message as an untrusted timestamp so forwarding
			// continues while adaptive insertion fails closed for this Record.
			return n, time.Time{}, false, nil
		}
		at, ok, parseErr := parseRXTimestampControl(oob[:oobLen])
		if parseErr != nil {
			return n, time.Time{}, false, nil
		}
		return n, at, ok, nil
	}
}

func parseRXTimestampControl(oob []byte) (time.Time, bool, error) {
	messages, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return time.Time{}, false, err
	}
	for _, message := range messages {
		if message.Header.Level != syscall.SOL_SOCKET ||
			message.Header.Type != syscall.SCM_TIMESTAMPING ||
			len(message.Data) < 16 {
			continue
		}
		seconds := int64(nativeEndian.Uint64(message.Data[0:8]))
		nanoseconds := int64(nativeEndian.Uint64(message.Data[8:16]))
		if seconds == 0 && nanoseconds == 0 {
			continue
		}
		return time.Unix(seconds, nanoseconds), true, nil
	}
	return time.Time{}, false, nil
}

type rxTimestampedReader interface {
	ReadWithRXTimestamp([]byte) (int, time.Time, bool, error)
}

// readFullWithRXTimestamp mirrors io.ReadFull while retaining only the RX
// timestamp associated with the call that supplied the final requested byte.
func readFullWithRXTimestamp(r io.Reader, dst []byte) (time.Time, bool, error) {
	if len(dst) == 0 {
		return time.Time{}, false, nil
	}
	timestamped, hasTimestampReader := r.(rxTimestampedReader)
	read := 0
	var (
		lastAt      time.Time
		lastTrusted bool
	)
	for read < len(dst) {
		var (
			n   int
			err error
			at  time.Time
			ok  bool
		)
		if hasTimestampReader {
			n, at, ok, err = timestamped.ReadWithRXTimestamp(dst[read:])
		} else {
			n, err = r.Read(dst[read:])
		}
		if n > 0 {
			read += n
			lastAt = at
			lastTrusted = ok && !at.IsZero()
		}
		if read == len(dst) {
			return lastAt, lastTrusted, nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if read == 0 {
					return time.Time{}, false, io.EOF
				}
				return time.Time{}, false, io.ErrUnexpectedEOF
			}
			return time.Time{}, false, err
		}
		if n == 0 {
			return time.Time{}, false, io.ErrNoProgress
		}
	}
	return lastAt, lastTrusted, nil
}
