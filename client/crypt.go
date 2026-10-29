package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	tlsRecordHeaderLen = 5

	tlsTypeHandshake       = 22
	tlsTypeApplicationData = 23

	markerLen          = 16
	nonceLen           = 12
	authTagLen         = 16
	fixedCiphertextLen = 1024
	embeddedPayloadLen = markerLen + fixedCiphertextLen + authTagLen
	covertHeaderLen    = 5
	minPSKLen          = 32

	maxTLSRecordPayloadLen = 1 << 15
)

var errEmbeddedAuth = errors.New("embedded record authentication failed")

type TLSRecordHeader struct {
	ContentType byte
	Version     [2]byte
	Length      uint16
}

type ConnKeys struct {
	KMarker []byte
	KAEAD   []byte
	KNonce  []byte
}

type ExtractedRecord struct {
	Seq    uint64
	Header TLSRecordHeader
	Data   []byte
}

func deriveConnSalt(clientRandom, serverRandom []byte) ([]byte, error) {
	if len(clientRandom) != 32 {
		return nil, fmt.Errorf("client random length must be 32 bytes, got %d", len(clientRandom))
	}
	if len(serverRandom) != 32 {
		return nil, fmt.Errorf("server random length must be 32 bytes, got %d", len(serverRandom))
	}

	h := sha256.New()
	_, _ = h.Write(clientRandom)
	_, _ = h.Write(serverRandom)
	return h.Sum(nil), nil
}

func deriveConnKeys(psk, clientRandom, serverRandom []byte) (*ConnKeys, error) {
	return deriveConnKeysWithInfo(psk, clientRandom, serverRandom, "marker", "aead", "nonce")
}

// deriveDownlinkConnKeys must remain byte-for-byte compatible with tls_sp's
// server-to-client embedding keys.
func deriveDownlinkConnKeys(psk, clientRandom, serverRandom []byte) (*ConnKeys, error) {
	return deriveConnKeysWithInfo(psk, clientRandom, serverRandom, "s2c-marker", "s2c-aead", "s2c-nonce")
}

func deriveConnKeysWithInfo(psk, clientRandom, serverRandom []byte, markerInfo, aeadInfo, nonceInfo string) (*ConnKeys, error) {
	if len(psk) < minPSKLen {
		return nil, fmt.Errorf("psk length must be at least %d bytes, got %d", minPSKLen, len(psk))
	}

	salt, err := deriveConnSalt(clientRandom, serverRandom)
	if err != nil {
		return nil, err
	}

	connSecret := hkdfExtract(salt, psk)
	return &ConnKeys{
		KMarker: hkdfExpand(connSecret, []byte(markerInfo), 32),
		KAEAD:   hkdfExpand(connSecret, []byte(aeadInfo), 32),
		KNonce:  hkdfExpand(connSecret, []byte(nonceInfo), 32),
	}, nil
}

func markerForSeq(key []byte, seq uint64) []byte {
	sum := hmacSHA256(key, seqBytes(seq))
	return append([]byte(nil), sum[:markerLen]...)
}

func nonceForSeq(key []byte, seq uint64) []byte {
	sum := hmacSHA256(key, seqBytes(seq))
	return append([]byte(nil), sum[:nonceLen]...)
}

func buildEmbeddedTLSRecord(template TLSRecordHeader, keys *ConnKeys, seq uint64, covertData []byte) ([]byte, error) {
	return buildEmbeddedTLSRecordSized(template, keys, seq, covertData, tlsRecordHeaderLen+embeddedPayloadLen)
}

// buildEmbeddedTLSRecordSized builds a complete TLS record whose observable
// wire length is exactly totalLen. The adaptive inserter only calls this with
// lengths that were observed on normal records.
func buildEmbeddedTLSRecordSized(template TLSRecordHeader, keys *ConnKeys, seq uint64, covertData []byte, totalLen int) ([]byte, error) {
	if keys == nil {
		return nil, errors.New("connection keys are not ready")
	}
	plaintextLen := embeddedPlaintextLenForRecord(totalLen)
	if plaintextLen < covertHeaderLen {
		return nil, fmt.Errorf("embedded TLS record length %d is below minimum %d", totalLen, minEmbeddedTLSRecordLen())
	}
	if totalLen > tlsRecordHeaderLen+maxTLSRecordPayloadLen {
		return nil, fmt.Errorf("embedded TLS record length %d exceeds maximum %d", totalLen, tlsRecordHeaderLen+maxTLSRecordPayloadLen)
	}

	plain, err := buildCovertPlaintext(template, covertData, plaintextLen)
	if err != nil {
		return nil, err
	}

	marker := markerForSeq(keys.KMarker, seq)
	nonce := nonceForSeq(keys.KNonce, seq)

	block, err := aes.NewCipher(keys.KAEAD)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if aead.NonceSize() != nonceLen {
		return nil, fmt.Errorf("unexpected AES-GCM nonce size: %d", aead.NonceSize())
	}

	ciphertextAndTag := aead.Seal(nil, nonce, plain, marker)
	if len(ciphertextAndTag) != plaintextLen+authTagLen {
		return nil, fmt.Errorf("unexpected ciphertext/tag length: %d", len(ciphertextAndTag))
	}

	payload := make([]byte, 0, embeddedPayloadLen)
	payload = append(payload, marker...)
	payload = append(payload, ciphertextAndTag...)

	recordHeader := TLSRecordHeader{
		ContentType: template.ContentType,
		Version:     template.Version,
		Length:      uint16(len(payload)),
	}
	if recordHeader.ContentType == 0 {
		recordHeader.ContentType = tlsTypeApplicationData
	}
	record := append(recordHeader.bytes(), payload...)
	if len(record) != totalLen {
		return nil, fmt.Errorf("embedded TLS record length = %d, want %d", len(record), totalLen)
	}
	return record, nil
}

func minEmbeddedTLSRecordLen() int {
	return tlsRecordHeaderLen + markerLen + authTagLen + covertHeaderLen
}

func embeddedPlaintextLenForRecord(totalLen int) int {
	return totalLen - tlsRecordHeaderLen - markerLen - authTagLen
}

func embeddedCovertCapacity(totalLen int) int {
	capacity := embeddedPlaintextLenForRecord(totalLen) - covertHeaderLen
	if capacity < 0 {
		return 0
	}
	return capacity
}

func buildCovertPlaintext(template TLSRecordHeader, data []byte, totalLen int) ([]byte, error) {
	if totalLen < covertHeaderLen {
		return nil, fmt.Errorf("covert plaintext length %d is too small", totalLen)
	}
	if len(data) > totalLen-covertHeaderLen {
		return nil, fmt.Errorf("covert data length %d exceeds fixed plaintext capacity %d", len(data), totalLen-covertHeaderLen)
	}
	if len(data) > 0xffff {
		return nil, fmt.Errorf("covert data length %d exceeds uint16", len(data))
	}

	plain := make([]byte, totalLen)
	binary.BigEndian.PutUint16(plain[0:2], uint16(len(data)))
	plain[2] = template.ContentType
	copy(plain[3:5], template.Version[:])
	copy(plain[5:], data)
	return plain, nil
}

func recordHasMarker(record []byte, keys *ConnKeys, seq uint64) bool {
	if keys == nil || len(record) < tlsRecordHeaderLen+markerLen+authTagLen {
		return false
	}

	header, err := parseTLSRecordHeader(record[:tlsRecordHeaderLen])
	if err != nil || header.ContentType != tlsTypeApplicationData {
		return false
	}
	if int(header.Length) != len(record)-tlsRecordHeaderLen {
		return false
	}

	payload := record[tlsRecordHeaderLen:]
	return hmac.Equal(payload[:markerLen], markerForSeq(keys.KMarker, seq))
}

func decryptEmbeddedTLSRecord(record []byte, keys *ConnKeys, seq uint64) (*ExtractedRecord, bool, bool, error) {
	if !recordHasMarker(record, keys, seq) {
		return nil, false, false, nil
	}

	header, err := parseTLSRecordHeader(record[:tlsRecordHeaderLen])
	if err != nil {
		return nil, true, false, err
	}
	payload := record[tlsRecordHeaderLen : tlsRecordHeaderLen+int(header.Length)]
	marker := payload[:markerLen]
	ciphertextAndTag := payload[markerLen:]

	block, err := aes.NewCipher(keys.KAEAD)
	if err != nil {
		return nil, true, false, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, true, false, err
	}
	if aead.NonceSize() != nonceLen {
		return nil, true, false, fmt.Errorf("unexpected AES-GCM nonce size: %d", aead.NonceSize())
	}

	plaintext, err := aead.Open(nil, nonceForSeq(keys.KNonce, seq), ciphertextAndTag, marker)
	if err != nil {
		return nil, true, false, fmt.Errorf("%w: %v", errEmbeddedAuth, err)
	}

	extracted, err := parseCovertPlaintext(seq, plaintext)
	if err != nil {
		return nil, true, true, err
	}
	return extracted, true, true, nil
}

func parseCovertPlaintext(seq uint64, plaintext []byte) (*ExtractedRecord, error) {
	if len(plaintext) < covertHeaderLen {
		return nil, fmt.Errorf("covert plaintext requires at least %d bytes, got %d", covertHeaderLen, len(plaintext))
	}

	dataLen := int(binary.BigEndian.Uint16(plaintext[0:2]))
	if dataLen > len(plaintext)-covertHeaderLen {
		return nil, fmt.Errorf("covert data length %d exceeds plaintext capacity %d", dataLen, len(plaintext)-covertHeaderLen)
	}

	data := make([]byte, dataLen)
	copy(data, plaintext[covertHeaderLen:covertHeaderLen+dataLen])

	return &ExtractedRecord{
		Seq: seq,
		Header: TLSRecordHeader{
			ContentType: plaintext[2],
			Version:     [2]byte{plaintext[3], plaintext[4]},
			Length:      uint16(dataLen),
		},
		Data: data,
	}, nil
}

func parseTLSRecordHeader(header []byte) (TLSRecordHeader, error) {
	if len(header) < tlsRecordHeaderLen {
		return TLSRecordHeader{}, fmt.Errorf("tls record header requires %d bytes, got %d", tlsRecordHeaderLen, len(header))
	}
	length := binary.BigEndian.Uint16(header[3:5])
	if int(length) > maxTLSRecordPayloadLen {
		return TLSRecordHeader{}, fmt.Errorf("tls record payload length %d exceeds limit %d", length, maxTLSRecordPayloadLen)
	}

	return TLSRecordHeader{
		ContentType: header[0],
		Version:     [2]byte{header[1], header[2]},
		Length:      length,
	}, nil
}

func (h TLSRecordHeader) bytes() []byte {
	out := make([]byte, tlsRecordHeaderLen)
	out[0] = h.ContentType
	out[1] = h.Version[0]
	out[2] = h.Version[1]
	binary.BigEndian.PutUint16(out[3:5], h.Length)
	return out
}

func hkdfExtract(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	_, _ = mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	var (
		result []byte
		t      []byte
		ctr    byte = 1
	)
	for len(result) < length {
		mac := hmac.New(sha256.New, prk)
		_, _ = mac.Write(t)
		_, _ = mac.Write(info)
		_, _ = mac.Write([]byte{ctr})
		t = mac.Sum(nil)
		result = append(result, t...)
		ctr++
	}
	return append([]byte(nil), result[:length]...)
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func seqBytes(seq uint64) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], seq)
	return out[:]
}
