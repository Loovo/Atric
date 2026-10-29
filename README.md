# Atric

**Atric** stands for **Adaptive TLS Record Insertion Covert Channel**. It consists of two Linux proxies written in Go. The client transparently forwards TLS connections to the server, while the server forwards them to a local TLS service. Either proxy can adaptively insert covert TLS records in its outgoing direction; the peer extracts those records before forwarding the original traffic. The TLS endpoints do not need to be modified.


## Source files

| Client file | Server file | Purpose |
| --- | --- | --- |
| [`arrival.go`](client/arrival.go) | [`arrival.go`](server/arrival.go) | Reads TCP data with kernel receive timestamps for record timing. |
| [`config.go`](client/config.go) | [`config.go`](server/config.go) | Sets network addresses, socket marks, the shared key, queue sizes, insertion defaults, and observation defaults. |
| [`crypt.go`](client/crypt.go) | [`crypt.go`](server/crypt.go) | Parses TLS records, derives covert-channel keys from handshake data and the shared key, and authenticates covert records. |
| [`detection.go`](client/detection.go) | [`detection.go`](server/detection.go) | Defines and writes record-level and stable-window JSONL observations. |
| [`egress.go`](client/egress.go) | [`egress.go`](server/egress.go) | Writes outgoing records, collects kernel transmit timestamps, and delivers egress events to insertion and observation logic. |
| [`features.go`](client/features.go) | [`features.go`](server/features.go) | Tracks traffic phases and windows and computes record-length, interval, rate, and burst features. |
| [`insert.go`](client/insert.go) | [`insert.go`](server/insert.go) | Chooses insertion opportunities, covert-record sizes, and timing. |
| [`main.go`](client/main.go) | [`main.go`](server/main.go) | Parses command-line flags, handles shutdown signals, and starts the proxy. |
| [`timestamp_predictor.go`](client/timestamp_predictor.go) | [`timestamp_predictor.go`](server/timestamp_predictor.go) | Calibrates predicted send times against actual transmit timestamps. |
| [`tlscp.go`](client/tlscp.go) | — | Handles transparent proxying, bidirectional record forwarding, and downlink covert-record extraction. |
| — | [`tlssp.go`](server/tlssp.go) | Handles reverse proxying, bidirectional record forwarding, and uplink covert-record extraction. |

## Build

Use Linux and a Go toolchain that satisfies both `go.mod` files. From the Atric directory:

```bash
go -C client build -o atric_client .
go -C server build -o atric_server .
```

## Before running

By default, the client listens on `127.0.0.1:1234` and obtains each connection's original destination from `SO_ORIGINAL_DST`. The server listens on `0.0.0.0:8443` and forwards to a TLS service at `127.0.0.1:8003`. Adjust these addresses in the respective `config.go` files for your deployment. Replace the example `pskK0` in **both** files with the same private key, then rebuild both programs.

For locally generated client traffic, the following example redirects connections to the server's port 8443 into the client proxy. Replace the example address with the server's actual IP address. The first rule lets the client's upstream sockets, marked `2` by the program, bypass the redirect.

```bash
SERVER_IP=
sudo iptables -t nat -I OUTPUT 1 -p tcp -m mark --mark 2 -j RETURN
sudo iptables -t nat -A OUTPUT -p tcp -d "$SERVER_IP" --dport 8443 -j REDIRECT --to-ports 1234
```

The server applies socket mark `3` to its downlink connections when egress tracking is enabled. Both proxies need permission to set socket marks; the example below runs them with `sudo`. Run the server and client on their respective hosts after the TLS service and redirect are ready:

```bash
sudo ./server/atric_server -embed=true -observe=true
sudo ./client/atric_client -embed=false -observe=true
```

These flags use the default insertion modes: server downlink insertion is on, and client uplink insertion is off. Set `-embed=false` on both sides to forward and observe without insertion.

## Configuration

### Command-line flags

Both programs accept the same four flags. They override the corresponding defaults in `config.go`.

| Flag | Client default | Server default | Purpose |
| --- | --- | --- | --- |
| `-embed` | `false` | `true` | Enables adaptive insertion on the client's uplink or the server's downlink. |
| `-observe` | `true` | `true` | Enables TLS record observation and JSONL output on that side, independently of insertion. |
| `-detection-record-output` | `detection_records.jsonl` | Same | Path for raw record events; an empty path disables this file. |
| `-detection-window-output` | `detection_windows.jsonl` | Same | Path for stable-window events; an empty path disables this file. |

Output paths are relative to the process working directory unless absolute paths are supplied. Use different working directories or paths if both programs run on one host. `-observe=false` prevents both JSONL files from being written. The two output paths must differ when both are enabled. The former `features.out` output and its flag are no longer present; insertion still uses its in-memory observations.

### `config.go` defaults

Values without a command-line flag require editing `config.go` and rebuilding. The insertion fallback default is assigned in `config.go` but defined in `insert.go`.

| Setting | Client default | Server default | Purpose |
| --- | --- | --- | --- |
| `proxyListenAddr` | `127.0.0.1:1234` | `0.0.0.0:8443` | Local listening address. |
| `proxyUpstreamAddr` | Empty (`SO_ORIGINAL_DST`) | `127.0.0.1:8003` | Forwarding destination. |
| `proxySocketMark` / `downlinkSocketMark` | `2` | `3` | Marks the client's upstream sockets or the server's downlink sockets. |
| `pskK0` | Example key | Same example key | Shared covert-channel key; unrelated to the TLS endpoints' keys. |
| `extractQueueLen` | `8` | `8` | Queue length for covert-record extraction. |
| `recordFeatureQueueLen` | `65536` | `65536` | Record observation event queue length. |
| `upstreamEmbeddingEnabled` / `downlinkEmbeddingEnabled` | `false` | `true` | Default for `-embed`. |
| `upstreamObservationEnabled` / `downlinkObservationEnabled` | `true` | `true` | Default for `-observe`. |
| `recordDetectionOutputPath` | `detection_records.jsonl` | Same | Default for `-detection-record-output`. |
| `windowDetectionOutputPath` | `detection_windows.jsonl` | Same | Default for `-detection-window-output`. |

