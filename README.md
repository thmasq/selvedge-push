# selvedge-push

Stateless Matrix Push Gateway (v1) for [Selvedge](https://github.com/thmasq/selvedge), delivering RFC 8291 (`aes128gcm`) encrypted [Declarative Web Push](https://webkit.org/blog/16535/meet-declarative-web-push/) notifications signed with RFC
8292 VAPID (ES256).

## Overview

- **Stateless**: No database and no persistent state. Active tab push suppression is handled via a bounded TTL-expiring in-memory heartbeat table.
- **Privacy-preserving**: Operates on Matrix `event_id_only` notifications (`room_id` + `event_id`). Push keys, encryption material, and Matrix IDs are never logged.
- **SSRF-hardened**: Outbound Web Push requests require HTTPS on port 443 with redirects disabled, no IP literals or URL credentials, and an explicit browser-vendor allowlist (`fcm.googleapis.com`, `push.services.mozilla.com` / `*.push.services.mozilla.com`, `web.push.apple.com` / `*.push.apple.com`, `*.notify.windows.com`).
- **Resource-bounded**: 16 KiB max request body, 15s request timeout, 256 max concurrent requests, 32 max deduplicated devices per notify call, and configurable outbound concurrency.

## Endpoints

| Method & Path                  | Purpose                                                                                                                                                                                       |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /_matrix/push/v1/notify` | Matrix Push Gateway API v1. Encrypts and dispatches Declarative Web Push (`web_push: 8030`, `mutable: true`) payloads. Returns `{"rejected": [...]}` for invalid subscriptions (`404`/`410`). |
| `POST /heartbeat`              | Creates or refreshes an active-session suppression lease. Body: `{"pushkey_hash": "<64-char lowercase hex sha256(pushkey)>"}`. Returns `204` (`503` if store is at capacity).                 |
| `DELETE /heartbeat`            | Clears an active-session suppression lease. Same JSON body. Returns `204`.                                                                                                                    |
| `POST /heartbeat/clear`        | Same as `DELETE /heartbeat`; accepts `text/plain` bodies for `navigator.sendBeacon()`. Returns `204`.                                                                                         |
| `GET /health`                  | Health check. Returns `200` with `{"status":"ok"}`.                                                                                                                                           |

CORS is scoped exclusively to `/heartbeat` and `/heartbeat/clear` for `CORS_ALLOWED_ORIGIN`.

## Configuration

Generate a fresh VAPID keypair:

```sh
selvedge-push --generate-vapid-keys
```

Set `VAPID_PRIVATE_KEY` on the gateway and configure `SELVEDGE_VAPID_PUBLIC_KEY` in the Selvedge web client.

### Required Environment Variables

| Variable            | Description                                                                    |
| ------------------- | ------------------------------------------------------------------------------ |
| `VAPID_PRIVATE_KEY` | Raw 32-byte base64url scalar or PKCS#8 / SEC1 PEM P-256 private key.           |
| `VAPID_SUBJECT`     | VAPID `sub` claim (`mailto:...` or `https://...`).                             |
| `APP_BASE_URL`      | Base `http(s)` URL of the Selvedge web app (used for `notification.navigate`). |

### Optional Environment Variables

| Variable                | Default                              | Description                                                  |
| ----------------------- | ------------------------------------ | ------------------------------------------------------------ |
| `ALLOWED_APP_ID`        | `org.selvedge.web`                   | Matrix `app_id` accepted by `/_matrix/push/v1/notify`.       |
| `BIND_ADDR`             | `127.0.0.1:8085`                     | Listen address (`0.0.0.0:8085` in the Docker image).         |
| `CORS_ALLOWED_ORIGIN`   | Origin of `APP_BASE_URL`             | Bare `http(s)` origin allowed for heartbeat endpoints.       |
| `HEARTBEAT_TTL_SECS`    | `90`                                 | Heartbeat suppression lease duration in seconds.             |
| `MAX_HEARTBEATS`        | `10000`                              | Maximum concurrent entries in the in-memory heartbeat store. |
| `PUSH_TTL_SECS`         | `86400`                              | Outbound Web Push `TTL` header value in seconds.             |
| `OUTBOUND_TIMEOUT_SECS` | `5`                                  | Per-request timeout for outbound push service calls.         |
| `MAX_CONCURRENT_PUSHES` | `64`                                 | Maximum concurrent outbound Web Push deliveries.             |
| `RUST_LOG`              | `selvedge_push=info,tower_http=info` | `tracing-subscriber` log filter directive.                   |

## Deployment

Deploy behind a TLS-terminating reverse proxy (Nginx, Caddy, etc.) with per-IP rate limiting on `/heartbeat` and `/_matrix/push/v1/notify`.

### Docker

Multi-arch (`linux/amd64`, `linux/arm64`) distroless images are published to GHCR:

```sh
docker run --rm \
	--read-only \
	--cap-drop=ALL \
	--security-opt=no-new-privileges:true \
	-p 127.0.0.1:8085:8085 \
	--env-file /etc/selvedge-push.env \
	ghcr.io/thmasq/selvedge-push:latest
```

### Linux Packages (`.deb`, `.rpm`, `.apk`)

Prebuilt packages with a hardened systemd unit are attached to each GitHub Release along with `SHA256SUMS.txt`.

1. Install the package for your distribution.
2. Populate `/etc/selvedge-push.env` (`chmod 0600`, `root:root`) with your VAPID key and app URL.
3. Enable and start the service:

```sh
sudo systemctl enable --now selvedge-push
```

### Building from Source

Requires Rust (edition 2024):

```sh
cargo build --release --locked
cargo test --locked
```

## License

Licensed under [AGPL-3.0-only](LICENSE).
