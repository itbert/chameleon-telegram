# chameleon-telegram

Telegram has been blocked since March 20, moving to a liberal Internet

Linux-first reliable CLI tunnel with pluggable transport architecture.
## Components
- `chameleon-core`: config, protocol, Noise crypto channel, allowlist policy, relay
- `chameleon-client`: local SOCKS5 (`CONNECT`) client
- `chameleon-bridge`: remote bridge server

## Scope
- Transport: `raw`
- Protocol: TCP only
- No obfuscation / anti-DPI logic
- Local Web UI on `127.0.0.1`

## Requirements
- Rust stable toolchain (`cargo`, `rustc`)

## Config
Single TOML file can include both sections.

```toml
[client]
listen = "127.0.0.1:1080"
bridge_addr = "YOUR_BRIDGE_IP:443"
server_pubkey_b64 = "<BRIDGE_PUBLIC_KEY>"
transport = "raw"
max_frame = 65535

# Optional
auth_psk_b64 = ""
handshake_timeout_ms = 5000
connect_timeout_ms = 8000
relay_idle_timeout_ms = 60000
shutdown_grace_ms = 5000
web_ui_addr = "127.0.0.1:7777"
web_ui_enabled = true
web_ui_auth_token = ""

[bridge]
listen = "0.0.0.0:443"
server_privkey_b64 = "<BRIDGE_PRIVATE_KEY>"
transport = "raw"
allow_all = false
allow_cidrs = ["149.154.0.0/16", "91.108.4.0/22"]
allow_domains = ["telegram.org", "t.me", "telegram.me"]
max_frame = 65535

# Optional
auth_psk_b64 = ""
require_auth = false
handshake_timeout_ms = 5000
target_connect_timeout_ms = 8000
relay_idle_timeout_ms = 60000
shutdown_grace_ms = 5000
max_connections = 10000
deny_private_targets = true
allow_loopback_targets = false
```

## Quick Start
1. Generate bridge keypair:
```bash
cargo run -p chameleon-bridge -- keygen
```

2. Optional: generate shared PSK (base64):
```bash
openssl rand -base64 32
```
Set the same value to both `client.auth_psk_b64` and `bridge.auth_psk_b64`. Set `bridge.require_auth = true` to enforce it.

3. Run bridge:
```bash
cargo run -p chameleon-bridge -- run --config config.toml
```

4. Run client:
```bash
cargo run -p chameleon-client -- run --config config.toml
```

5. Configure Telegram/app/system to use SOCKS5 at `127.0.0.1:1080`.

## Web UI
- Default: `http://127.0.0.1:7777`
- If `web_ui_auth_token` is empty at first run, the client generates a token and stores it in config.
- Paste the token in the UI to enable API calls.

CLI helpers:
```bash
chameleon-client status --config config.toml
chameleon-client open-ui --config config.toml
chameleon-client install --config config.toml
```

## Linux Runbook
### systemd units
Files:
- `deploy/systemd/chameleon-bridge.service`
- `deploy/systemd/chameleon-client.service`

Install example:
```bash
sudo cp deploy/systemd/chameleon-bridge.service /etc/systemd/system/
sudo cp deploy/systemd/chameleon-client.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now chameleon-bridge
sudo systemctl enable --now chameleon-client
```

### Install script
```bash
sudo deploy/install/linux/install.sh
```

### Docker Compose
Files:
- `deploy/docker/Dockerfile`
- `deploy/docker/docker-compose.yml`

Run example:
```bash
cd deploy/docker
cp config.toml.example config.toml
docker compose up --build -d
```

Bridge healthcheck uses `nc -z 127.0.0.1 443`.

## Windows Runbook
### Install script (WinSW)
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
deploy\\install\\windows\\install.ps1 -DownloadWinSW
```

Config path: `%ProgramData%\\Chameleon\\config.toml`

See `docs/windows-quickstart.md` for details.

## Logging
Set `RUST_LOG=info` or `RUST_LOG=debug`.

v0.2 logs include:
- `conn_id`, peer
- auth result
- target host/port
- bytes up/down
- session duration
- close reason (`upstream_eof`, `downstream_eof`, `idle_timeout`)

Client log files rotate by size in the local log directory.

## Rollout Checklist
1. Local e2e test with explicit SOCKS5 client.
2. Single-VPS canary with `require_auth=true`.
3. Controlled pilot with allowlist tuned for expected destinations.

## Monitoring Signals
- auth failure rate
- connect failure rate
- handshake latency
- target connect latency
- active connection saturation (`max_connections`)
- relay idle-timeout ratio

## Security Notes
- Client-to-bridge link is encrypted/authenticated with Noise IK.
- Bridge can enforce PSK auth (`require_auth=true`).
- `deny_private_targets=true` blocks private/special destinations by policy.
- Fail-closed: auth/policy errors reject connection.

## Known Limitations
- `raw` transport only
- no UDP relay
- no OS-level traffic interception
- no stream multiplexing

## License
GPL-3.0-or-later
