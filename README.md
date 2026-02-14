# chameleon-telegram

Minimal MVP tunnel for Telegram traffic with a pluggable transport architecture.

## Components
- `chameleon-core`: crypto, framing, protocol, allowlist, relay
- `chameleon-client`: SOCKS5 proxy + tunnel client
- `chameleon-bridge`: tunnel server (bridge)

## Requirements
- Rust toolchain (stable)

## Quick start

1) Generate bridge keys:

```bash
cargo run -p chameleon-bridge -- keygen
```

2) Create a config file (example `config.toml`):

```toml
[client]
listen = "127.0.0.1:1080"
bridge_addr = "YOUR_BRIDGE_IP:443"
server_pubkey_b64 = "<PASTE_SERVER_PUBLIC_KEY>"
transport = "raw"
max_frame = 65535

[bridge]
listen = "0.0.0.0:443"
server_privkey_b64 = "<PASTE_SERVER_PRIVATE_KEY>"
transport = "raw"
allow_all = false
allow_cidrs = ["0.0.0.0/0"]
allow_domains = ["telegram.org", "t.me", "telegram.me"]
max_frame = 65535
```

3) Run bridge:

```bash
cargo run -p chameleon-bridge -- run --config config.toml
```

4) Run client:

```bash
cargo run -p chameleon-client -- run --config config.toml
```

5) Configure Telegram (or system) to use SOCKS5 proxy at `127.0.0.1:1080`.

## Security / MVP limitations
- RAW transport only (no obfuscation yet). Traffic is not disguised.
- TCP-only (no UDP/VoIP).
- No OS-level traffic interception; only explicit SOCKS5 proxy.
- No multiplexing; one bridge connection per local client connection.
- Client authentication is not enforced; bridge relies on allowlist.

## License
GPL-3.0-or-later
