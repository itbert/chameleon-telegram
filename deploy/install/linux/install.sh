#!/usr/bin/env bash
set -euo pipefail

CONFIG_PATH=${CONFIG_PATH:-/etc/chameleon/config.toml}
BIN_DIR=${BIN_DIR:-/usr/local/bin}
SYSTEMD_DIR=${SYSTEMD_DIR:-/etc/systemd/system}

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo)."
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found. Build binaries first or install Rust toolchain."
  exit 1
fi

echo "Building release binaries..."
cargo build --release -p chameleon-client -p chameleon-bridge

install -d "$BIN_DIR" /etc/chameleon
install -m 755 target/release/chameleon-client "$BIN_DIR/chameleon-client"
install -m 755 target/release/chameleon-bridge "$BIN_DIR/chameleon-bridge"

if [[ ! -f "$CONFIG_PATH" ]]; then
  echo "Creating default config at $CONFIG_PATH"
  cp deploy/docker/config.toml.example "$CONFIG_PATH"
fi

install -m 644 deploy/systemd/chameleon-client.service "$SYSTEMD_DIR/chameleon-client.service"
install -m 644 deploy/systemd/chameleon-bridge.service "$SYSTEMD_DIR/chameleon-bridge.service"

systemctl daemon-reload
systemctl enable --now chameleon-client

echo "Install complete. Client service is running."
