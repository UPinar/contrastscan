#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "=== ContrastScan Setup ==="

# Build C scanner
echo "[1/5] Building scanner binary..."
cd "$SCRIPT_DIR/scanner" && make clean && make
# Symlink binary to repo root (where config.py expects it)
ln -sf "$SCRIPT_DIR/scanner/contrastscan" "$SCRIPT_DIR/contrastscan"

# Python venv
echo "[2/5] Creating Python venv..."
cd "$SCRIPT_DIR"
python3 -m venv venv
venv/bin/pip install --quiet -r requirements.txt

# Database directory
echo "[3/5] Setting up database directory..."
mkdir -p /var/lib/contrastscan
chmod 755 /var/lib/contrastscan

# Systemd service
echo "[4/5] Installing systemd service..."
cp "$SCRIPT_DIR/deploy/systemd/contrastscan.service" /etc/systemd/system/ 2>/dev/null || true
systemctl daemon-reload

# Start
echo "[5/5] Starting service..."
systemctl enable contrastscan
systemctl restart contrastscan
echo "=== Done! ==="
systemctl status contrastscan --no-pager | head -5
