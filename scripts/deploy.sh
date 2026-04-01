#!/bin/bash
# ContrastScan deploy script
# Usage: ssh local 'bash /tmp/deploy-scan.sh'

set -e

APP_DIR="/opt/contrastscan"
SERVICE="contrastscan"

echo "=== Deploying $SERVICE ==="

cd "$APP_DIR"

# Discard local changes and remove untracked files in static/fonts
git checkout -- .
git clean -fd app/static/fonts/

# Pull latest
git pull

# Restart service
systemctl restart "$SERVICE"

# Warm up workers
sleep 2
curl -s http://127.0.0.1:8001/ > /dev/null && echo "Workers warmed up"

echo "=== $SERVICE deployed ==="
echo "Version: $(grep VERSION app/config.py 2>/dev/null || echo 'n/a')"
