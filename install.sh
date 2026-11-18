#!/bin/bash
# install.sh - install lim as a system service
# Usage: sudo ./install.sh
set -e   # stop at the first error

if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo: sudo ./install.sh"
    exit 1
fi

cd "$(dirname "$0")"   # run from the repo folder no matter where we were called from

echo "[1/5] Copying lim to /opt/lim (owned by root, not writable by other users)"
install -d -m 755 -o root -g root /opt/lim /opt/lim/core
install -m 755 -o root -g root lim.py /opt/lim/
install -m 644 -o root -g root core/*.py /opt/lim/core/
if [ -f /opt/lim/config.json ]; then
    echo "      keeping existing /opt/lim/config.json"
else
    install -m 644 -o root -g root config.json /opt/lim/
fi

echo "[2/5] Creating the protected state folder /var/lib/lim"
install -d -m 700 -o root -g root /var/lib/lim

echo "[3/5] Taking a baseline (if there isn't one yet)"
if [ -f /var/lib/lim/baseline.json ]; then
    echo "      baseline already exists, keeping it"
else
    python3 /opt/lim/lim.py init
fi

echo "[4/5] Installing the systemd service"
install -m 644 -o root -g root lim.service /etc/systemd/system/lim.service
systemctl daemon-reload

echo "[5/5] Starting lim and enabling it at boot"
systemctl enable --now lim

echo
systemctl --no-pager status lim | head -n 5
echo
echo "Done. Useful commands:"
echo "  journalctl -u lim -f          # watch lim's alerts live"
echo "  sudo python3 /opt/lim/lim.py verify   # audit everything"
echo "  sudo systemctl stop lim       # stop it"
echo "  sudo ./uninstall.sh           # remove it"