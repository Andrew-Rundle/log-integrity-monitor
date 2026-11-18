#!/bin/bash
# uninstall.sh - remove the lim service (keeps /var/lib/lim records and the alert log)
# Usage: sudo ./uninstall.sh
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run with sudo: sudo ./uninstall.sh"
    exit 1
fi

systemctl disable --now lim 2>/dev/null || true
rm -f /etc/systemd/system/lim.service
systemctl daemon-reload
rm -rf /opt/lim
echo "lim removed. Records kept in /var/lib/lim and /var/log/lim_alerts.log"
echo "(delete them with: sudo rm -rf /var/lib/lim /var/log/lim_alerts.log)"