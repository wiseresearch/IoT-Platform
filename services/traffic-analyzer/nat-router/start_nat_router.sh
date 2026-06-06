#!/bin/sh
set -eu

mkdir -p /var/log/suricata
mkdir -p /var/lib/suricata
mkdir -p /etc/suricata/rules

touch /etc/suricata/suricata.rules
touch /var/log/suricata/eve.json
touch /var/log/suricata/suricata.log

if [ ! -e /var/lib/suricata/rules ]; then
    ln -s /etc/suricata /var/lib/suricata/rules
fi

if [ -f /var/run/suricata.pid ]; then
    SURICATA_PID="$(cat /var/run/suricata.pid 2>/dev/null || true)"
    if [ -n "${SURICATA_PID}" ] && kill -0 "${SURICATA_PID}" 2>/dev/null; then
        echo "Suricata already running with PID ${SURICATA_PID}; skipping startup."
    else
        echo "Removing stale Suricata PID file."
        rm -f /var/run/suricata.pid
    fi
fi

if pgrep -x suricata >/dev/null 2>&1; then
    echo "Detected running Suricata process; skipping startup."
else
    echo "Starting Suricata with config /etc/suricata/suricata.yaml"
    if suricata -c /etc/suricata/suricata.yaml --af-packet -D; then
        sleep 2
    else
        echo "WARNING: Suricata failed to start. NAT router API will continue running."
    fi
fi

echo "Starting NAT router API"
exec python3 /app/nat_router.py
