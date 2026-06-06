#!/usr/bin/env bash
set -euo pipefail

SERVER="${SERVER:-http://localhost:8080}"
INTERVAL_SECONDS="${INTERVAL_SECONDS:-0}"

get_primary_ip() {
  ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}'
}

get_iface_for_ip() {
  local ip="$1"
  ip -4 addr | awk -v ip="$ip" '$0 ~ ip {print $NF; exit}'
}

get_mac_for_iface() {
  local iface="$1"
  cat "/sys/class/net/$iface/address" 2>/dev/null || echo ""
}

get_os_info() {
  local name=""
  local version=""
  if [[ -f /etc/os-release ]]; then
    name=$(grep -E '^NAME=' /etc/os-release | head -1 | cut -d= -f2- | tr -d '"')
    version=$(grep -E '^VERSION_ID=' /etc/os-release | head -1 | cut -d= -f2- | tr -d '"')
  fi
  echo "$name|$version"
}

send_report() {
  local ip
  ip="$(get_primary_ip)"
  if [[ -z "$ip" ]]; then
    echo "No valid IPv4 address found."
    return
  fi

  local iface mac
  iface="$(get_iface_for_ip "$ip")"
  mac="$(get_mac_for_iface "$iface")"

  local osinfo os_name os_version
  osinfo="$(get_os_info)"
  os_name="${osinfo%%|*}"
  os_version="${osinfo##*|}"

  local hostname
  hostname="$(hostname)"

  local payload
  payload=$(cat <<EOF
{
  "ip_address": "$ip",
  "mac_address": "$mac",
  "hostname": "$hostname",
  "os_name": "$os_name",
  "os_version": "$os_version",
  "vendor": "",
  "device_type": "Managed Agent"
}
EOF
)

  curl -sS -X POST "$SERVER/api/agent/report" \
    -H "Content-Type: application/json" \
    -d "$payload" >/dev/null && echo "Report sent"
}

if [[ "$INTERVAL_SECONDS" -gt 0 ]]; then
  while true; do
    send_report
    sleep "$INTERVAL_SECONDS"
  done
else
  send_report
fi
