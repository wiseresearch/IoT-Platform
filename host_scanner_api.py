# Simple HTTP API for Host Network Scanning
# This script creates a REST API that containers can call to trigger network scans

from flask import Flask, jsonify, request
import subprocess
from concurrent.futures import ThreadPoolExecutor
import json
import os
from datetime import datetime
import re
import sys
import threading
import time
import socket
import ipaddress

from shared.windows_network import detect_primary_interface, detect_primary_subnet, load_local_env

load_local_env()

STATE_MAP = {
    0: 'unreachable',
    1: 'incomplete',
    2: 'probe',
    3: 'delay',
    4: 'stale',
    5: 'reachable',
    6: 'permanent'
}

app = Flask(__name__)


def get_default_scan_range():
    return detect_primary_subnet(fallback_subnet=os.getenv('FALLBACK_SUBNET', '192.168.1.0/24'))


def parse_target_network(network_range):
    try:
        return ipaddress.ip_network(network_range, strict=False)
    except ValueError:
        return None


def ip_in_target_network(ip_value, target_network):
    if not target_network:
        return True

    try:
        ip_obj = ipaddress.ip_address(ip_value)
    except ValueError:
        return False

    if ip_obj not in target_network:
        return False

    if ip_obj == target_network.network_address:
        return False

    broadcast_address = getattr(target_network, 'broadcast_address', None)
    if broadcast_address and ip_obj == broadcast_address:
        return False

    return True


def build_quick_scan_targets(target_network):
    candidate_offsets = (1, 2, 10, 20, 50, 100, 150, 200, 254)
    network_base = int(target_network.network_address)
    broadcast_base = int(target_network.broadcast_address)
    targets = []

    for offset in candidate_offsets:
        candidate_int = network_base + offset
        if candidate_int >= broadcast_base:
            continue

        candidate_ip = str(ipaddress.ip_address(candidate_int))
        if candidate_ip not in targets:
            targets.append(candidate_ip)

    if targets:
        return targets

    for host in target_network.hosts():
        targets.append(str(host))
        if len(targets) >= 8:
            break

    return targets


def _ping_host(ip):
    """Return True when a single ICMP echo succeeds."""
    cmd = ["ping", "-n", "1", "-w", "1000", ip] if os.name == "nt" else ["ping", "-c", "1", "-W", "1", ip]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=3).returncode == 0
    except Exception:
        return False


def _read_ipv4_neighbors():
    """Return {ip: {mac, state}} from the kernel neighbour table (Linux)."""
    neighbors = {}
    if os.name == "nt":
        return neighbors
    try:
        result = subprocess.run(["ip", "-j", "-4", "neigh", "show"], capture_output=True, text=True, timeout=10)
        if result.returncode != 0 or not result.stdout.strip():
            return neighbors
        for item in json.loads(result.stdout):
            ip = item.get("dst")
            if not ip:
                continue
            state = item.get("state", "")
            if isinstance(state, list):
                state = state[0] if state else ""
            neighbors[ip] = {
                "mac": item.get("lladdr"),
                "state": str(state).upper()
            }
    except Exception:
        pass
    return neighbors


def _local_host_neighbor():
    """Return the host's own (ip, mac) so loopback is not the only missing identity."""
    try:
        info = detect_primary_interface()
        ip = info.get("ip")
        mac = info.get("mac")
        if not mac and os.name != "nt":
            name = info.get("name")
            if name:
                try:
                    with open(f"/sys/class/net/{name}/address", "r", encoding="utf-8") as handle:
                        mac = handle.read().strip() or None
                except OSError:
                    mac = None
        return ip, mac
    except Exception:
        return None, None


def _ping_sweep(target_network, max_workers=64):
    """Ping every usable host in a /24-or-smaller network in parallel."""
    hosts = [str(host) for host in target_network.hosts()]
    if len(hosts) > 1024:
        return None, []
    with ThreadPoolExecutor(max_workers=min(max_workers, max(1, len(hosts)))) as pool:
        results = list(pool.map(lambda ip: (ip, _ping_host(ip)), hosts))
    return hosts, results

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "service": "host-network-scanner-api"})

@app.route('/neighbors', methods=['GET'])
def get_neighbors():
    """Return current ARP/neighbor table (passive)"""
    try:
        if os.name != "nt":
            result = subprocess.run(["ip", "-j", "-4", "neigh", "show"], capture_output=True, text=True, timeout=10)
            raw = json.loads(result.stdout) if result.stdout.strip() else []
            items = []
            for n in raw:
                ip = n.get("dst")
                if not ip:
                    continue
                state = n.get("state", "")
                if isinstance(state, list):
                    state = state[0] if state else ""
                items.append({
                    "ip": ip,
                    "mac": n.get("lladdr"),
                    "state": str(state).upper(),
                    "dev": n.get("dev"),
                })
        else:
            cmd = (
                'powershell -ExecutionPolicy Bypass -Command '
                '"Get-NetNeighbor -AddressFamily IPv4 | '
                'Select-Object IPAddress, LinkLayerAddress, @{Name=\'State\';Expression={$_.State.ToString()}} | '
                'ConvertTo-Json -Compress"'
            )
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
            if result.returncode != 0:
                return jsonify({
                    "status": "error",
                    "message": result.stderr
                }), 500

            raw = json.loads(result.stdout) if result.stdout else []
            neighbors = raw if isinstance(raw, list) else [raw]
            items = []
            for n in neighbors:
                ip = n.get('IPAddress')
                mac = n.get('LinkLayerAddress')
                state = n.get('State', '')
                if isinstance(state, (int, float)) or (isinstance(state, str) and state.isdigit()):
                    state = STATE_MAP.get(int(state), str(state))
                if not ip:
                    continue
                items.append({
                    "ip": ip,
                    "mac": mac,
                    "state": state
                })

        return jsonify({
            "status": "success",
            "neighbors": items,
            "count": len(items)
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/host-info', methods=['GET'])
def get_host_info():
    """Return current host IP/MAC/hostname (best-effort, non-virtual adapter)."""
    try:
        # Fast path: use ipconfig + getmac (avoid PowerShell stalls)
        hostname = os.environ.get('COMPUTERNAME') or socket.gethostname()
        network_info = detect_primary_interface()
        ip = network_info.get('ip')
        try:
            if not ip:
                ipconfig = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5)
                for line in (ipconfig.stdout or "").splitlines():
                    if "IPv4 Address" in line or "Adresse IPv4" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            candidate = parts[1].strip()
                            if candidate and not candidate.startswith("169.254") and candidate != "127.0.0.1":
                                ip = candidate
                                break
        except Exception:
            ip = network_info.get('ip')

        mac = None
        try:
            getmac = subprocess.run(["getmac", "/NH", "/FO", "CSV"], capture_output=True, text=True, timeout=5)
            for line in (getmac.stdout or "").splitlines():
                if not line.strip():
                    continue
                if "disconnected" in line.lower():
                    continue
                raw = line.strip().strip('"')
                parts = [p.strip().strip('"') for p in raw.split('","')]
                if not parts:
                    continue
                candidate = parts[0].strip()
                if candidate and candidate.lower() != 'n/a' and candidate != '00-00-00-00-00-00':
                    mac = candidate
                    break
        except Exception:
            mac = None
        if not mac and os.name != "nt":
            interface_name = network_info.get('name')
            if interface_name:
                try:
                    with open(f"/sys/class/net/{interface_name}/address", "r", encoding="utf-8") as handle:
                        mac = handle.read().strip() or None
                except OSError:
                    mac = None

        payload = {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "interface": network_info.get('name') or "unknown",
            "subnet": network_info.get('subnet') or get_default_scan_range()
        }
        return jsonify({
            "status": "success",
            "host": payload
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/restart', methods=['POST'])
def restart_service():
    """Restart this API process."""
    def _restart():
        time.sleep(0.5)
        os.execv(sys.executable, [sys.executable] + sys.argv)

    threading.Thread(target=_restart, daemon=True).start()
    return jsonify({"status": "restarting"})

@app.route('/reachability', methods=['POST'])
def reachability():
    """Active reachability check (ICMP ping + TCP + ARP neighbor fallback)."""
    try:
        data = request.get_json(silent=True) or {}
        ips = data.get('ips', [])
        if not isinstance(ips, list):
            return jsonify({"status": "error", "message": "ips must be a list"}), 400

        ip_re = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
        filtered = []
        for ip in ips:
            if isinstance(ip, str) and ip_re.match(ip):
                filtered.append(ip)
        filtered = filtered[:50]

        if not filtered:
            return jsonify({"status": "success", "results": {}})

        def ping_one(ip):
            try:
                if os.name == "nt":
                    ping_cmd = ["ping", "-n", "1", "-w", "1000", ip]
                else:
                    ping_cmd = ["ping", "-c", "1", "-W", "1", ip]
                ping_result = subprocess.run(
                    ping_cmd,
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                return ip, ping_result.returncode == 0
            except Exception:
                return ip, False

        with ThreadPoolExecutor(max_workers=32) as pool:
            results = dict(pool.map(ping_one, filtered))

        return jsonify({"status": "success", "results": results})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e), "results": {}})

@app.route('/scan', methods=['GET'])
def scan_network():
    """Discover LAN hosts via a parallel ping sweep plus the ARP table."""
    try:
        network_range = request.args.get('range') or get_default_scan_range()
        target_network = parse_target_network(network_range)
        if not target_network or target_network.version != 4:
            return jsonify({
                "status": "error",
                "message": f"Invalid IPv4 network range: {network_range}"
            }), 400

        if os.name == "nt":
            command = (
                "Get-NetNeighbor -AddressFamily IPv4 | "
                "Select-Object IPAddress, LinkLayerAddress, "
                "@{Name='State';Expression={$_.State.ToString()}} | "
                "ConvertTo-Json -Compress"
            )
            result = subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-Command", command],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode != 0:
                return jsonify({"status": "error", "message": result.stderr}), 500
            raw = json.loads(result.stdout) if result.stdout.strip() else []
            rows = raw if isinstance(raw, list) else [raw]
            hosts = []
            for row in rows:
                ip = row.get("IPAddress")
                if not ip or not ip_in_target_network(ip, target_network):
                    continue
                state = row.get("State", "")
                if isinstance(state, (int, float)) or (isinstance(state, str) and state.isdigit()):
                    state = STATE_MAP.get(int(state), str(state))
                hosts.append({
                    "ip": ip,
                    "mac": row.get("LinkLayerAddress"),
                    "hostname": "",
                    "state": str(state).upper(),
                    "device_type": "Unknown"
                })
            return jsonify({
                "status": "success",
                "data": {"hosts": hosts, "method": "get-netneighbor"}
            })

        targets, ping_results = _ping_sweep(target_network)
        if targets is None:
            return jsonify({
                "status": "error",
                "message": "Network range is too large (maximum 1024 hosts)"
            }), 400

        responsive = {ip for ip, is_up in ping_results if is_up}
        neighbors = _read_ipv4_neighbors()
        local_ip, local_mac = _local_host_neighbor()
        if local_ip and local_mac and ip_in_target_network(local_ip, target_network):
            neighbors.setdefault(local_ip, {"mac": local_mac, "state": "REACHABLE"})
        candidate_ips = responsive | set(neighbors)
        hosts = []
        for ip in sorted(candidate_ips, key=lambda value: ipaddress.ip_address(value)):
            if not ip_in_target_network(ip, target_network):
                continue
            neighbor = neighbors.get(ip, {})
            state = str(neighbor.get("state") or "").upper()
            if state in ("FAILED", "INCOMPLETE") and ip not in responsive:
                continue
            hosts.append({
                "ip": ip,
                "mac": neighbor.get("mac"),
                "hostname": "",
                "state": state or ("REACHABLE" if ip in responsive else ""),
                "device_type": "Unknown"
            })

        return jsonify({
            "status": "success",
            "data": {
                "hosts": hosts,
                "method": "ping+arp",
                "scanned": len(targets),
                "responsive": len(responsive)
            }
        })
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "Scan timed out"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/quick-scan', methods=['GET'])
def quick_scan():
    """Ping a small representative host set for a fast discovery pass."""
    try:
        network_range = request.args.get('range') or get_default_scan_range()
        target_network = parse_target_network(network_range)
        if not target_network:
            return jsonify({
                "status": "error",
                "message": f"Invalid network range: {network_range}"
            }), 400

        targets = build_quick_scan_targets(target_network)
        neighbors = _read_ipv4_neighbors()
        with ThreadPoolExecutor(max_workers=min(16, max(1, len(targets)))) as pool:
            results = list(pool.map(lambda ip: (ip, _ping_host(ip)), targets))

        hosts = []
        for ip, is_up in results:
            if not is_up:
                continue
            neighbor = neighbors.get(ip, {})
            hosts.append({
                "ip": ip,
                "status": "up",
                "method": "ping",
                "mac": neighbor.get("mac"),
                "state": neighbor.get("state", "REACHABLE"),
                "device_type": "Unknown"
            })

        return jsonify({
            "status": "success",
            "scan_time": datetime.now().isoformat(),
            "network_range": network_range,
            "total_hosts_found": len(hosts),
            "hosts": hosts
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    default_range = get_default_scan_range()
    print("Starting Host Network Scanner API...")
    print("Available endpoints:")
    print("  GET /health - Health check")
    print(f"  GET /scan?range={default_range} - Full network scan")
    print(f"  GET /quick-scan?range={default_range} - Quick ping scan")
    print("")
    print("Starting server on http://localhost:5555")
    
    app.run(host='0.0.0.0', port=5555, debug=False, threaded=True)
