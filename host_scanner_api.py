# Simple HTTP API for Host Network Scanning
# This script creates a REST API that containers can call to trigger network scans

from flask import Flask, jsonify, request
import subprocess
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

        results = {}
        for ip in filtered:
            try:
                ping_cmd = ["ping", "-n", "1", "-w", "1000", ip]
                ping_result = subprocess.run(
                    ping_cmd,
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if ping_result.returncode == 0 and "TTL=" in (ping_result.stdout or ""):
                    results[ip] = True
                else:
                    results[ip] = False
            except Exception:
                results[ip] = False

        return jsonify({"status": "success", "results": results})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e), "results": {}})

@app.route('/scan', methods=['GET'])
def scan_network():
    """Trigger PowerShell network scan and return results"""
    try:
        network_range = request.args.get('range') or get_default_scan_range()
        target_network = parse_target_network(network_range)
        
        # Get the directory of this script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        ps_script = os.path.join(script_dir, "host_network_scanner.ps1")
        use_inline = not os.path.exists(ps_script)
        
        if use_inline:
            # Fallback: use Get-NetNeighbor if script is missing
            cmd = (
                'powershell -ExecutionPolicy Bypass -Command '
                '"Get-NetNeighbor -AddressFamily IPv4 | '
                'Select-Object IPAddress, LinkLayerAddress, @{Name=\'State\';Expression={$_.State.ToString()}} | '
                'ConvertTo-Json -Compress"'
            )
        else:
            cmd = f'powershell -ExecutionPolicy Bypass -File "{ps_script}" -NetworkRange "{network_range}"'
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            if use_inline:
                try:
                    raw = json.loads(result.stdout)
                    neighbors = raw if isinstance(raw, list) else [raw]

                    hosts = []
                    for n in neighbors:
                        ip = n.get('IPAddress')
                        mac = n.get('LinkLayerAddress')
                        state = n.get('State', '')
                        if not ip or not ip_in_target_network(ip, target_network):
                            continue
                        hosts.append({
                            "ip": ip,
                            "mac": mac,
                            "hostname": "",
                            "state": state,
                            "device_type": "Neighbor"
                        })

                    return jsonify({
                        "status": "success",
                        "data": {
                            "hosts": hosts,
                            "method": "get-netneighbor"
                        }
                    })
                except json.JSONDecodeError as e:
                    return jsonify({
                        "status": "error",
                        "message": f"Failed to parse Get-NetNeighbor JSON: {str(e)}",
                        "raw_output": result.stdout
                    }), 500

            # Parse output for JSON
            lines = result.stdout.split('\n')
            json_start = -1
            
            for i, line in enumerate(lines):
                if 'JSON Output:' in line:
                    json_start = i + 1
                    break
            
            if json_start > 0:
                json_lines = lines[json_start:]
                json_text = '\n'.join([line for line in json_lines if line.strip()])
                
                try:
                    scan_results = json.loads(json_text)
                    return jsonify({
                        "status": "success",
                        "data": scan_results
                    })
                except json.JSONDecodeError as e:
                    return jsonify({
                        "status": "error",
                        "message": f"Failed to parse JSON: {str(e)}",
                        "raw_output": result.stdout
                    }), 500
            else:
                return jsonify({
                    "status": "error", 
                    "message": "No JSON output found",
                    "raw_output": result.stdout
                }), 500
        else:
            return jsonify({
                "status": "error",
                "message": f"PowerShell script failed: {result.stderr}",
                "returncode": result.returncode
            }), 500
            
    except subprocess.TimeoutExpired:
        return jsonify({
            "status": "error",
            "message": "Scan timed out after 120 seconds"
        }), 500
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/quick-scan', methods=['GET'])
def quick_scan():
    """Quick ping-only scan for faster results"""
    try:
        network_range = request.args.get('range') or get_default_scan_range()
        target_network = parse_target_network(network_range)

        if not target_network:
            return jsonify({
                "status": "error",
                "message": f"Invalid network range: {network_range}"
            }), 400

        results = []

        for ip in build_quick_scan_targets(target_network):
            ping_cmd = f'ping -n 1 -w 1000 {ip}'
            ping_result = subprocess.run(ping_cmd, shell=True, capture_output=True, text=True)

            if ping_result.returncode == 0 and "TTL=" in ping_result.stdout:
                results.append({
                    "ip": ip,
                    "status": "up",
                    "method": "ping"
                })

        return jsonify({
            "status": "success",
            "scan_time": datetime.now().isoformat(),
            "network_range": network_range,
            "total_hosts_found": len(results),
            "hosts": results
        })
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

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
