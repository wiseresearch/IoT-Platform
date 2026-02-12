# Simple HTTP API for Host Network Scanning
# This script creates a REST API that containers can call to trigger network scans

from flask import Flask, jsonify, request
import subprocess
import json
import os
from datetime import datetime
import re

app = Flask(__name__)

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
            'Select-Object IPAddress, LinkLayerAddress, State | '
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

        ps_ips = ",".join([f"'{ip}'" for ip in filtered])
        cmd = (
            'powershell -ExecutionPolicy Bypass -Command '
            f'"$ips=@({ps_ips}); $out=@{{}}; '
            '$okStates=@(\'Reachable\',\'Stale\',\'Delay\',\'Probe\',\'Permanent\'); '
            'foreach($ip in $ips){ '
            '$ping=Test-Connection -Quiet -Count 1 -TimeoutSeconds 1 -Destination $ip; '
            'if($ping){ $out[$ip]=$true; continue }; '
            '$tcp443=Test-NetConnection -ComputerName $ip -Port 443 -InformationLevel Quiet; '
            'if($tcp443){ $out[$ip]=$true; continue }; '
            '$tcp80=Test-NetConnection -ComputerName $ip -Port 80 -InformationLevel Quiet; '
            'if($tcp80){ $out[$ip]=$true; continue }; '
            '$neighbor=Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.IPAddress -eq $ip } | Select-Object -First 1; '
            'if($neighbor){ '
            '$mac=$neighbor.LinkLayerAddress; '
            '$macOk=($mac -and $mac -ne \'00-00-00-00-00-00\' -and $mac -ne \'00:00:00:00:00:00\'); '
            'if($macOk -and ($okStates -contains $neighbor.State)){ $out[$ip]=$true } else { $out[$ip]=$false } '
            '} else { $out[$ip]=$false } '
            '}; '
            '$out | ConvertTo-Json -Compress"'
        )

        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return jsonify({"status": "error", "message": result.stderr}), 500

        raw = json.loads(result.stdout) if result.stdout else {}
        if not isinstance(raw, dict):
            raw = {}

        return jsonify({"status": "success", "results": raw})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/scan', methods=['GET'])
def scan_network():
    """Trigger PowerShell network scan and return results"""
    try:
        network_range = request.args.get('range', '10.0.0.0/24')
        
        # Get the directory of this script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        ps_script = os.path.join(script_dir, "host_network_scanner.ps1")
        use_inline = not os.path.exists(ps_script)
        
        if use_inline:
            # Fallback: use Get-NetNeighbor if script is missing
            cmd = (
                'powershell -ExecutionPolicy Bypass -Command '
                '"Get-NetNeighbor -AddressFamily IPv4 | '
                'Select-Object IPAddress, LinkLayerAddress, State | '
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
                        if not ip:
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
        network_range = request.args.get('range', '10.0.0.0/24')
        
        if network_range == "10.0.0.0/24":
            # Quick ping test of common IPs
            common_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.10", "10.0.0.100"]
            results = []
            
            for ip in common_ips:
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
        else:
            return jsonify({
                "status": "error",
                "message": "Quick scan only supports 10.0.0.0/24"
            }), 400
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

if __name__ == '__main__':
    print("Starting Host Network Scanner API...")
    print("Available endpoints:")
    print("  GET /health - Health check")
    print("  GET /scan?range=10.0.0.0/24 - Full network scan") 
    print("  GET /quick-scan?range=10.0.0.0/24 - Quick ping scan")
    print("")
    print("Starting server on http://localhost:5555")
    
    app.run(host='0.0.0.0', port=5555, debug=False)
