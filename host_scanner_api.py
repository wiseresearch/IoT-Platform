# Simple HTTP API for Host Network Scanning
# This script creates a REST API that containers can call to trigger network scans

from flask import Flask, jsonify, request
import subprocess
import json
import os
from datetime import datetime

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

@app.route('/scan', methods=['GET'])
def scan_network():
    """Trigger PowerShell network scan and return results"""
    try:
        network_range = request.args.get('range', '172.20.10.0/24')
        
        # Get the directory of this script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        ps_script = os.path.join(script_dir, "host_network_scanner.ps1")
        
        # Execute PowerShell scanner
        cmd = f'powershell -ExecutionPolicy Bypass -File "{ps_script}" -NetworkRange "{network_range}"'
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
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
        network_range = request.args.get('range', '172.20.10.0/24')
        
        if network_range == "172.20.10.0/24":
            # Quick ping test of common IPs
            common_ips = ["172.20.10.1", "172.20.10.2", "172.20.10.15", "172.20.10.10"]
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
                "message": "Quick scan only supports 172.20.10.0/24"
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
    print("  GET /scan?range=172.20.10.0/24 - Full network scan") 
    print("  GET /quick-scan?range=172.20.10.0/24 - Quick ping scan")
    print("")
    print("Starting server on http://localhost:5555")
    
    app.run(host='0.0.0.0', port=5555, debug=False)