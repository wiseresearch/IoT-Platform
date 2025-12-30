#!/usr/bin/env python3
"""
Windows Host Scanner Service
Performs network scanning from the Windows host and provides results to containers
"""

from flask import Flask, jsonify, request
import subprocess
import json
import logging
import socket
import threading
import time
from datetime import datetime

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WindowsHostScanner:
    def __init__(self):
        self.last_scan_results = []
        self.last_scan_time = None
        
    def get_windows_network_info(self):
        """Get network information from Windows"""
        try:
            # Get network adapter information
            result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            logger.error(f"Failed to get network info: {str(e)}")
            return ""
    
    def get_arp_table(self):
        """Get ARP table from Windows"""
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            arp_entries = []
            
            for line in result.stdout.split('\n'):
                if '172.20.10.' in line and 'dynamic' in line.lower():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        mac = parts[1]
                        arp_entries.append({'ip': ip, 'mac': mac, 'type': 'arp'})
                        
            logger.info(f"Found {len(arp_entries)} ARP entries")
            return arp_entries
            
        except Exception as e:
            logger.error(f"Failed to get ARP table: {str(e)}")
            return []
    
    def ping_host(self, host_ip):
        """Ping a specific host"""
        try:
            result = subprocess.run(['ping', '-n', '1', '-w', '1000', host_ip], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def scan_network_range(self, network_range="172.20.10.0/24"):
        """Scan network range from Windows host"""
        try:
            logger.info(f"Starting Windows host scan of {network_range}")
            discovered_devices = []
            
            # Method 1: Get ARP table entries (most reliable)
            arp_devices = self.get_arp_table()
            discovered_devices.extend(arp_devices)
            
            # Method 2: Ping sweep for active discovery
            if network_range == "172.20.10.0/24":
                for i in range(1, 255):
                    ip = f"172.20.10.{i}"
                    if self.ping_host(ip):
                        # Check if already found via ARP
                        if not any(d['ip'] == ip for d in discovered_devices):
                            discovered_devices.append({
                                'ip': ip,
                                'mac': 'unknown',
                                'type': 'ping'
                            })
                            logger.info(f"Ping discovered: {ip}")
            
            # Method 3: Check for open ports on discovered IPs
            for device in discovered_devices:
                device['ports'] = self.scan_common_ports(device['ip'])
                device['device_type'] = self.identify_device_type(device['ports'])
                device['timestamp'] = datetime.now().isoformat()
            
            self.last_scan_results = discovered_devices
            self.last_scan_time = datetime.now().isoformat()
            
            logger.info(f"Windows host scan completed. Found {len(discovered_devices)} devices")
            return discovered_devices
            
        except Exception as e:
            logger.error(f"Network scan error: {str(e)}")
            return []
    
    def scan_common_ports(self, host_ip, timeout=1):
        """Scan common ports on a host"""
        common_ports = [22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 8080, 8443]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host_ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                continue
        
        return open_ports
    
    def identify_device_type(self, open_ports):
        """Identify device type based on open ports"""
        if 22 in open_ports:
            return "Linux/Unix Device"
        elif 135 in open_ports or 139 in open_ports or 445 in open_ports:
            return "Windows Device"
        elif 80 in open_ports or 443 in open_ports:
            return "Web Server/Router"
        elif 23 in open_ports:
            return "Network Device"
        else:
            return "Unknown Device"

# Initialize scanner
scanner = WindowsHostScanner()

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "service": "windows-host-scanner"})

@app.route('/scan', methods=['GET'])
def scan_network():
    """Perform network scan"""
    network_range = request.args.get('range', '172.20.10.0/24')
    
    try:
        results = scanner.scan_network_range(network_range)
        
        return jsonify({
            "status": "success",
            "scan_time": scanner.last_scan_time,
            "network_range": network_range,
            "devices_found": len(results),
            "devices": results
        })
        
    except Exception as e:
        logger.error(f"Scan request failed: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/network-info', methods=['GET'])
def get_network_info():
    """Get Windows network configuration"""
    try:
        network_info = scanner.get_windows_network_info()
        arp_table = scanner.get_arp_table()
        
        return jsonify({
            "status": "success",
            "network_config": network_info,
            "arp_table": arp_table
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/last-scan', methods=['GET'])
def get_last_scan():
    """Get results from last scan"""
    return jsonify({
        "status": "success",
        "scan_time": scanner.last_scan_time,
        "devices_found": len(scanner.last_scan_results),
        "devices": scanner.last_scan_results
    })

if __name__ == '__main__':
    logger.info("Starting Windows Host Scanner Service...")
    
    # Start background scanner thread
    def background_scanner():
        while True:
            try:
                scanner.scan_network_range()
                time.sleep(300)  # Scan every 5 minutes
            except Exception as e:
                logger.error(f"Background scan error: {str(e)}")
                time.sleep(60)
    
    scanner_thread = threading.Thread(target=background_scanner, daemon=True)
    scanner_thread.start()
    
    # Start Flask app
    app.run(host='0.0.0.0', port=5555, debug=False)