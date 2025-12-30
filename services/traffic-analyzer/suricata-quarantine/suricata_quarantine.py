#!/usr/bin/env python3

"""
Suricata Quarantine Management Script
Handles quarantine and unquarantine operations for the Unified Security Platform
"""

import sys
import subprocess
import logging
import json
import time
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class QuarantineManager:
    def __init__(self):
        self.quarantined_ips = set()
        self.quarantine_log = "/var/log/suricata/quarantine.log"
    
    def quarantine_ip(self, ip_address, reason="Security threat detected"):
        """Quarantine an IP address by blocking traffic"""
        try:
            # Add iptables rule to drop traffic from this IP
            subprocess.run([
                'iptables', '-I', 'INPUT', '1', '-s', ip_address, '-j', 'DROP'
            ], check=True)
            
            subprocess.run([
                'iptables', '-I', 'FORWARD', '1', '-s', ip_address, '-j', 'DROP'
            ], check=True)
            
            # Add to quarantined set
            self.quarantined_ips.add(ip_address)
            
            # Log the action
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'action': 'quarantine',
                'ip': ip_address,
                'reason': reason
            }
            
            self.log_action(log_entry)
            logger.info(f"Quarantined IP: {ip_address} - {reason}")
            
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to quarantine IP {ip_address}: {e}")
            return False
        except Exception as e:
            logger.error(f"Error quarantining IP {ip_address}: {e}")
            return False
    
    def unquarantine_ip(self, ip_address):
        """Remove quarantine for an IP address"""
        try:
            # Remove iptables rules
            subprocess.run([
                'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'
            ], check=False)  # Don't fail if rule doesn't exist
            
            subprocess.run([
                'iptables', '-D', 'FORWARD', '-s', ip_address, '-j', 'DROP'
            ], check=False)
            
            # Remove from quarantined set
            self.quarantined_ips.discard(ip_address)
            
            # Log the action
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'action': 'unquarantine',
                'ip': ip_address,
                'reason': 'Manual unquarantine'
            }
            
            self.log_action(log_entry)
            logger.info(f"Unquarantined IP: {ip_address}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error unquarantining IP {ip_address}: {e}")
            return False
    
    def list_quarantined(self):
        """List all quarantined IPs"""
        return list(self.quarantined_ips)
    
    def log_action(self, log_entry):
        """Log quarantine actions"""
        try:
            with open(self.quarantine_log, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.error(f"Failed to write log: {e}")

def main():
    """Main function for command-line usage"""
    if len(sys.argv) < 3:
        print("Usage: python3 suricata_quarantine.py <quarantine|unquarantine> <ip_address> [reason]")
        sys.exit(1)
    
    action = sys.argv[1].lower()
    ip_address = sys.argv[2]
    reason = sys.argv[3] if len(sys.argv) > 3 else "Manual action"
    
    qm = QuarantineManager()
    
    if action == 'quarantine':
        if qm.quarantine_ip(ip_address, reason):
            print(f"Successfully quarantined {ip_address}")
        else:
            print(f"Failed to quarantine {ip_address}")
            sys.exit(1)
    
    elif action == 'unquarantine':
        if qm.unquarantine_ip(ip_address):
            print(f"Successfully unquarantined {ip_address}")
        else:
            print(f"Failed to unquarantine {ip_address}")
            sys.exit(1)
    
    elif action == 'list':
        quarantined = qm.list_quarantined()
        if quarantined:
            print("Quarantined IPs:")
            for ip in quarantined:
                print(f"  - {ip}")
        else:
            print("No IPs currently quarantined")
    
    else:
        print(f"Unknown action: {action}")
        print("Valid actions: quarantine, unquarantine, list")
        sys.exit(1)

if __name__ == '__main__':
    main()