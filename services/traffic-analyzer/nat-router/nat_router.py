#!/usr/bin/env python3

"""
Simple NAT Router for Unified Security Platform
Provides basic routing and traffic management functionality
"""

import os
import sys
import subprocess
import logging
import time
from flask import Flask, jsonify, request

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

class NATRouter:
    def __init__(self):
        self.running = False
    
    def setup_nat_rules(self):
        """Setup basic NAT and routing rules"""
        try:
            # Enable IP forwarding
            subprocess.run(['sysctl', 'net.ipv4.ip_forward=1'], check=True)
            
            # Setup basic iptables rules for NAT
            subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', 
                          '-s', '172.20.0.0/24', '-o', 'eth1', '-j', 'MASQUERADE'], 
                         check=False)
            
            logger.info("NAT rules configured successfully")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to setup NAT rules: {e}")
        except Exception as e:
            logger.error(f"Error setting up NAT: {e}")
    
    def start_routing(self):
        """Start the routing service"""
        if not self.running:
            self.running = True
            self.setup_nat_rules()
            logger.info("NAT Router started")
    
    def stop_routing(self):
        """Stop the routing service"""
        if self.running:
            self.running = False
            logger.info("NAT Router stopped")

# Initialize router
nat_router = NATRouter()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'nat-router',
        'routing_active': nat_router.running
    })

@app.route('/start', methods=['POST'])
def start_routing():
    """Start NAT routing"""
    nat_router.start_routing()
    return jsonify({'status': 'NAT routing started'})

@app.route('/stop', methods=['POST'])
def stop_routing():
    """Stop NAT routing"""
    nat_router.stop_routing()
    return jsonify({'status': 'NAT routing stopped'})

@app.route('/status', methods=['GET'])
def get_status():
    """Get routing status"""
    return jsonify({
        'routing_active': nat_router.running,
        'timestamp': time.time()
    })

if __name__ == '__main__':
    # Auto-start routing
    nat_router.start_routing()
    
    # Start Flask API
    app.run(host='0.0.0.0', port=5050, debug=False)