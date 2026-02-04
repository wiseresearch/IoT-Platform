# Host Traffic Monitor with TShark
# Captures actual network traffic with real byte counts using Wireshark/TShark

from flask import Flask, jsonify, request
import subprocess
import json
from datetime import datetime
import threading
import time
from collections import defaultdict

app = Flask(__name__)

# Global storage for traffic statistics
traffic_stats = defaultdict(lambda: {'bytes_sent': 0, 'bytes_recv': 0, 'packets_sent': 0, 'packets_recv': 0})
capture_running = False
capture_thread = None

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "service": "host-traffic-monitor-tshark"})

@app.route('/connections', methods=['GET'])
def get_connections():
    """Get current network connections - combines psutil TCP + tshark UDP flows"""
    try:
        import psutil
        
        connections = []
        seen_keys = set()
        
        # First, add TCP connections from psutil (with ESTABLISHED state)
        net_connections = psutil.net_connections(kind='inet')
        
        for conn in net_connections:
            if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
                local_ip = conn.laddr.ip
                local_port = conn.laddr.port
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                
                # Skip loopback
                if local_ip in ['127.0.0.1', '::1'] or remote_ip in ['127.0.0.1', '::1']:
                    continue
                
                # Create connection key
                conn_key = f"{local_ip}:{local_port}-{remote_ip}:{remote_port}"
                seen_keys.add(conn_key)
                
                # Get stats from tshark capture
                stats = traffic_stats.get(conn_key, {'bytes_sent': 0, 'bytes_recv': 0, 'packets_sent': 0, 'packets_recv': 0})
                
                try:
                    process = psutil.Process(conn.pid) if conn.pid else None
                    process_name = process.name() if process else 'Unknown'
                except:
                    process_name = 'Unknown'
                
                connections.append({
                    'protocol': 'tcp',
                    'src_ip': local_ip,
                    'dest_ip': remote_ip,
                    'src_port': local_port,
                    'dest_port': remote_port,
                    'state': conn.status.lower(),
                    'pid': conn.pid,
                    'process_name': process_name,
                    'bytes_sent': stats['bytes_sent'],
                    'bytes_recv': stats['bytes_recv'],
                    'packets_sent': stats['packets_sent'],
                    'packets_recv': stats['packets_recv']
                })
        
        # Add UDP flows from TShark data (flows with traffic in last 60 seconds)
        now = time.time()
        cutoff_time = now - 60  # Last 60 seconds
        
        for conn_key, stats in list(traffic_stats.items()):
            if conn_key in seen_keys:
                continue  # Already added as TCP
            
            # Check if this flow has recent activity
            last_seen = stats.get('last_seen', 0)
            if last_seen < cutoff_time:
                continue
            
            # Parse connection key: "src_ip:src_port-dest_ip:dest_port"
            try:
                src_part, dest_part = conn_key.split('-')
                src_ip, src_port = src_part.rsplit(':', 1)
                dest_ip, dest_port = dest_part.rsplit(':', 1)
                
                # Assume UDP if not in psutil TCP connections
                connections.append({
                    'protocol': 'udp',
                    'src_ip': src_ip,
                    'dest_ip': dest_ip,
                    'src_port': int(src_port),
                    'dest_port': int(dest_port),
                    'state': 'active',
                    'pid': None,
                    'process_name': 'Unknown',
                    'bytes_sent': stats['bytes_sent'],
                    'bytes_recv': stats['bytes_recv'],
                    'packets_sent': stats['packets_sent'],
                    'packets_recv': stats['packets_recv']
                })
            except:
                continue
        
        return jsonify({
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "total_connections": len(connections),
            "connections": connections,
            "capture_active": capture_running
        })
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/start-capture', methods=['POST'])
def start_capture():
    """Start tshark packet capture"""
    global capture_running, capture_thread
    
    if capture_running:
        return jsonify({"status": "already_running"})
    
    capture_running = True
    capture_thread = threading.Thread(target=capture_traffic, daemon=True)
    capture_thread.start()
    
    return jsonify({"status": "started"})

@app.route('/stop-capture', methods=['POST'])
def stop_capture():
    """Stop tshark packet capture"""
    global capture_running
    capture_running = False
    return jsonify({"status": "stopped"})

def capture_traffic():
    """Capture traffic using tshark and update statistics"""
    global traffic_stats, capture_running
    
    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
    
    # Capture command: -i any (all interfaces), -T fields for custom output
    # Capture: src IP, dst IP, src port, dst port, frame length
    # Use interface name "Wi-Fi 2" which is the active adapter with IP 172.20.10.2
    interface_name = 'Wi-Fi 2'
    
    cmd = [
        tshark_path,
        '-i', interface_name,
        '-f', 'tcp or udp',  # Capture filter for TCP and UDP
        '-T', 'fields',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'ip.proto',  # Protocol number (6=TCP, 17=UDP)
        '-e', 'tcp.srcport',
        '-e', 'tcp.dstport',
        '-e', 'udp.srcport',
        '-e', 'udp.dstport',
        '-e', 'frame.len',
        '-E', 'separator=,'
    ]
    
    print(f"🔍 Starting tshark capture on interface '{interface_name}'")
    print(f"   Command: {' '.join(cmd)}")
    print(f"   Filtering: TCP and UDP traffic")
    print(f"   Fields: src_ip, dst_ip, protocol, src_port, dst_port, frame_length")
    print("   Waiting for packets...")
    
    try:
        import sys
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Redirect stderr to stdout
            text=True,
            bufsize=0,  # Unbuffered
            universal_newlines=True
        )
        
        print("✅ TShark process started successfully!")
        print(f"   PID: {process.pid}")
        sys.stdout.flush()
        packet_count = 0
        
        # Read from stdout line by line
        while capture_running:
            try:
                line = process.stdout.readline()
                if not line:
                    # Check if process ended
                    if process.poll() is not None:
                        print(f"⚠️ TShark process ended unexpectedly (exit code: {process.returncode})")
                        # Read any error output
                        stderr = process.stderr.read()
                        if stderr:
                            print(f"❌ TShark error: {stderr}")
                        break
                    continue
                
                line = line.strip()
                if not line:
                    continue
                
                # Parse the CSV line: src_ip,dst_ip,proto,tcp_src,tcp_dst,udp_src,udp_dst,frame_len
                parts = line.split(',')
                if len(parts) >= 8:
                    src_ip = parts[0]
                    dst_ip = parts[1]
                    proto_num = parts[2]  # 6=TCP, 17=UDP
                    tcp_src = parts[3]
                    tcp_dst = parts[4]
                    udp_src = parts[5]
                    udp_dst = parts[6]
                    frame_len = parts[7]
                    
                    # Determine protocol and ports
                    if proto_num == '6' and tcp_src and tcp_dst:  # TCP
                        src_port = tcp_src
                        dst_port = tcp_dst
                    elif proto_num == '17' and udp_src and udp_dst:  # UDP
                        src_port = udp_src
                        dst_port = udp_dst
                    else:
                        continue
                    
                    # Skip if any required field is empty
                    if not all([src_ip, dst_ip, src_port, dst_port, frame_len]):
                        continue
                    
                    src_port = int(src_port) if str(src_port).isdigit() else 0
                    dst_port = int(dst_port) if str(dst_port).isdigit() else 0
                    frame_len = int(frame_len) if frame_len.isdigit() else 0
                    
                    packet_count += 1
                    if packet_count == 1:
                        print(f"🎉 First packet captured!")
                        sys.stdout.flush()
                    if packet_count % 50 == 0:
                        print(f"📦 Captured {packet_count} packets, tracking {len(traffic_stats)} connections")
                        sys.stdout.flush()
                    
                    # Update stats for outgoing traffic (from local host)
                    if src_ip.startswith('172.20.10.'):
                        conn_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                        traffic_stats[conn_key]['bytes_sent'] += frame_len
                        traffic_stats[conn_key]['packets_sent'] += 1
                        traffic_stats[conn_key]['last_seen'] = time.time()
                    
                    # Update stats for incoming traffic (to local host)
                    if dst_ip.startswith('172.20.10.'):
                        conn_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
                        traffic_stats[conn_key]['bytes_recv'] += frame_len
                        traffic_stats[conn_key]['packets_recv'] += 1
                        traffic_stats[conn_key]['last_seen'] = time.time()
                        
            except ValueError as e:
                if packet_count == 0:
                    print(f"⚠️ Error parsing packet data: {e}")
                    print(f"   Raw line: {line}")
                    sys.stdout.flush()
                continue
            except Exception as e:
                if packet_count == 0:
                    print(f"⚠️ Unexpected error in capture loop: {e}")
                    sys.stdout.flush()
                continue
        
        # Process ended
        print(f"\n🛑 Capture loop ended. Processed {packet_count} packets.")
        sys.stdout.flush()
                
    except Exception as e:
        import sys
        print(f"❌ TShark capture error: {e}")
        print(f"   Make sure you're running as Administrator!")
        sys.stdout.flush()
    finally:
        capture_running = False
        print("🏁 Capture thread ended")
        sys.stdout.flush()

if __name__ == '__main__':
    print("=" * 60)
    print("Host Traffic Monitor with TShark")
    print("=" * 60)
    print("This version uses Wireshark/TShark for accurate byte counts")
    print("")
    print("Available endpoints:")
    print("  GET  /health - Health check")
    print("  GET  /connections - Get connections with real byte counts")
    print("  POST /start-capture - Start packet capture")
    print("  POST /stop-capture - Stop packet capture")
    print("")
    print("IMPORTANT: Packet capture requires Administrator privileges!")
    print("Please run this script as Administrator.")
    print("")
    print("Starting server on http://localhost:5556")
    print("=" * 60)
    
    # Auto-start capture
    print("\nAuto-starting packet capture...")
    capture_running = True
    capture_thread = threading.Thread(target=capture_traffic, daemon=True)
    capture_thread.start()
    
    app.run(host='0.0.0.0', port=5556, debug=False)
