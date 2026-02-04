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

# DHCP fingerprint storage
dhcp_fingerprints = {}


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

@app.route('/dhcp/devices', methods=['GET'])
def get_dhcp_devices():
    devices = []
    now = time.time()

    for mac, data in dhcp_fingerprints.items():

        #  Ignore les devices trop anciens (5 minutes)
        if now - data["last_seen"] > 300:
            continue

        os_name, confidence = infer_os_with_confidence(
            data.get("param_req", []),
            mac=mac,
            ttl=data.get("ttl_guess"),
            hostname=data.get("hostname"),
            vendor_class=data.get("vendor_class")
        )

        devices.append({
            "mac_address": mac,
            "hostname": data.get("hostname"),
            "vendor_class": data.get("vendor_class"),
            "ttl_guess": data.get("ttl_guess"),
            "os": os_name,
            "os_confidence": confidence,
            "last_seen": datetime.fromtimestamp(data["last_seen"]).isoformat()
        })

    return jsonify({
        "status": "success",
        "devices": devices
    })



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
    global capture_running

    capture_running = False

    # Attendre que tshark ferme correctement le fichier PCAP
    time.sleep(2)

    # ÉTAPE 2 : analyse du PCAP
    analyze_dhcp_pcap()

    return jsonify({
        "status": "stopped",
        "devices_found": len(dhcp_fingerprints)
    })


def capture_traffic():
    global capture_running

    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"

    cmd = [
        tshark_path,
        "-i", "6",
        "-f", "udp port 67 or udp port 68",
        "-w", "dhcp_capture.pcap"
    ]

    print("🔍 Capturing DHCP traffic to dhcp_capture.pcap")

    process = subprocess.Popen(cmd)

    while capture_running:
        time.sleep(1)

    process.terminate()
    print("🛑 Capture stopped")




def analyze_dhcp_pcap():
    global dhcp_fingerprints
    dhcp_fingerprints.clear()

    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"

    cmd = [
        tshark_path,
        "-r", "dhcp_capture.pcap",
        "-T", "fields",
        "-e", "bootp.hw.mac_addr",
        "-e", "dhcp.option.request_list_item",
        "-e", "ip.ttl",
        "-e", "bootp.option.hostname",
        "-e", "bootp.option.vendor_class_id",
        "-E", "separator=|"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    prl_by_mac = defaultdict(list)
    ttl_by_mac = defaultdict(list)
    hostname_by_mac = {}
    vendor_by_mac = {}

    for line in result.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < 2:
            continue

        mac = parts[0].split(",")[0].strip()

        item = parts[1].strip()
        ttl_raw = parts[2].strip() if len(parts) > 2 else ""
        hostname = parts[3].strip() if len(parts) > 3 else ""
        vendor_class = parts[4].strip() if len(parts) > 4 else ""

        if mac and item:
            # TShark peut renvoyer une liste CSV sur une seule ligne: "1,3,6,15,..."
            # On stocke chaque code séparément pour une signature DHCP correcte.
            for token in item.split(","):
                token = token.strip()
                if token:
                    prl_by_mac[mac].append(token)
        if mac and ttl_raw:
            for t in ttl_raw.split(","):
                t = t.strip()
                if not t:
                    continue
                try:
                    ttl_val = int(t)
                    if 1 <= ttl_val <= 255:
                        ttl_by_mac[mac].append(ttl_val)
                except ValueError:
                    pass
        if mac and hostname and mac not in hostname_by_mac:
            hostname_by_mac[mac] = hostname
        if mac and vendor_class and mac not in vendor_by_mac:
            vendor_by_mac[mac] = vendor_class

    def infer_initial_ttl(ttl_values):
        if not ttl_values:
            return None
        # Heuristique type Zeek/p0f: normaliser vers la base TTL la plus proche
        avg_ttl = sum(ttl_values) / len(ttl_values)
        for base in (32, 60, 64, 128, 255):
            if avg_ttl <= base:
                return base
        return 255


    for mac, prl in prl_by_mac.items():
        # suppression des doublons + nettoyage
        clean_prl = sorted(set(p for p in prl if p))
        ttl_guess = infer_initial_ttl(ttl_by_mac.get(mac, []))

        dhcp_fingerprints[mac] = {
            "hostname": hostname_by_mac.get(mac),
            "vendor_class": vendor_by_mac.get(mac),
            "param_req": clean_prl,
            "ttl_guess": ttl_guess,
            "last_seen": time.time()
        }






def infer_os_with_confidence(opts, mac=None, ttl=None, hostname=None, vendor_class=None):
    if not opts:
        return "Unknown", 30

    # Normalisation robuste: int/str + éclatement des listes "1,3,6,15"
    normalized_opts = set()
    for raw in opts:
        if raw is None:
            continue
        for token in str(raw).split(","):
            token = token.strip()
            if token:
                normalized_opts.add(token)
    opts = normalized_opts
    mac = (mac or "").lower().replace("-", ":")
    hostname = (hostname or "").lower()
    vendor_class = (vendor_class or "").lower()

    # Score de base (DHCP + TTL)
    scores = {
        "Windows": 0,
        "Android": 0,
        "iOS": 0,
        "Linux": 0,
        "IoT / Embedded": 0
    }

    # ───────────────── DHCP PRL signatures (style Zeek) ─────────────────
    has_android_core = {"26", "28"}.issubset(opts)
    has_ios_core = {"119", "252"}.issubset(opts) or {"95", "252"}.issubset(opts)
    has_windows_core = {"44", "46", "47"}.issubset(opts) or "249" in opts

    if {"44", "46", "47"}.issubset(opts):
        scores["Windows"] += 45
    if "249" in opts:
        scores["Windows"] += 35
    if "43" in opts:
        scores["Windows"] += 16
    if {"1", "3", "6", "15"}.issubset(opts):
        scores["Windows"] += 4

    if {"26", "28"}.issubset(opts):
        scores["Android"] += 45
    if "114" in opts:
        scores["Android"] += 16
    if {"51", "58", "59"}.issubset(opts):
        scores["Android"] += 10

    if {"119", "252"}.issubset(opts):
        scores["iOS"] += 36
    if {"95", "252"}.issubset(opts):
        scores["iOS"] += 28
    if "95" in opts:
        scores["iOS"] += 8
    if {"1", "3", "6", "15"}.issubset(opts):
        scores["iOS"] += 4

    if {"17", "23"}.issubset(opts):
        scores["Linux"] += 18
    if "42" in opts:
        scores["Linux"] += 12
    if {"12", "51", "58", "59"}.issubset(opts):
        scores["Linux"] += 8

    # IoT: PRL courte/générique, sans marqueurs forts mobile/desktop
    if len(opts) <= 3:
        scores["IoT / Embedded"] += 26
    if len(opts) <= 5 and not (has_android_core or has_ios_core or has_windows_core):
        scores["IoT / Embedded"] += 16
    if opts.issubset({"1", "3", "6", "15", "51", "54"}):
        scores["IoT / Embedded"] += 12

    # ───────────────── DHCP host/vclass hints ─────────────────
    hint_text = f"{hostname} {vendor_class}"
    if any(x in hint_text for x in ("iphone", "ipad", "ios")):
        scores["iOS"] += 55
    if "android" in hint_text:
        scores["Android"] += 45
    if any(x in hint_text for x in ("windows", "msft", "microsoft")):
        scores["Windows"] += 45
    if any(x in hint_text for x in ("ubuntu", "debian", "fedora", "centos", "linux")):
        scores["Linux"] += 35

    # ───────────────── TTL (style Zeek/p0f simplifié) ─────────────────
    # Windows: souvent 128 ; Linux/Android/iOS: souvent 64 ; équipements réseau/IoT: parfois 255
    if ttl is not None:
        try:
            t = int(ttl)
            if t == 128:
                scores["Windows"] += 24
                scores["Linux"] -= 8
                scores["Android"] -= 8
                scores["iOS"] -= 6
            elif t in (60, 64):
                scores["Linux"] += 12
                scores["Android"] += 14
                scores["iOS"] += 16
                scores["Windows"] -= 10
                scores["IoT / Embedded"] -= 8
            elif t == 255:
                scores["IoT / Embedded"] += 20
                scores["Windows"] -= 8
            elif t == 32:
                scores["IoT / Embedded"] += 10
        except (TypeError, ValueError):
            pass

    # ───────────────── Conflits entre signatures ─────────────────
    if {"26", "28"}.issubset(opts):
        scores["iOS"] -= 12
        scores["Windows"] -= 6
    if {"95", "119", "252"}.issubset(opts):
        scores["Android"] -= 8
    if "249" in opts:
        scores["Android"] -= 10
        scores["iOS"] -= 8
    if has_ios_core:
        scores["IoT / Embedded"] -= 18
    if has_windows_core:
        scores["IoT / Embedded"] -= 14

    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    best_os, best_score = ranked[0]
    second_score = ranked[1][1]
    gap = max(0, best_score - second_score)

    # Si tout est trop faible / ambigu, éviter un faux positif fort.
    if best_score < 34:
        return "Unknown", 35

    # Confiance finale: priorité au meilleur score + séparation avec le second
    confidence = min(98, max(45, best_score + min(20, gap * 2)))
    return best_os, int(confidence)









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
