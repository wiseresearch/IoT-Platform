# Host Traffic Monitor with TShark
# Captures actual network traffic with real byte counts using Wireshark/TShark

from flask import Flask, jsonify, request
import subprocess
import json
from datetime import datetime, timezone
import threading
import time
import re
import os
import shutil
from collections import defaultdict



app = Flask(__name__)

# Global storage for traffic statistics
traffic_stats = defaultdict(lambda: {
    'bytes_sent': 0,
    'bytes_recv': 0,
    'packets_sent': 0,
    'packets_recv': 0,
    'last_seen': 0
})
traffic_stats_lock = threading.Lock()
capture_running = False
capture_thread = None
capture_process = None
capture_started_at = None
traffic_sampling_running = False
traffic_sampling_thread = None

# DHCP fingerprint storage
dhcp_fingerprints = {}

# Minimal OUI/vendor hints for passive OS inference (best-effort)
OUI_VENDOR_HINTS = {
    "d8:eb:46": ("Google", "Android"),   # Chromecast / Google
    "f0:ef:86": ("Apple", "iOS"),
    "3c:22:fb": ("Apple", "iOS"),
    "bc:92:6b": ("Apple", "iOS"),
    "8c:17:59": ("Samsung", "Android"),
    "d0:17:c2": ("Samsung", "Android"),
    "f0:25:b7": ("Samsung", "Android"),
    "00:15:5d": ("Microsoft", "Windows"),  # Hyper-V / Windows host
}


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
                with traffic_stats_lock:
                    stats = traffic_stats.get(conn_key, {
                        'bytes_sent': 0,
                        'bytes_recv': 0,
                        'packets_sent': 0,
                        'packets_recv': 0
                    })
                
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
        
        with traffic_stats_lock:
            stats_items = list(traffic_stats.items())
        for conn_key, stats in stats_items:
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
    max_age_param = request.args.get('max_age_seconds', '3600')
    try:
        max_age_seconds = int(max_age_param)
    except ValueError:
        max_age_seconds = 3600

    for mac, data in dhcp_fingerprints.items():

        #  Ignore stale devices unless max_age_seconds is 0
        if max_age_seconds > 0 and now - data["last_seen"] > max_age_seconds:
            continue

        os_name, confidence, os_version, version_confidence = infer_os_with_confidence(
            data.get("param_req", []),
            mac=mac,
            ttl=data.get("ttl_guess"),
            hostname=data.get("hostname"),
            vendor_class=data.get("vendor_class")
        )

        devices.append({
            "ip_address": data.get("ip_address"),
            "mac_address": mac,
            "hostname": data.get("hostname"),
            "vendor_class": data.get("vendor_class"),
            "ttl_guess": data.get("ttl_guess"),
            "os": os_name,
            "os_confidence": confidence,
            "os_version": os_version,
            "version_confidence": version_confidence,
            "last_seen": datetime.fromtimestamp(data["last_seen"]).isoformat()
        })

    return jsonify({
        "status": "success",
        "devices": devices,
        "count": len(devices),
        "capture_active": capture_running,
        "capture_started_at": capture_started_at
    })



def perform_start_capture():
    """Start tshark packet capture (internal helper)."""
    global capture_running, capture_thread, capture_started_at

    if capture_running:
        return {"status": "already_running"}, 200

    # Reset fingerprints and PCAP on fresh start
    dhcp_fingerprints.clear()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_path = os.path.join(script_dir, "dhcp_capture.pcap")
    try:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)
    except Exception:
        pass

    capture_running = True
    capture_started_at = datetime.now(timezone.utc).isoformat()
    capture_thread = threading.Thread(target=capture_traffic, daemon=True)
    capture_thread.start()

    return {"status": "started", "capture_started_at": capture_started_at}, 200


def perform_stop_capture():
    """Stop tshark packet capture (internal helper)."""
    global capture_running, capture_thread, capture_process

    capture_running = False

    if capture_process and capture_process.poll() is None:
        try:
            capture_process.terminate()
            capture_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            capture_process.kill()
        except Exception:
            pass
        finally:
            capture_process = None

    if capture_thread and capture_thread.is_alive():
        capture_thread.join(timeout=10)

    return {"status": "stopped", "devices_found": len(dhcp_fingerprints)}, 200


@app.route('/start-capture', methods=['POST'])
def start_capture():
    """Start tshark packet capture"""
    payload, code = perform_start_capture()
    return jsonify(payload), code


@app.route('/stop-capture', methods=['POST'])
def stop_capture():
    payload, code = perform_stop_capture()
    return jsonify(payload), code


@app.route('/restart-capture', methods=['POST'])
def restart_capture():
    """Restart tshark packet capture"""
    perform_stop_capture()
    payload, code = perform_start_capture()
    payload["status"] = "restarted" if payload.get("status") == "started" else payload.get("status")
    return jsonify(payload), code

def wait_for_pcap(pcap_path, timeout_seconds=10):
    """Wait for PCAP file to exist and be non-empty."""
    start = time.time()
    while time.time() - start < timeout_seconds:
        if os.path.exists(pcap_path):
            try:
                if os.path.getsize(pcap_path) > 0:
                    return True
            except Exception:
                pass
        time.sleep(0.5)
    return False


def capture_traffic():
    global capture_running, capture_process

    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_path = os.path.join(script_dir, "dhcp_capture.pcap")
    capture_interface = os.getenv("TSHARK_INTERFACE", "Wi-Fi 2")
    capture_duration = int(os.getenv("TSHARK_CAPTURE_SECONDS", "0"))
    analyze_interval = int(os.getenv("TSHARK_ANALYZE_INTERVAL", "15"))
    last_analyze = 0

    cmd = [
        tshark_path,
        "-i", capture_interface,
        "-f", "udp port 67 or udp port 68",
        "-w", pcap_path
    ]

    if capture_duration > 0:
        cmd.insert(5, "-a")
        cmd.insert(6, f"duration:{capture_duration}")

    print(f"Using capture interface: {capture_interface}")
    if capture_duration > 0:
        print(f"Capturing DHCP traffic to {pcap_path} (auto-stop after {capture_duration}s)")
    else:
        print(f"Capturing DHCP traffic to {pcap_path} (no auto-stop)")

    capture_process = subprocess.Popen(cmd)

    # Wait briefly for the PCAP to be created before first analysis
    wait_for_pcap(pcap_path, timeout_seconds=5)

    while capture_running:
        if capture_process.poll() is not None:
            break
        if analyze_interval > 0 and (time.time() - last_analyze) >= analyze_interval:
            analyze_dhcp_pcap()
            last_analyze = time.time()
        time.sleep(1)

    if capture_process and capture_process.poll() is None:
        capture_process.terminate()
        try:
            capture_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            capture_process.kill()

    capture_running = False
    capture_process = None
    print("Capture stopped")
    analyze_dhcp_pcap()
    print(f"DHCP analysis complete: {len(dhcp_fingerprints)} device(s) fingerprinted")

def analyze_dhcp_pcap():
    global dhcp_fingerprints

    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_path = os.path.join(script_dir, "dhcp_capture.pcap")
    snapshot_path = os.path.join(script_dir, "dhcp_capture.snapshot.pcap")

    if not wait_for_pcap(pcap_path, timeout_seconds=5):
        print(f"PCAP not ready: {pcap_path}")
        return
    try:
        if os.path.getsize(pcap_path) < 64:
            # Too small to parse reliably; avoid wiping existing fingerprints.
            return
    except Exception:
        return

    try:
        shutil.copyfile(pcap_path, snapshot_path)
    except Exception as e:
        print(f"PCAP snapshot copy failed: {e}")
        return

    cmd = [
        tshark_path,
        "-r", snapshot_path,
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "bootp.hw.mac_addr",
        "-e", "dhcp.option.requested_ip_address",
        "-e", "dhcp.option.request_list_item",
        "-e", "ip.ttl",
        "-e", "bootp.option.hostname",
        "-e", "bootp.option.vendor_class_id",
        "-E", "separator=|"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"TShark read error: {result.stderr}")
        return

    # Only clear on successful parse to avoid dropping devices on transient errors.
    dhcp_fingerprints.clear()

    prl_by_mac = defaultdict(list)
    ttl_by_mac = defaultdict(list)
    hostname_by_mac = {}
    vendor_by_mac = {}
    ip_by_mac = {}
    last_seen_by_mac = {}

    for line in result.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < 3:
            continue

        ts_raw = parts[0].strip()
        mac = parts[1].split(",")[0].strip().lower().replace("-", ":")

        requested_ip = parts[2].strip() if len(parts) > 2 else ""
        item = parts[3].strip() if len(parts) > 3 else ""
        ttl_raw = parts[4].strip() if len(parts) > 4 else ""
        hostname = parts[5].strip() if len(parts) > 5 else ""
        vendor_class = parts[6].strip() if len(parts) > 6 else ""

        try:
            ts_epoch = float(ts_raw) if ts_raw else None
        except ValueError:
            ts_epoch = None

        if mac and requested_ip and mac not in ip_by_mac:
            ip_by_mac[mac] = requested_ip
        if mac and ts_epoch:
            prev_ts = last_seen_by_mac.get(mac)
            if not prev_ts or ts_epoch > prev_ts:
                last_seen_by_mac[mac] = ts_epoch

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

        last_seen_value = last_seen_by_mac.get(mac) or time.time()
        dhcp_fingerprints[mac] = {
            "hostname": hostname_by_mac.get(mac),
            "vendor_class": vendor_by_mac.get(mac),
            "param_req": clean_prl,
            "ttl_guess": ttl_guess,
            "ip_address": ip_by_mac.get(mac),
            "last_seen": last_seen_value
        }

def _prune_traffic_stats(ttl_seconds):
    cutoff = time.time() - ttl_seconds
    with traffic_stats_lock:
        for key, stats in list(traffic_stats.items()):
            if stats.get('last_seen', 0) < cutoff:
                traffic_stats.pop(key, None)


def _update_traffic_stats_from_packets(lines):
    now = time.time()
    for line in lines:
        parts = line.split("|")
        if len(parts) < 8:
            continue
        ip_src = parts[1].strip()
        ip_dst = parts[2].strip()
        tcp_src = parts[3].strip()
        tcp_dst = parts[4].strip()
        udp_src = parts[5].strip()
        udp_dst = parts[6].strip()
        frame_len_raw = parts[7].strip()

        if not ip_src or not ip_dst:
            continue

        src_port = tcp_src or udp_src
        dst_port = tcp_dst or udp_dst
        if not src_port or not dst_port:
            continue

        try:
            src_port = int(src_port)
            dst_port = int(dst_port)
            frame_len = int(frame_len_raw)
        except ValueError:
            continue

        key = f"{ip_src}:{src_port}-{ip_dst}:{dst_port}"
        rev_key = f"{ip_dst}:{dst_port}-{ip_src}:{src_port}"

        with traffic_stats_lock:
            stats = traffic_stats[key]
            stats['bytes_sent'] += frame_len
            stats['packets_sent'] += 1
            stats['last_seen'] = now

            rev_stats = traffic_stats[rev_key]
            rev_stats['bytes_recv'] += frame_len
            rev_stats['packets_recv'] += 1
            rev_stats['last_seen'] = now


def start_traffic_sampling():
    """Start periodic tshark sampling for traffic stats."""
    global traffic_sampling_running, traffic_sampling_thread
    if traffic_sampling_running and traffic_sampling_thread and traffic_sampling_thread.is_alive():
        return
    traffic_sampling_running = True
    traffic_sampling_thread = threading.Thread(target=_traffic_sampling_loop, daemon=True)
    traffic_sampling_thread.start()


def stop_traffic_sampling():
    """Stop periodic tshark sampling for traffic stats."""
    global traffic_sampling_running, traffic_sampling_thread
    traffic_sampling_running = False
    if traffic_sampling_thread and traffic_sampling_thread.is_alive():
        traffic_sampling_thread.join(timeout=5)
    traffic_sampling_thread = None


def _traffic_sampling_loop():
    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
    capture_interface = os.getenv("TSHARK_INTERFACE", "Wi-Fi 2")
    sample_seconds = int(os.getenv("TSHARK_TRAFFIC_SAMPLE_SECONDS", "3"))
    sample_interval = int(os.getenv("TSHARK_TRAFFIC_SAMPLE_INTERVAL", "5"))
    ttl_seconds = int(os.getenv("TSHARK_TRAFFIC_TTL_SECONDS", "600"))

    if not os.path.exists(tshark_path):
        print(f"TShark not found at {tshark_path}. Traffic sampling disabled.")
        return

    while traffic_sampling_running:
        cmd = [
            tshark_path,
            "-i", capture_interface,
            "-a", f"duration:{sample_seconds}",
            "-f", "ip",
            "-n",
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
            "-e", "frame.len",
            "-E", "separator=|"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0 and result.stdout:
                _update_traffic_stats_from_packets(result.stdout.splitlines())
        except Exception as e:
            print(f"Traffic sampling error: {e}")

        _prune_traffic_stats(ttl_seconds)
        time.sleep(sample_interval)

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


def lookup_oui_vendor(mac):
    if not mac:
        return None, None
    prefix = mac.lower().replace("-", ":")[:8]
    return OUI_VENDOR_HINTS.get(prefix, (None, None))


def infer_os_version(best_os, hostname, vendor_class, mac_vendor_hint, ttl):
    hostname = (hostname or "").lower()
    vendor_class = (vendor_class or "").lower()
    version_confidence = 0
    version = "unknown"

    if best_os == "Windows":
        if re.search(r"(win|windows)[-_ ]?11", hostname):
            version = "Windows 11"
            version_confidence = 75
        match = re.search(r"(23h2|22h2|21h2)", hostname)
        if match:
            version = f"Windows 11 {match.group(1).upper()}"
            version_confidence = 85
        if re.search(r"(win|windows)[-_ ]?10", hostname):
            version = "Windows 10"
            version_confidence = max(version_confidence, 70)
        if "msft" in vendor_class:
            version_confidence = max(version_confidence, 40)

    if best_os == "iOS":
        match = re.search(r"(ios|iphoneos)[-_ ]?(\d+(?:\.\d+)*)", hostname)
        if match:
            version = f"iOS {match.group(2)}"
            version_confidence = 75
        if "iphone" in hostname or "ipad" in hostname:
            version_confidence = max(version_confidence, 40)

    if best_os == "Android":
        match = re.search(r"(android)[-_ ]?(\d+(?:\.\d+)*)", hostname)
        if match:
            version = f"Android {match.group(2)}"
            version_confidence = 75
        if "android" in vendor_class:
            version_confidence = max(version_confidence, 45)

    if best_os == "Linux":
        match = re.search(r"(ubuntu|debian)[-_ ]?(\d+(?:\.\d+)*)", hostname)
        if match:
            distro = match.group(1).capitalize()
            version = f"{distro} {match.group(2)}"
            version_confidence = 65

    if mac_vendor_hint:
        if best_os == "iOS" and mac_vendor_hint == "Apple":
            version_confidence = max(version_confidence, 45)
        if best_os == "Android" and mac_vendor_hint in ("Samsung", "Google"):
            version_confidence = max(version_confidence, 40)

    if ttl in (60, 64) and best_os in ("Android", "iOS", "Linux"):
        version_confidence = min(90, version_confidence + 5)

    return version, int(version_confidence)


def infer_os_with_confidence(opts, mac=None, ttl=None, hostname=None, vendor_class=None):
    if not opts:
        return "Unknown", 30, "unknown", 0

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
    vendor_name, vendor_os_hint = lookup_oui_vendor(mac)

    scores = {
        "Windows": 0,
        "Android": 0,
        "iOS": 0,
        "Linux": 0,
        "IoT / Embedded": 0
    }

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

    if len(opts) <= 3:
        scores["IoT / Embedded"] += 26
    if len(opts) <= 5 and not (has_android_core or has_ios_core or has_windows_core):
        scores["IoT / Embedded"] += 16
    if opts.issubset({"1", "3", "6", "15", "51", "54"}):
        scores["IoT / Embedded"] += 12

    hint_text = f"{hostname} {vendor_class}"
    if any(x in hint_text for x in ("iphone", "ipad", "ios")):
        scores["iOS"] += 55
    if "android" in hint_text:
        scores["Android"] += 45
    if any(x in hint_text for x in ("windows", "msft", "microsoft")):
        scores["Windows"] += 45
    if any(x in hint_text for x in ("ubuntu", "debian", "fedora", "centos", "linux")):
        scores["Linux"] += 35

    if vendor_os_hint == "iOS":
        scores["iOS"] += 18
    if vendor_os_hint == "Android":
        scores["Android"] += 18
    if vendor_os_hint == "Windows":
        scores["Windows"] += 12

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

    if best_score < 34:
        return "Unknown", 35, "unknown", 0

    confidence = min(98, max(45, best_score + min(20, gap * 2)))
    version, version_confidence = infer_os_version(best_os, hostname, vendor_class, vendor_name, ttl)
    version_threshold = int(os.getenv("VERSION_DETECTION_THRESHOLD", "60"))
    if version_confidence < version_threshold:
        version = "unknown"
    return best_os, int(confidence), version, int(version_confidence)









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
    print("Starting traffic sampling for real byte counts...")
    start_traffic_sampling()
    capture_running = True
    capture_started_at = datetime.now(timezone.utc).isoformat()
    capture_thread = threading.Thread(target=capture_traffic, daemon=True)
    capture_thread.start()
    
    app.run(host='0.0.0.0', port=5556, debug=False)
