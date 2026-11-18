"""Unified Fleet Store and real-time event stream.

Builds one normalized state model (devices, gateways, links, clusters and
incidents) from the discovery/monitoring tables, enriches it with live
reachability + latency probes, and publishes incremental deltas on the
``fleet_events`` Redis channel.  Every dashboard visualisation consumes the
same model so the topology graph, health bullseye and telemetry matrix stay
in lock-step.

The collector runs in a single gunicorn worker, elected through a Redis lock,
so N workers never duplicate probes or events.
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import threading
import time
import uuid
from collections import Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import mysql.connector
import redis
import requests

logger = logging.getLogger(__name__)

CHANNEL = "fleet_events"
SNAPSHOT_KEY = "fleet:snapshot"
LOCK_KEY = "fleet:collector:lock"
RECENT_KEY = "fleet:events:recent"
PROBE_TICK = int(os.getenv("FLEET_TICK_SECONDS", "20"))
LOCK_TTL = max(15, PROBE_TICK * 3)
PROBE_TIMEOUT = float(os.getenv("FLEET_PROBE_TIMEOUT_SECONDS", "0.6"))
PROBE_WORKERS = int(os.getenv("FLEET_PROBE_WORKERS", "24"))
PROBE_LIMIT = int(os.getenv("FLEET_PROBE_LIMIT", "200"))
QUARANTINE_SECONDS = int(os.getenv("FLEET_QUARANTINE_SECONDS", "900"))

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "unified-db"),
    "user": os.getenv("DB_USER", "security_user"),
    "password": os.getenv("DB_PASS", "change_me_db_password"),
    "database": os.getenv("DB_NAME", "unified_security"),
    "connection_timeout": 8,
}

HOST_SCANNER_API = os.getenv("HOST_SCANNER_API_URL", "http://host.docker.internal:5555")

_redis = redis.Redis(
    host=os.getenv("REDIS_HOST", "redis"),
    port=6379,
    db=0,
    decode_responses=True,
    socket_connect_timeout=3,
    socket_timeout=5,
)

WORKER_ID = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

IGNORED_PREFIXES = (
    "127.", "169.254.", "172.17.", "172.18.", "172.19.", "172.2", "172.3",
    "192.168.250.", "0.0.0.0", "::1", "fe80",
)

STRONG_NEIGHBOUR_STATES = {"REACHABLE", "DELAY", "PROBE", "PERMANENT"}
WEAK_NEIGHBOUR_STATES = {"STALE"}

RISK_PENALTY = {"low": 0, "medium": 9, "high": 19, "critical": 30}

CATEGORY_LABELS = {
    "network": "Network",
    "camera": "Cameras",
    "sensor": "Sensors",
    "hub": "Hubs & Bridges",
    "speaker": "Media & Voice",
    "phone": "Phones & Tablets",
    "computer": "Computers",
    "printer": "Printers",
    "nas": "Storage & Servers",
    "appliance": "Appliances",
    "other": "Other",
}

# Order matters: the first match wins.
CATEGORY_RULES = [
    ("network", r"router|gateway|puma|archer|nighthawk|unifi|edgerouter|openwrt|fritz|deco|orbi|access.?point"),
    ("camera", r"camera|ipcam|cam-|-cam|hikvision|dahua|reolink|wyze|blink|arlo|doorbell|nest.?cam"),
    ("speaker", r"echo|alexa|sonos|homepod|speaker|soundbar|chromecast|roku|appletv|fire.?tv|smart.?tv|tv-|television"),
    ("phone", r"iphone|ipad|android|pixel|galaxy|oneplus|phone|tablet"),
    ("printer", r"printer|laserjet|officejet|deskJet|epson|canon|brother"),
    ("nas", r"nas|synology|qnap|diskstation|fileserver|proxmox|server"),
    ("hub", r"hub|bridge|zigbee|z-wave|zwave|smartthings|home.?assistant|conbee|hue.?bridge"),
    ("appliance", r"vacuum|roborock|roomba|fridge|washer|dryer|oven|dishwasher|thermostat|airconditioner"),
    ("sensor", r"sensor|thermo|ecobee|hue|bulb|plug|switchbot|aqara|tuya|motion|contact|water.?leak"),
    ("computer", r"orin|jetson|macbook|imac|laptop|desktop|thinkpad|windows|linux|ubuntu|raspberry|rpi|workstation|-pc|wsalhab"),
]

TYPE_HINTS = {
    "camera": "camera",
    "router": "network",
    "switch": "network",
    "access point": "network",
    "printer": "printer",
    "nas": "nas",
    "server": "nas",
    "phone": "phone",
    "tablet": "phone",
    "tv": "speaker",
    "speaker": "speaker",
    "thermostat": "sensor",
    "sensor": "sensor",
    "hub": "hub",
}


def _iso(ts=None):
    if ts is None:
        ts = time.time()
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _as_ts(value):
    """Best-effort conversion of a DB datetime/string into epoch seconds."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc).timestamp()
        return value.timestamp()
    try:
        text = str(value).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except Exception:
        return None


def _clamp(value, low=0.0, high=100.0):
    return max(low, min(high, value))


def _normalize_mac(mac):
    if not mac:
        return None
    compact = re.sub(r"[^0-9a-fA-F]", "", str(mac)).lower()
    if len(compact) != 12 or compact == "0" * 12:
        return None
    return ":".join(compact[i:i + 2] for i in range(0, 12, 2))


def _device_key(mac, ip):
    return f"mac:{_normalize_mac(mac)}" if _normalize_mac(mac) else f"ip:{ip}"


def _category_for(row):
    haystack = " ".join(
        str(row.get(field) or "")
        for field in ("device_type", "hostname", "vendor", "os_name", "firmware_version")
    ).lower()
    device_type = str(row.get("device_type") or "").lower()
    for hint, category in TYPE_HINTS.items():
        if hint in device_type and "iot device" not in device_type:
            return category
    for category, pattern in CATEGORY_RULES:
        if re.search(pattern, haystack):
            return category
    return "other"


def _link_kind(category):
    if category in {"phone", "camera", "speaker", "sensor", "hub", "appliance"}:
        return "wifi"
    if category in {"computer", "nas", "printer", "network"}:
        return "wired"
    return "unknown"


def _is_ignored(ip):
    return not ip or ip.startswith(IGNORED_PREFIXES)


# ---------------------------------------------------------------------------
# data access
# ---------------------------------------------------------------------------

def _db():
    return mysql.connector.connect(**DB_CONFIG)


def load_devices():
    query = """
        SELECT d.id, d.ip_address, d.mac_address, d.hostname, d.device_type,
               d.vendor, d.os_name, d.os_version, d.os_confidence,
               d.version_confidence, d.firmware_version, d.first_seen,
               d.last_seen, d.status, d.risk_level,
               (SELECT COUNT(*) FROM device_ports p
                 WHERE p.device_id = d.id AND p.state = 'open') AS open_ports,
               (SELECT COUNT(*) FROM device_vulnerabilities dv
                 WHERE dv.device_id = d.id) AS vuln_count
        FROM devices d
        ORDER BY d.id
    """
    conn = _db()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query)
        rows = cursor.fetchall()
        cursor.close()
        return rows
    finally:
        conn.close()


def load_ports(device_ids):
    if not device_ids:
        return {}
    placeholders = ",".join(["%s"] * len(device_ids))
    query = f"""
        SELECT device_id, port_number, protocol, service_name, state
        FROM device_ports
        WHERE device_id IN ({placeholders}) AND state IN ('open', 'filtered')
        ORDER BY device_id, port_number
    """
    conn = _db()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, tuple(device_ids))
        result = defaultdict(list)
        for row in cursor.fetchall():
            result[row["device_id"]].append({
                "port": int(row["port_number"]),
                "protocol": row.get("protocol") or "tcp",
                "service": row.get("service_name") or "",
                "state": row.get("state"),
            })
        cursor.close()
        return result
    finally:
        conn.close()


def load_cves(device_ids):
    if not device_ids:
        return {}
    placeholders = ",".join(["%s"] * len(device_ids))
    query = f"""
        SELECT dv.device_id, v.cve_id, v.severity, v.cvss_score, v.summary
        FROM device_vulnerabilities dv
        JOIN vulnerabilities v ON v.id = dv.vulnerability_id
        WHERE dv.device_id IN ({placeholders})
        ORDER BY v.cvss_score DESC
        LIMIT 800
    """
    conn = _db()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, tuple(device_ids))
        result = defaultdict(list)
        for row in cursor.fetchall():
            result[row["device_id"]].append({
                "cve": row.get("cve_id"),
                "severity": row.get("severity"),
                "cvss": float(row["cvss_score"]) if row.get("cvss_score") is not None else None,
                "summary": (row.get("summary") or "")[:160],
            })
        cursor.close()
        return result
    finally:
        conn.close()


def load_incidents():
    query = """
        SELECT id, incident_id, title, description, severity, status,
               affected_devices, created_at, updated_at
        FROM security_incidents
        WHERE status IN ('open', 'investigating', 'contained')
        ORDER BY FIELD(severity, 'critical', 'high', 'medium', 'low'), created_at DESC
        LIMIT 60
    """
    try:
        conn = _db()
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(query)
            rows = cursor.fetchall()
            cursor.close()
            return rows
        finally:
            conn.close()
    except Exception as exc:  # table may not exist on older installs
        logger.warning("fleet: incidents unavailable: %s", exc)
        return []


def fetch_neighbours():
    try:
        response = requests.get(f"{HOST_SCANNER_API}/neighbors", timeout=4)
        payload = response.json() if response.ok else {}
        return {
            item["ip"]: str(item.get("state") or "").upper()
            for item in payload.get("neighbors", [])
            if item.get("ip")
        }
    except Exception as exc:
        logger.debug("fleet: neighbour table unavailable: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# live probes
# ---------------------------------------------------------------------------

_metrics = {}
_metrics_lock = threading.Lock()
_alert_penalties = {}
_alert_lock = threading.Lock()
_series_cache = {}


def _probe_target(ip, ports):
    candidates = [p["port"] for p in ports if p.get("state") == "open"][:3]
    for fallback in (80, 443, 22, 445, 53, 1883, 8080, 554, 8008):
        if fallback not in candidates:
            candidates.append(fallback)
    return ip, candidates[:4]


def _tcp_probe(ip, ports):
    """Return (responded, rtt_ms). A refused connection still proves liveness."""
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(PROBE_TIMEOUT)
        started = time.perf_counter()
        try:
            sock.connect((ip, port))
            return True, (time.perf_counter() - started) * 1000.0
        except ConnectionRefusedError:
            return True, (time.perf_counter() - started) * 1000.0
        except socket.timeout:
            continue
        except OSError:
            continue
        finally:
            sock.close()
    return False, None


def probe_fleet(rows, ports_by_device):
    """Probe a bounded set of LAN devices, returning per-key telemetry."""
    targets = []
    for row in rows:
        ip = row.get("ip_address")
        if _is_ignored(ip):
            continue
        targets.append((_device_key(row.get("mac_address"), ip), ip, ports_by_device.get(row["id"], [])))
    targets = targets[:PROBE_LIMIT]

    results = {}

    def run(item):
        key, ip, ports = item
        _, candidates = _probe_target(ip, ports)
        return key, ip, _tcp_probe(ip, candidates)

    with ThreadPoolExecutor(max_workers=PROBE_WORKERS) as pool:
        for key, ip, (responded, rtt) in pool.map(run, targets):
            results[key] = {"ip": ip, "responded": responded, "rtt": rtt}

    now = time.time()
    with _metrics_lock:
        for key, probe in results.items():
            metric = _metrics.setdefault(key, {
                "latency": None,
                "samples": deque(maxlen=12),
                "last_seen": None,
                "failures": 0,
            })
            metric["samples"].append(probe["rtt"] if probe["responded"] else None)
            if probe["responded"] and probe["rtt"] is not None:
                previous = metric["latency"]
                metric["latency"] = round(
                    probe["rtt"] if previous is None else previous * 0.65 + probe["rtt"] * 0.35, 2
                )
                metric["last_seen"] = now
                metric["failures"] = 0
            else:
                metric["failures"] = metric.get("failures", 0) + 1
            results[key]["latency"] = metric["latency"]
            results[key]["failures"] = metric["failures"]
            results[key]["last_seen"] = metric["last_seen"]
            results[key]["loss"] = round(
                100.0 * sum(1 for sample in metric["samples"] if sample is None) / len(metric["samples"]), 1
            ) if metric["samples"] else 0.0
        # forget metrics for devices that disappeared
        live_keys = {key for key, _, _ in targets}
        for stale in [key for key in _metrics if key not in live_keys]:
            _metrics.pop(stale, None)
    return results


def get_alert_penalty(key, now=None):
    now = now or time.time()
    with _alert_lock:
        entry = _alert_penalties.get(key)
        if not entry:
            return 0.0
        expires_at, penalty, ttl = entry
        if expires_at < now:
            _alert_penalties.pop(key, None)
            return 0.0
        return penalty * max(0.0, min(1.0, (expires_at - now) / ttl))


def note_alert(key, severity):
    penalty = {"critical": 22.0, "high": 15.0, "medium": 8.0, "low": 3.0}.get(
        str(severity or "").lower(), 5.0
    )
    ttl = 120.0
    with _alert_lock:
        _alert_penalties[key] = (time.time() + ttl, penalty, ttl)


# ---------------------------------------------------------------------------
# normalisation
# ---------------------------------------------------------------------------

def _health_for(row, probe, neighbours, vuln_count, quarantined, now):
    ip = row.get("ip_address")
    status = str(row.get("status") or "unknown").lower()
    last_seen_ts = _as_ts(row.get("last_seen"))
    age = max(0.0, now - last_seen_ts) if last_seen_ts else None
    neighbour = neighbours.get(ip, "")

    probe_responded = probe.get("responded") if probe else None
    control_plane_alive = status == "online" and age is not None and age < 900
    strong_neighbour = neighbour in STRONG_NEIGHBOUR_STATES
    weak_neighbour = neighbour in WEAK_NEIGHBOUR_STATES

    alive = bool(probe_responded) or strong_neighbour or control_plane_alive or weak_neighbour
    if probe is not None and probe_responded is False and not (strong_neighbour or control_plane_alive):
        alive = False

    score = 100.0
    if not alive:
        score = 24.0
    else:
        score -= RISK_PENALTY.get(str(row.get("risk_level") or "low").lower(), 0)
        score -= min(18.0, vuln_count * 2.2)
        latency = (probe or {}).get("latency")
        if latency is not None:
            score -= min(22.0, max(0.0, (latency - 20.0) / 10.0))
        score -= float((probe or {}).get("loss") or 0.0) * 0.35
    score -= get_alert_penalty(_device_key(row.get("mac_address"), ip), now)
    if status == "offline":
        score = min(score, 30.0)
    score = round(_clamp(score), 1)

    if quarantined:
        state = "unidentified"
    elif score < 35 or (not alive and age is not None and age > 1800):
        state = "offline"
    elif score < 78:
        state = "degraded"
    else:
        state = "healthy"

    return {
        "score": score,
        "state": state,
        "latency_ms": (probe or {}).get("latency"),
        "loss_pct": (probe or {}).get("loss", 0.0),
        "reachable": bool(alive),
        "age_s": round(age, 0) if age is not None else None,
        "last_probe_at": _iso(now) if probe else None,
    }


def _gateway_for(ip, gateway_ip):
    prefix = ip.rsplit(".", 1)[0] if ip and ip.count(".") == 3 else None
    if not prefix:
        return "gw:unknown", "Unknown gateway"
    ip_addr = f"{prefix}.1"
    if gateway_ip and ip.startswith(gateway_ip.rsplit(".", 1)[0] + "."):
        ip_addr = gateway_ip
    return f"gw:{ip_addr}", f"Gateway {ip_addr}"


def build_snapshot(probe=True):
    now = time.time()
    rows = [row for row in load_devices() if not _is_ignored(row.get("ip_address"))]
    ports = load_ports([row["id"] for row in rows])
    cves = load_cves([row["id"] for row in rows])
    neighbours = fetch_neighbours() if probe else {}
    probes = probe_fleet(rows, ports) if probe else {}

    lan_prefix = None
    prefixes = Counter(row["ip_address"].rsplit(".", 1)[0] for row in rows if row.get("ip_address"))
    if prefixes:
        lan_prefix = prefixes.most_common(1)[0][0]
    gateway_ip = f"{lan_prefix}.1" if lan_prefix else None
    host_row = next((row for row in rows if row.get("ip_address") == gateway_ip), None)

    devices = []
    gateways = {}
    links = []
    category_groups = defaultdict(int)

    for row in rows:
        ip = row["ip_address"]
        key = _device_key(row.get("mac_address"), ip)
        category = _category_for(row)
        vuln_list = cves.get(row["id"], [])
        vuln_count = int(row.get("vuln_count") or len(vuln_list))
        first_seen_ts = _as_ts(row.get("first_seen"))
        vendor = (row.get("vendor") or "").strip()
        hostname = (row.get("hostname") or "").strip()
        confidence = int(row.get("os_confidence") or 0)
        quarantined = (
            (not vendor and confidence < 55 and not hostname)
            or (first_seen_ts is not None and now - first_seen_ts < QUARANTINE_SECONDS and not vendor)
        )
        health = _health_for(row, probes.get(key), neighbours, vuln_count, quarantined, now)
        gateway_id, gateway_name = _gateway_for(ip, gateway_ip)
        is_gateway = bool(gateway_ip and ip == gateway_ip) or (host_row is not None and row["id"] == host_row["id"])

        if is_gateway:
            category = "network"

        device = {
            "key": key,
            "device_id": row["id"],
            "name": hostname or ip,
            "hostname": hostname,
            "ip": ip,
            "mac": _normalize_mac(row.get("mac_address")) or "",
            "vendor": vendor or "Unknown",
            "os": " ".join(part for part in [row.get("os_name"), row.get("os_version")] if part) or "Unknown",
            "type": row.get("device_type") or "Unknown",
            "category": category,
            "category_label": CATEGORY_LABELS.get(category, "Other"),
            "risk": str(row.get("risk_level") or "low").lower(),
            "status": str(row.get("status") or "unknown").lower(),
            "gateway_id": gateway_id,
            "gateway_name": gateway_name,
            "link_kind": _link_kind(category),
            "health": health,
            "quarantined": quarantined,
            "is_gateway": is_gateway,
            "open_ports": int(row.get("open_ports") or 0),
            "ports": ports.get(row["id"], []),
            "vuln_count": vuln_count,
            "top_cves": vuln_list[:3],
            "first_seen": _iso(first_seen_ts) if first_seen_ts else None,
            "last_seen": _iso(_as_ts(row.get("last_seen"))) if row.get("last_seen") else None,
            "battery": None,
        }
        devices.append(device)

        gw = gateways.setdefault(gateway_id, {
            "id": gateway_id,
            "name": gateway_name,
            "ip": gateway_ip if gateway_id == f"gw:{gateway_ip}" else gateway_id.split(":", 1)[1],
            "kind": "gateway",
            "device_count": 0,
            "healthy": 0,
            "degraded": 0,
            "offline": 0,
            "quarantined": 0,
            "latency_ms": None,
            "health": 100.0,
            "state": "healthy",
            "last_seen": None,
        })
        gw["device_count"] += 1
        if quarantine_guard := device["quarantined"]:
            gw["quarantined"] += 1
        elif health["state"] == "healthy":
            gw["healthy"] += 1
        elif health["state"] == "degraded":
            gw["degraded"] += 1
        else:
            gw["offline"] += 1
        if device["is_gateway"] and health.get("latency_ms") is not None:
            gw["latency_ms"] = health["latency_ms"]
        if health.get("latency_ms") is not None:
            gw["last_seen"] = health["last_probe_at"]

        category_groups[(gateway_id, category)] += 1
        links.append({
            "id": f"link:{key}",
            "source": key,
            "target": gateway_id,
            "kind": device["link_kind"],
            "device_ip": ip,
            "quality": "good" if health["state"] == "healthy" else health["state"],
        })

    for gw in gateways.values():
        checked = max(1, gw["device_count"] - gw["quarantined"])
        gw["health"] = round(100.0 * (gw["healthy"] + gw["degraded"] * 0.55) / checked, 1)
        gw["health"] = _clamp(gw["health"])
        if gw["offline"] >= max(2, checked):
            gw["state"] = "offline"
        elif gw["degraded"] + gw["offline"] > checked * 0.25:
            gw["state"] = "degraded"
        else:
            gw["state"] = "healthy"

    clusters = []
    for gw in gateways.values():
        cluster_id = f"cluster:{gw['id']}"
        clusters.append({
            "id": cluster_id,
            "label": gw["name"],
            "kind": "gateway",
            "parent": None,
            "gateway_id": gw["id"],
            "device_count": gw["device_count"],
            "state": gw["state"],
            "health": gw["health"],
        })
        for (gateway_id, category), count in sorted(category_groups.items()):
            if gateway_id != gw["id"]:
                continue
            clusters.append({
                "id": f"{cluster_id}:{category}",
                "label": CATEGORY_LABELS.get(category, "Other"),
                "kind": "role",
                "parent": cluster_id,
                "gateway_id": gw["id"],
                "category": category,
                "device_count": count,
                "state": "healthy",
                "health": 100.0,
            })

    incidents = []
    by_ip = {device["ip"]: device["key"] for device in devices}
    for row in load_incidents():
        affected = row.get("affected_devices") or []
        if isinstance(affected, str):
            try:
                affected = json.loads(affected)
            except Exception:
                affected = []
        if isinstance(affected, dict):
            affected = [affected]
        keys = []
        for item in affected if isinstance(affected, list) else []:
            if not isinstance(item, dict):
                continue
            key = by_ip.get(item.get("ip_address"))
            if key:
                keys.append(key)
        incident_devices = [device for device in devices if device["key"] in keys]
        incidents.append({
            "id": f"incident:{row['incident_id']}",
            "incident_id": row["incident_id"],
            "title": row.get("title"),
            "description": (row.get("description") or "")[:240],
            "severity": str(row.get("severity") or "low").lower(),
            "status": str(row.get("status") or "open").lower(),
            "created_at": _iso(_as_ts(row.get("created_at"))) if row.get("created_at") else None,
            "device_keys": keys,
            "gateway_ids": sorted({device["gateway_id"] for device in incident_devices}),
            "blast_radius": len(keys),
        })

    summary = {
        "total": len(devices),
        "healthy": sum(1 for d in devices if d["health"]["state"] == "healthy"),
        "degraded": sum(1 for d in devices if d["health"]["state"] == "degraded"),
        "offline": sum(1 for d in devices if d["health"]["state"] == "offline"),
        "unidentified": sum(1 for d in devices if d["health"]["state"] == "unidentified"),
        "quarantined": sum(1 for d in devices if d["quarantined"]),
        "active_incidents": len(incidents),
        "gateways": len(gateways),
    }
    latencies = [d["health"]["latency_ms"] for d in devices if d["health"].get("latency_ms") is not None]
    summary["avg_latency_ms"] = round(sum(latencies) / len(latencies), 1) if latencies else None

    return {
        "generated_at": _iso(now),
        "seq": 0,
        "source": "fleet-collector",
        "devices": devices,
        "gateways": list(gateways.values()),
        "links": links,
        "clusters": clusters,
        "incidents": incidents,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# hub
# ---------------------------------------------------------------------------

class FleetHub:
    def __init__(self):
        self.worker_id = WORKER_ID
        self._lock = threading.Lock()
        self._prev = None
        self._prev_incidents = {}
        self._seq = 0
        self._gateway_down = {}
        self._thread = None
        self._bus_thread = None
        self._stop = threading.Event()
        self._last_tick = None
        self._last_error = None
        self._leader = False
        self._events = deque(maxlen=300)
        self._history = defaultdict(lambda: deque(maxlen=40))

    # -- leadership ---------------------------------------------------------
    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._leadership_loop, name="fleet-leader", daemon=True)
        self._thread.start()

    def _leadership_loop(self):
        while not self._stop.is_set():
            try:
                acquired = _redis.set(LOCK_KEY, self.worker_id, nx=True, ex=LOCK_TTL)
                if acquired:
                    logger.info("fleet: worker %s is the collector", self.worker_id)
                    self._leader = True
                    self._run_collector()
                    self._leader = False
                else:
                    holder = _redis.get(LOCK_KEY)
                    if holder == self.worker_id:
                        self._leader = True
                        self._run_collector()
                        self._leader = False
            except Exception as exc:
                self._last_error = str(exc)
                logger.warning("fleet: leadership error: %s", exc)
            self._stop.wait(5)

    def _refresh_lock(self):
        holder = _redis.get(LOCK_KEY)
        if holder == self.worker_id:
            _redis.expire(LOCK_KEY, LOCK_TTL)
            return True
        return False

    # -- collector ----------------------------------------------------------
    def _run_collector(self):
        if not self._bus_thread or not self._bus_thread.is_alive():
            self._bus_thread = threading.Thread(target=self._bus_loop, name="fleet-bus", daemon=True)
            self._bus_thread.start()
        while not self._stop.is_set() and self._refresh_lock():
            started = time.time()
            try:
                snapshot = build_snapshot(probe=True)
                self._seq += 1
                snapshot["seq"] = self._seq
                snapshot["collected_at"] = _iso(started)
                snapshot["collector"] = self.worker_id
                with self._lock:
                    previous = self._prev
                    self._prev = snapshot
                self._publish_snapshot(snapshot)
                self._record_series(snapshot)
                if previous:
                    self._diff(previous, snapshot)
                self._last_tick = time.time()
                self._last_error = None
            except Exception as exc:
                self._last_error = str(exc)
                logger.exception("fleet: collection failed")
            elapsed = time.time() - started
            self._stop.wait(max(2.0, PROBE_TICK - elapsed))

    def _publish_snapshot(self, snapshot):
        payload = json.dumps(snapshot, default=str)
        try:
            _redis.set(SNAPSHOT_KEY, payload, ex=max(120, PROBE_TICK * 6))
            # Authoritative state convergence for every connected view.
            sync = json.dumps({
                "type": "fleet.sync",
                "ts": _iso(),
                "seq": snapshot.get("seq"),
                "fleet": snapshot,
            }, default=str)
            _redis.publish(CHANNEL, sync)
        except Exception as exc:
            logger.warning("fleet: snapshot cache failed: %s", exc)

    def _record_series(self, snapshot):
        pipe = _redis.pipeline()
        for device in snapshot["devices"]:
            latency = device["health"].get("latency_ms")
            if latency is None:
                continue
            key = f"fleet:series:{device['key']}"
            pipe.lpush(key, latency)
            pipe.ltrim(key, 0, 39)
            pipe.expire(key, 3600)
        try:
            pipe.execute()
        except Exception as exc:
            logger.debug("fleet: series write failed: %s", exc)

    # -- events -------------------------------------------------------------
    def _emit(self, event_type, payload=None, device=None, detail=None):
        self._seq += 1
        event = {
            "type": event_type,
            "seq": self._seq,
            "ts": _iso(),
            "detail": detail or "",
        }
        if payload:
            event.update(payload)
        if device:
            event["device"] = device
            event["device_key"] = device.get("key")
        try:
            _redis.publish(CHANNEL, json.dumps(event, default=str))
            _redis.lpush(RECENT_KEY, json.dumps(event, default=str))
            _redis.ltrim(RECENT_KEY, 0, 99)
            if event.get("device_key"):
                log_key = f"fleet:log:{event['device_key']}"
                _redis.lpush(log_key, json.dumps(event, default=str))
                _redis.ltrim(log_key, 0, 59)
                _redis.expire(log_key, 86400)
        except Exception as exc:
            logger.debug("fleet: publish failed: %s", exc)
        self._events.append(event)
        return event

    def _diff(self, previous, current):
        old_devices = {d["key"]: d for d in previous["devices"]}
        new_devices = {d["key"]: d for d in current["devices"]}

        for key, device in new_devices.items():
            old = old_devices.get(key)
            if not old:
                self._emit(
                    "device.discovered",
                    {"device": device, "quarantined": device["quarantined"]},
                    device,
                    detail=f"New device {device['ip']} discovered on {device['gateway_name']}",
                )
                self._remember(key, "discovered", device.get("gateway_id"))
                continue

            if old.get("gateway_id") != device.get("gateway_id"):
                self._emit(
                    "device.roamed",
                    {
                        "device": device,
                        "from_gateway": old.get("gateway_id"),
                        "from_gateway_name": old.get("gateway_name"),
                        "to_gateway": device.get("gateway_id"),
                        "to_gateway_name": device.get("gateway_name"),
                    },
                    device,
                    detail=f"Roamed {old.get('gateway_name')} \u2192 {device.get('gateway_name')}",
                )
                self._remember(key, "roamed", device.get("gateway_id"))

            old_state = old.get("health", {}).get("state")
            new_state = device.get("health", {}).get("state")
            if old_state != new_state:
                if new_state in ("degraded", "offline"):
                    self._emit(
                        "health.degraded",
                        {"previous_state": old_state, "state": new_state},
                        device,
                        detail=f"{device['name']} {old_state} \u2192 {new_state}",
                    )
                elif old_state in ("degraded", "offline") and new_state == "healthy":
                    self._emit(
                        "health.recovered",
                        {"previous_state": old_state, "state": new_state},
                        device,
                        detail=f"{device['name']} recovered",
                    )
                if old.get("quarantined") and not device.get("quarantined"):
                    self._emit("device.identified", {"device": device}, device,
                               detail=f"{device['name']} fingerprinted and released from quarantine")

            if old.get("quarantined") and not device.get("quarantined"):
                self._remember(key, "identified", device.get("gateway_id"))

        for key, old in old_devices.items():
            if key not in new_devices:
                self._emit("device.lost", {"previous": old, "device_key": key},
                           old, detail=f"{old.get('ip')} left the fleet")

        # reachable batch -> hex-grid heartbeat pulses
        reported = [
            d["key"] for d in current["devices"]
            if d["health"].get("reachable") and d["health"].get("state") != "offline"
        ]
        self._emit("telemetry.batch", {
            "reported": reported,
            "metrics": [
                {
                    "key": d["key"],
                    "latency_ms": d["health"].get("latency_ms"),
                    "loss_pct": d["health"].get("loss_pct"),
                    "score": d["health"].get("score"),
                    "state": d["health"].get("state"),
                }
                for d in current["devices"]
            ],
        }, detail=f"{len(reported)} devices reported telemetry")

        # gateway outage detection
        for gateway in current["gateways"]:
            gid = gateway["id"]
            down = gateway["state"] == "offline"
            if down and gid not in self._gateway_down:
                self._gateway_down[gid] = time.time()
            elif down and gid in self._gateway_down:
                if time.time() - self._gateway_down[gid] > PROBE_TICK * 1.5:
                    self._emit("gateway.outage", {
                        "gateway": gateway,
                        "affected": [d["key"] for d in current["devices"] if d["gateway_id"] == gid],
                    }, detail=f"{gateway['name']} outage \u2014 {gateway['device_count']} devices affected")
                    self._gateway_down[gid] = time.time() + 3600  # re-alert window
            elif not down and gid in self._gateway_down:
                self._gateway_down.pop(gid, None)
                if gateway["device_count"]:
                    self._emit("gateway.online", {"gateway": gateway}, detail=f"{gateway['name']} back online")

        # incidents
        current_incidents = {incident["id"]: incident for incident in current["incidents"]}
        for incident_id, incident in current_incidents.items():
            if incident_id not in self._prev_incidents:
                self._emit("incident.opened", {"incident": incident},
                           detail=f"{incident['severity'].upper()}: {incident['title']}")
        for incident_id, incident in self._prev_incidents.items():
            if incident_id not in current_incidents:
                self._emit("incident.closed", {"incident": incident},
                           detail=f"Incident closed: {incident['title']}")
        self._prev_incidents = current_incidents

    def _remember(self, key, event, gateway_id):
        with self._lock:
            self._history[key].append({"ts": _iso(), "event": event, "gateway_id": gateway_id})
        try:
            _redis.lpush(f"fleet:conn:{key}", json.dumps({
                "ts": _iso(), "event": event, "gateway_id": gateway_id
            }))
            _redis.ltrim(f"fleet:conn:{key}", 0, 29)
            _redis.expire(f"fleet:conn:{key}", 86400)
        except Exception:
            pass

    # -- inbound monitor buses ---------------------------------------------
    def _bus_loop(self):
        """Translate discovery/monitoring bus messages into fleet events."""
        try:
            pubsub = _redis.pubsub(ignore_subscribe_messages=True)
            pubsub.subscribe("scan_updates", "security_events", "traffic_events", "alert_updates")
        except Exception as exc:
            logger.warning("fleet: bus subscribe failed: %s", exc)
            return

        while not self._stop.is_set():
            try:
                message = pubsub.get_message(timeout=2)
            except Exception:
                time.sleep(2)
                continue
            if not message:
                continue
            try:
                payload = json.loads(message.get("data") or "{}")
            except Exception:
                continue
            channel = message.get("channel")
            if channel == "scan_updates":
                status = payload.get("status")
                if status in ("completed", "failed", "started", "running"):
                    self._emit(f"scan.{status}", {
                        "scan_id": payload.get("scan_id"),
                        "devices_found": payload.get("devices_found"),
                        "vulnerabilities_found": payload.get("vulnerabilities_found"),
                    }, detail=f"Discovery scan {status}")
            elif channel in ("security_events", "traffic_events", "alert_updates"):
                event_type = payload.get("event_type") or payload.get("type")
                ips = [payload.get("src_ip"), payload.get("dest_ip")]
                with self._lock:
                    snapshot = self._prev
                if not snapshot:
                    continue
                by_ip = {device["ip"]: device for device in snapshot["devices"]}
                for ip in ips:
                    device = by_ip.get(ip)
                    if not device:
                        continue
                    severity = payload.get("severity") or "medium"
                    note_alert(device["key"], severity)
                    self._emit("device.alert", {
                        "severity": severity,
                        "alert": payload.get("signature") or payload.get("title") or event_type,
                        "channel": channel,
                    }, device, detail=f"{severity} alert on {device['name']}")

    # -- public API ---------------------------------------------------------
    def snapshot(self):
        cached = _read_cached_snapshot()
        if cached:
            return cached
        snapshot = build_snapshot(probe=False)
        snapshot["collector"] = "on-demand"
        return snapshot

    def detail(self, key):
        snapshot = self.snapshot()
        device = next((d for d in snapshot["devices"] if d["key"] == key), None)
        if not device:
            return None
        try:
            series = [float(value) for value in _redis.lrange(f"fleet:series:{key}", 0, 39)]
        except Exception:
            series = []
        try:
            events = [json.loads(item) for item in _redis.lrange(f"fleet:log:{key}", 0, 29)]
        except Exception:
            events = []
        try:
            history = [json.loads(item) for item in _redis.lrange(f"fleet:conn:{key}", 0, 19)]
        except Exception:
            history = []
        if not events:
            events = [event for event in self._events if event.get("device_key") == key][-30:][::-1]
        if not history:
            history = list(self._history.get(key, []))[::-1]
        incidents = [
            incident for incident in snapshot["incidents"] if key in incident.get("device_keys", [])
        ]
        return {
            "device": device,
            "latency_series": series[::-1],
            "events": events,
            "connection_history": history,
            "incidents": incidents,
            "gateway": next((g for g in snapshot["gateways"] if g["id"] == device["gateway_id"]), None),
            "generated_at": snapshot.get("generated_at"),
        }

    def diagnostics(self):
        return {
            "worker": self.worker_id,
            "leader": bool(_redis.get(LOCK_KEY) == self.worker_id),
            "last_tick": _iso(self._last_tick) if self._last_tick else None,
            "seconds_since_tick": round(time.time() - self._last_tick, 1) if self._last_tick else None,
            "last_error": self._last_error,
            "tick_seconds": PROBE_TICK,
            "events": len(self._events),
        }


def _read_cached_snapshot():
    try:
        raw = _redis.get(SNAPSHOT_KEY)
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    return None


_hub = None
_hub_lock = threading.Lock()


def ensure_collector():
    global _hub
    if _hub is not None:
        return _hub
    with _hub_lock:
        if _hub is None:
            _hub = FleetHub()
            _hub.start()
    return _hub


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

def register_fleet_routes(app):
    from flask import Response, jsonify, request

    @app.route("/api/fleet/snapshot", methods=["GET"])
    def fleet_snapshot():
        ensure_collector()
        try:
            return jsonify(_read_cached_snapshot() or _hub.snapshot())
        except Exception as exc:
            logger.exception("fleet snapshot failed")
            return jsonify({"status": "error", "message": str(exc)}), 500

    @app.route("/api/fleet/stream", methods=["GET"])
    def fleet_stream():
        ensure_collector()
        snapshot = _read_cached_snapshot() or _hub.snapshot()

        def generate():
            yield "retry: 3000\n\n"
            yield f"data: {json.dumps({'type': 'snapshot', 'ts': _iso(), 'fleet': snapshot}, default=str)}\n\n"
            client = _redis.pubsub(ignore_subscribe_messages=True)
            client.subscribe(CHANNEL)
            try:
                while True:
                    message = client.get_message(timeout=15)
                    if message and message.get("type") == "message":
                        yield f"data: {message['data']}\n\n"
                    else:
                        yield ": keepalive\n\n"
            except GeneratorExit:
                return
            except Exception as exc:
                logger.warning("fleet stream error: %s", exc)
                yield f"data: {json.dumps({'type': 'stream.error', 'message': str(exc)})}\n\n"
            finally:
                try:
                    client.close()
                except Exception:
                    pass

        return Response(generate(), mimetype="text/event-stream", headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        })

    @app.route("/api/fleet/device/<path:key>", methods=["GET"])
    def fleet_device(key):
        ensure_collector()
        detail = _hub.detail(key)
        if not detail:
            return jsonify({"status": "error", "message": "device not found"}), 404
        return jsonify(detail)

    @app.route("/api/fleet/events", methods=["GET"])
    def fleet_events():
        ensure_collector()
        limit = min(100, max(1, int(request.args.get("limit", 40))))
        try:
            events = [json.loads(item) for item in _redis.lrange(RECENT_KEY, 0, limit - 1)]
        except Exception:
            events = []
        return jsonify({"events": events})

    @app.route("/api/fleet/health", methods=["GET"])
    def fleet_health():
        ensure_collector()
        return jsonify(_hub.diagnostics())
