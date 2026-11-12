from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
import logging
from datetime import datetime, timedelta, timezone
from collections import Counter, defaultdict
import json
import pickle
from pathlib import Path
import math
import re
import unicodedata
import ast

try:
    from sklearn.svm import OneClassSVM
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TRAFFIC_SERVICE = os.getenv("TRAFFIC_SERVICE_URL", "http://traffic-analyzer:5002")
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
CORRELATION_SERVICE = os.getenv("CORRELATION_SERVICE_URL", "http://correlation-engine:5003")

LLM_ENABLED = os.getenv("LLM_ENABLED", "1").lower() in ("1", "true", "yes")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama").lower()
LLM_MODEL = os.getenv("LLM_MODEL", "gemma4:e4b")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://host.docker.internal:11434")
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT_SECONDS", "90"))
LLM_FALLBACK_MODELS = [
    item.strip()
    for item in os.getenv("LLM_FALLBACK_MODELS", "llama3.1:latest").split(",")
    if item.strip()
]

DEFAULT_WINDOW_HOURS = int(os.getenv("ANALYSIS_DEFAULT_WINDOW_HOURS", "24"))
MAX_EVENTS = int(os.getenv("ANALYSIS_MAX_EVENTS", "3000"))
SEGMENT_GAP_SECONDS = int(os.getenv("ANALYSIS_SEGMENT_GAP_SECONDS", "180"))

MODEL_DIR = Path(os.getenv("AGENT_MODEL_DIR", "/tmp/log-agent"))
MODEL_DIR.mkdir(parents=True, exist_ok=True)
MODEL_PATH = MODEL_DIR / "oneclass_svm.pkl"

FEATURE_NAMES = [
    "events_count",
    "duration_seconds",
    "bytes_total",
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "unique_event_types",
]

last_report = None
last_agent_report = None
last_agent_train = {
    "trained": False,
    "trained_at": None,
    "samples": 0,
    "sklearn_available": SKLEARN_AVAILABLE,
    "model_path": str(MODEL_PATH),
}


ATTACK_TECHNIQUE_PATTERNS = [
    {"id": "T1595", "name": "Active Scanning", "keywords": ["scan", "port scan", "ping sweep", "recon"]},
    {"id": "T1110", "name": "Brute Force", "keywords": ["brute force", "failed login", "login attempt", "credential"]},
    {"id": "T1059.001", "name": "PowerShell", "keywords": ["powershell", "-enc", "encodedcommand"]},
    {"id": "T1071.004", "name": "DNS C2/Tunneling", "keywords": ["dns tunnel", "dns tunneling", "suspicious dns"]},
    {"id": "T1021.002", "name": "SMB/Remote Services", "keywords": ["smb", "rpc", "lateral movement"]},
    {"id": "T1048", "name": "Exfiltration", "keywords": ["large outbound", "upload", "exfiltration", "ftp upload"]},
    {"id": "T1105", "name": "Ingress Tool Transfer", "keywords": ["wget", "curl", "download tool", "suspicious user agent"]},
    {"id": "T1190", "name": "Exploit Public-Facing Application", "keywords": ["sql injection", "xss", "directory traversal"]},
]


def parse_timestamp(value):
    if not value:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def normalize_alert(alert):
    return {
        "event_type": "alert",
        "timestamp": alert.get("timestamp"),
        "src_ip": alert.get("src_ip"),
        "dest_ip": alert.get("dest_ip"),
        "src_port": alert.get("src_port"),
        "dest_port": alert.get("dest_port"),
        "protocol": (alert.get("protocol") or "").lower(),
        "signature": alert.get("signature") or "security alert",
        "severity": (alert.get("severity") or "low").lower(),
        "status": alert.get("status") or "open",
        "metadata": {"alert_id": alert.get("alert_id")},
    }


def normalize_flow(flow):
    bytes_total = int(flow.get("bytes_to_server") or 0) + int(flow.get("bytes_to_client") or 0)
    return {
        "event_type": "flow",
        "timestamp": flow.get("start_time") or flow.get("end_time"),
        "src_ip": flow.get("src_ip"),
        "dest_ip": flow.get("dest_ip"),
        "src_port": flow.get("src_port"),
        "dest_port": flow.get("dest_port"),
        "protocol": (flow.get("protocol") or "").lower(),
        "signature": f"flow:{flow.get('state') or 'unknown'}",
        "severity": "low",
        "status": flow.get("state") or "unknown",
        "metadata": {
            "bytes_total": bytes_total,
            "packets_total": int(flow.get("packets_to_server") or 0) + int(flow.get("packets_to_client") or 0),
            "flow_id": flow.get("flow_id"),
        },
    }


def elastic_available():
    try:
        response = requests.get(f"{ELASTICSEARCH_URL}", timeout=3)
        return response.ok
    except Exception:
        return False


def elastic_bulk_index(events):
    if not events or not elastic_available():
        return 0
    lines = []
    for event in events:
        ts = parse_timestamp(event.get("timestamp"))
        index_name = f"security-logs-{ts.strftime('%Y.%m.%d')}"
        lines.append(json.dumps({"index": {"_index": index_name}}))
        lines.append(json.dumps(event, default=str))
    payload = "\n".join(lines) + "\n"
    try:
        response = requests.post(
            f"{ELASTICSEARCH_URL}/_bulk",
            data=payload,
            headers={"Content-Type": "application/x-ndjson"},
            timeout=10,
        )
        if response.ok:
            return len(events)
    except Exception as e:
        logger.warning(f"Elastic bulk index failed: {str(e)}")
    return 0


def elastic_fetch_events(window_hours, limit):
    if not elastic_available():
        return []
    gte = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat()
    query = {
        "size": min(limit, MAX_EVENTS),
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {"bool": {"filter": [{"range": {"timestamp": {"gte": gte}}}]}},
    }
    try:
        response = requests.post(f"{ELASTICSEARCH_URL}/security-logs-*/_search", json=query, timeout=10)
        if not response.ok:
            return []
        hits = response.json().get("hits", {}).get("hits", [])
        return [h.get("_source", {}) for h in hits]
    except Exception as e:
        logger.warning(f"Elastic fetch failed: {str(e)}")
        return []


def fetch_live_logs(limit):
    alerts = []
    flows = []
    try:
        alert_response = requests.get(f"{TRAFFIC_SERVICE}/alerts", timeout=8)
        if alert_response.ok:
            alerts = alert_response.json().get("alerts", [])[:limit]
    except Exception as e:
        logger.warning(f"Fetch alerts failed: {str(e)}")

    try:
        flow_response = requests.get(f"{TRAFFIC_SERVICE}/traffic/flows", timeout=8)
        if flow_response.ok:
            flows = flow_response.json().get("flows", [])[:limit]
    except Exception as e:
        logger.warning(f"Fetch flows failed: {str(e)}")

    events = [normalize_alert(a) for a in alerts] + [normalize_flow(f) for f in flows]
    events.sort(key=lambda ev: parse_timestamp(ev.get("timestamp")))
    return events


def segment_actions(events):
    if not events:
        return []

    segments = []
    current = None
    for event in events:
        ts = parse_timestamp(event.get("timestamp"))
        key = (
            event.get("src_ip") or "-",
            event.get("dest_ip") or "-",
            event.get("protocol") or "-",
            event.get("signature") or "-",
        )

        if current is None:
            current = {"key": key, "start": ts, "end": ts, "events": [event]}
            continue

        gap = (ts - current["end"]).total_seconds()
        if key == current["key"] and gap <= SEGMENT_GAP_SECONDS:
            current["events"].append(event)
            current["end"] = ts
        else:
            segments.append(current)
            current = {"key": key, "start": ts, "end": ts, "events": [event]}

    if current:
        segments.append(current)

    actions = []
    for idx, seg in enumerate(segments, start=1):
        group = seg["events"]
        sev_counter = Counter((e.get("severity") or "low").lower() for e in group)
        bytes_total = sum(int((e.get("metadata") or {}).get("bytes_total") or 0) for e in group)
        actions.append({
            "action_id": f"A{idx:03d}",
            "start_time": seg["start"].isoformat(),
            "end_time": seg["end"].isoformat(),
            "duration_seconds": int((seg["end"] - seg["start"]).total_seconds()),
            "src_ip": group[0].get("src_ip"),
            "dest_ip": group[0].get("dest_ip"),
            "protocol": group[0].get("protocol"),
            "signature": group[0].get("signature") or "unknown",
            "events_count": len(group),
            "severity_counts": dict(sev_counter),
            "bytes_total": bytes_total,
            "event_types": sorted(list(set(e.get("event_type") for e in group if e.get("event_type")))),
        })
    return actions


def map_attack_techniques(actions):
    mapped = []
    for action in actions:
        text = f"{action.get('signature', '')} {action.get('protocol', '')}".lower()
        hits = []
        for item in ATTACK_TECHNIQUE_PATTERNS:
            if any(keyword in text for keyword in item["keywords"]):
                hits.append({"technique_id": item["id"], "name": item["name"], "confidence": 0.82})
        if action.get("events_count", 0) >= 20 and "scan" in text:
            hits.append({"technique_id": "T1595", "name": "Active Scanning", "confidence": 0.9})
        mapped.append({"action_id": action["action_id"], "techniques": hits})

    aggregate = defaultdict(lambda: {"name": "", "count": 0, "confidence_sum": 0.0})
    for row in mapped:
        for tech in row["techniques"]:
            tid = tech["technique_id"]
            aggregate[tid]["name"] = tech["name"]
            aggregate[tid]["count"] += 1
            aggregate[tid]["confidence_sum"] += tech["confidence"]

    top = []
    for tid, data in aggregate.items():
        top.append({
            "technique_id": tid,
            "name": data["name"],
            "count": data["count"],
            "confidence": round(data["confidence_sum"] / max(data["count"], 1), 2),
        })
    top.sort(key=lambda x: (-x["count"], -x["confidence"]))
    return mapped, top[:10]


def action_feature_vector(action):
    sev = action.get("severity_counts", {})
    return [
        float(action.get("events_count", 0)),
        float(action.get("duration_seconds", 0)),
        float(action.get("bytes_total", 0)),
        float(sev.get("critical", 0)),
        float(sev.get("high", 0)),
        float(sev.get("medium", 0)),
        float(sev.get("low", 0)),
        float(len(action.get("event_types", []))),
    ]


def save_model_bundle(bundle):
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(bundle, f)


def load_model_bundle():
    if not MODEL_PATH.exists():
        return None
    try:
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    except Exception as e:
        logger.warning(f"Failed loading model bundle: {str(e)}")
        return None


def train_svm(actions):
    global last_agent_train
    if not SKLEARN_AVAILABLE:
        last_agent_train = {
            **last_agent_train,
            "trained": False,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "samples": len(actions),
            "message": "scikit-learn unavailable",
        }
        return last_agent_train

    vectors = [action_feature_vector(a) for a in actions]
    min_samples = 20
    if len(vectors) < min_samples:
        last_agent_train = {
            **last_agent_train,
            "trained": False,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "samples": len(vectors),
            "message": f"not enough samples for training (need >= {min_samples})",
        }
        return last_agent_train

    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(vectors)
    model = OneClassSVM(kernel="rbf", gamma="scale", nu=0.08)
    model.fit(x_scaled)

    bundle = {
        "scaler": scaler,
        "model": model,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "features": FEATURE_NAMES,
        "samples": len(vectors),
        "engine": "OneClassSVM",
    }
    save_model_bundle(bundle)
    last_agent_train = {
        "trained": True,
        "trained_at": bundle["trained_at"],
        "samples": len(vectors),
        "engine": bundle["engine"],
        "model_path": str(MODEL_PATH),
        "sklearn_available": SKLEARN_AVAILABLE,
    }
    return last_agent_train


def detect_with_svm(actions):
    bundle = load_model_bundle()
    if not bundle or not SKLEARN_AVAILABLE:
        # Heuristic fallback when model is absent
        anomalies = 0
        for action in actions:
            sev = action.get("severity_counts", {})
            flag = (
                sev.get("critical", 0) > 0 or
                sev.get("high", 0) > 0 or
                action.get("events_count", 0) > 30 or
                action.get("bytes_total", 0) > 5_000_000
            )
            action["ml_engine"] = "heuristic"
            action["ml_is_anomaly"] = flag
            action["ml_score"] = 0.9 if flag else 0.2
            if flag:
                anomalies += 1
        return {
            "engine": "heuristic",
            "model_loaded": False,
            "anomaly_actions": anomalies,
            "total_actions": len(actions),
        }

    scaler = bundle["scaler"]
    model = bundle["model"]
    vectors = [action_feature_vector(a) for a in actions]
    if not vectors:
        return {"engine": "OneClassSVM", "model_loaded": True, "anomaly_actions": 0, "total_actions": 0}

    x_scaled = scaler.transform(vectors)
    preds = model.predict(x_scaled)  # -1 anomaly, 1 normal
    decisions = model.decision_function(x_scaled)

    anomalies = 0
    for action, pred, decision in zip(actions, preds, decisions):
        # Convert decision score to anomaly confidence
        # lower decision => more anomalous
        score = 1.0 / (1.0 + math.exp(float(decision) * 3.0))
        is_anomaly = int(pred) == -1
        action["ml_engine"] = "OneClassSVM"
        action["ml_is_anomaly"] = is_anomaly
        action["ml_score"] = round(score, 3)
        if is_anomaly:
            anomalies += 1

    return {
        "engine": "OneClassSVM",
        "model_loaded": True,
        "anomaly_actions": anomalies,
        "total_actions": len(actions),
        "trained_at": bundle.get("trained_at"),
        "samples": bundle.get("samples", 0),
    }


def infer_cognitive_traits(actions):
    if not actions:
        return {
            "tool_switching": "low",
            "protocol_transitions": "low",
            "goal_persistence": "low",
            "risk_tolerance": "low",
            "notes": "Insufficient activity to infer behavior.",
        }

    signatures = [a.get("signature") or "-" for a in actions]
    protocols = [a.get("protocol") or "-" for a in actions]
    switches = sum(1 for i in range(1, len(signatures)) if signatures[i] != signatures[i - 1])
    proto_switches = sum(1 for i in range(1, len(protocols)) if protocols[i] != protocols[i - 1])

    high_events = sum((a.get("severity_counts", {}).get("high", 0) + a.get("severity_counts", {}).get("critical", 0)) for a in actions)
    repeated_targets = Counter(a.get("dest_ip") for a in actions if a.get("dest_ip"))
    persistence = max(repeated_targets.values()) if repeated_targets else 0

    def level(v, low, high):
        if v >= high:
            return "high"
        if v >= low:
            return "medium"
        return "low"

    return {
        "tool_switching": level(switches, 3, 8),
        "protocol_transitions": level(proto_switches, 2, 6),
        "goal_persistence": level(persistence, 3, 6),
        "risk_tolerance": level(high_events, 3, 10),
        "notes": "Heuristic cognitive indicators inferred from action sequence.",
    }


def extract_json_object(text):
    if not text:
        return None
    text = text.strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        snippet = text[start:end + 1]
        try:
            return json.loads(snippet)
        except Exception:
            return None
    return None


def normalize_loose_text(value):
    text = unicodedata.normalize("NFKD", str(value or ""))
    return text.encode("ascii", "ignore").decode("ascii").lower().strip()


def coerce_confidence(value, default=0.6):
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return max(0.0, min(float(value), 1.0))

    text = str(value).strip()
    if not text:
        return default

    normalized = normalize_loose_text(text)
    if normalized.endswith("%"):
        try:
            return max(0.0, min(float(normalized[:-1]) / 100.0, 1.0))
        except Exception:
            return default

    confidence_aliases = {
        "low": 0.35,
        "medium": 0.6,
        "moderate": 0.6,
        "med": 0.6,
        "high": 0.85,
        "very high": 0.95,
    }
    if normalized in confidence_aliases:
        return confidence_aliases[normalized]

    try:
        numeric = float(normalized)
        if numeric > 1.0:
            numeric = numeric / 100.0
        return max(0.0, min(numeric, 1.0))
    except Exception:
        return default


def coerce_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    normalized = normalize_loose_text(value)
    if normalized in ("true", "yes", "1", "oui"):
        return True
    if normalized in ("false", "no", "0", "non"):
        return False
    return default


def coerce_string_list(value, default=None):
    if default is None:
        default = []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return list(default)
        try:
            candidate = json.loads(stripped)
            if isinstance(candidate, list):
                return [str(item).strip() for item in candidate if str(item).strip()]
        except Exception:
            pass
        parts = [part.strip(" -\t\r\n") for part in re.split(r"[\r\n,;]+", stripped)]
        return [part for part in parts if part]
    return list(default)


def coerce_incident_payload(value, default):
    candidate = value if isinstance(value, dict) else {}
    severity = normalize_loose_text(candidate.get("severity", default.get("severity", "medium")))
    if severity not in {"low", "medium", "high", "critical"}:
        severity = default.get("severity", "medium")
    return {
        "should_create": coerce_bool(candidate.get("should_create"), default.get("should_create", False)),
        "severity": severity,
        "title": str(candidate.get("title") or default.get("title") or "AI Agent Incident").strip(),
        "description": str(candidate.get("description") or default.get("description") or "Automated incident from AI agent").strip(),
    }


def coerce_summary_text(value, default):
    if isinstance(value, dict):
        anomalies = value.get("anomalies_detected", value.get("anomaly_actions"))
        total_actions = value.get("total_actions", value.get("actions_detected"))
        engine = value.get("engine")
        parts = []
        if anomalies is not None and total_actions is not None:
            parts.append(f"Detected {anomalies} anomalous actions in {total_actions} actions.")
        elif anomalies is not None:
            parts.append(f"Detected {anomalies} anomalous actions.")
        if engine:
            parts.append(f"Engine: {engine}.")
        return " ".join(parts).strip() or default

    if isinstance(value, list):
        joined = " ".join(str(item).strip() for item in value if str(item).strip())
        return joined or default

    text = str(value or "").strip()
    if not text:
        return default

    parsed = extract_json_object(text)
    if not parsed and text.startswith("{") and text.endswith("}"):
        try:
            parsed = ast.literal_eval(text)
        except Exception:
            parsed = None
    if isinstance(parsed, dict):
        return coerce_summary_text(parsed, default)
    return text


def get_ollama_model_candidates():
    ordered = []
    for item in [LLM_MODEL, *LLM_FALLBACK_MODELS]:
        name = str(item or "").strip()
        if name and name not in ordered:
            ordered.append(name)
    return ordered


def generate_with_ollama(prompt):
    errors = []
    for model_name in get_ollama_model_candidates():
        try:
            response = requests.post(
                f"{LLM_BASE_URL}/api/generate",
                json={
                    "model": model_name,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.1},
                },
                timeout=LLM_TIMEOUT,
            )
            if not response.ok:
                raise RuntimeError(f"Ollama status {response.status_code}")
            raw = (response.json() or {}).get("response", "")
            if not str(raw).strip():
                raise RuntimeError("Empty Ollama response")
            return model_name, raw
        except Exception as e:
            logger.warning(f"Ollama model {model_name} failed: {str(e)}")
            errors.append(f"{model_name}: {str(e)}")

    raise RuntimeError("; ".join(errors) if errors else "No usable Ollama models configured")


def generate_suricata_sid():
    # Keep custom SIDs in a user/local range to avoid collisions with bundled rules.
    return 9_000_000 + int(datetime.now(timezone.utc).timestamp() * 1000) % 900_000


def sanitize_suricata_msg(text):
    compact = re.sub(r"\s+", " ", str(text or "")).strip()
    compact = compact.replace('"', "'")
    if len(compact) > 110:
        compact = compact[:107] + "..."
    return compact or "AI translated rule"


def normalize_prompt_text(text):
    value = unicodedata.normalize("NFKD", str(text or ""))
    return value.encode("ascii", "ignore").decode("ascii").lower().strip()


SERVICE_PROFILES = [
    {"name": "ssh", "label": "SSH", "tokens": ("ssh", "secure shell", "port 22"), "protocol": "tcp", "port": "22", "encrypted": True},
    {"name": "telnet", "label": "Telnet", "tokens": ("telnet", "port 23"), "protocol": "tcp", "port": "23", "encrypted": False},
    {"name": "rdp", "label": "RDP", "tokens": ("rdp", "remote desktop", "port 3389"), "protocol": "tcp", "port": "3389", "encrypted": True},
    {"name": "smb", "label": "SMB", "tokens": ("smb", "port 445"), "protocol": "tcp", "port": "445", "encrypted": False},
    {"name": "dns", "label": "DNS", "tokens": ("dns", "domain", "port 53"), "protocol": "udp", "port": "53", "encrypted": False},
    {"name": "https", "label": "HTTPS", "tokens": ("https", "tls", "ssl", "port 443"), "protocol": "tcp", "port": "443", "encrypted": True},
    {"name": "http", "label": "HTTP", "tokens": ("http", "web", "port 80", "port 8080"), "protocol": "tcp", "port": "80", "encrypted": False},
    {"name": "ftp", "label": "FTP", "tokens": ("ftp", "port 21"), "protocol": "tcp", "port": "21", "encrypted": False},
    {"name": "smtp", "label": "SMTP", "tokens": ("smtp", "mail", "port 25"), "protocol": "tcp", "port": "25", "encrypted": False},
    {"name": "imap", "label": "IMAP", "tokens": ("imap", "port 143"), "protocol": "tcp", "port": "143", "encrypted": False},
    {"name": "pop3", "label": "POP3", "tokens": ("pop3", "port 110"), "protocol": "tcp", "port": "110", "encrypted": False},
    {"name": "snmp", "label": "SNMP", "tokens": ("snmp", "port 161"), "protocol": "udp", "port": "161", "encrypted": False},
    {"name": "ntp", "label": "NTP", "tokens": ("ntp", "port 123"), "protocol": "udp", "port": "123", "encrypted": False},
    {"name": "dhcp", "label": "DHCP", "tokens": ("dhcp", "port 67", "port 68"), "protocol": "udp", "port": "67", "encrypted": False},
]

BLOCK_KEYWORDS = ("block", "bloque", "deny", "refuse", "drop", "quarantine")
REJECT_KEYWORDS = ("reject",)
ALLOW_KEYWORDS = ("allow", "autorise", "permit", "pass")
PING_KEYWORDS = (
    "icmp",
    "icmpv4",
    "icmpv6",
    "ping",
    "pings",
    "echo",
    "echo request",
    "icmp echo",
    "requete icmp",
    "requetes icmp",
    "requete de ping",
    "requetes de ping",
)
PORT_SCAN_KEYWORDS = ("port scan", "port scanning", "scan de port", "scan de ports", "balayage de ports", "enumeration de ports")
BRUTE_FORCE_KEYWORDS = (
    "brute force",
    "failed login",
    "failed logins",
    "failed password",
    "password spray",
    "credential stuffing",
    "authentication failure",
    "auth failure",
    "login attempt",
    "login attempts",
)
THRESHOLD_HINT_KEYWORDS = ("too many", "trop de", "repeated", "repeatedly", "burst", "flood", "au moins", "at least", "more than", "over", "plus de")
CONTENT_MATCH_KEYWORDS = (
    "content",
    "payload",
    "contains",
    "contain",
    "uri",
    "path",
    "header",
    "host",
    "dns query",
    "domain name",
    "pcre",
    "regex",
    "regexp",
)
UDP_DEFAULT_PORTS = {"53", "67", "68", "123", "161"}


def contains_any_token(normalized_text, tokens):
    for token in tokens:
        escaped = re.escape(token)
        if re.search(rf"(?<!\w){escaped}(?!\w)", normalized_text):
            return True
    return False


def extract_explicit_port(normalized_text):
    match = re.search(r"\bport(?:\s+number)?\s+(\d{1,5})\b", normalized_text)
    if not match:
        return None
    port = int(match.group(1))
    if 1 <= port <= 65535:
        return str(port)
    return None


def infer_protocol_for_port(port, normalized_text):
    if contains_any_token(normalized_text, PING_KEYWORDS):
        return "icmp"
    if " udp " in f" {normalized_text} ":
        return "udp"
    if " tcp " in f" {normalized_text} ":
        return "tcp"
    return "udp" if str(port) in UDP_DEFAULT_PORTS else "tcp"


def infer_service_profile(normalized_text):
    explicit_port = extract_explicit_port(normalized_text)

    if contains_any_token(normalized_text, PING_KEYWORDS):
        return {
            "name": "icmp",
            "label": "ICMP",
            "protocol": "icmp",
            "port": "any",
            "encrypted": False,
        }
    # Fuzzy fallback for minor typos such as "icpm", "imcp", etc.
    if re.search(r"\bi\w{0,2}c\w{0,2}m\w{0,2}p\b", normalized_text):
        return {
            "name": "icmp",
            "label": "ICMP",
            "protocol": "icmp",
            "port": "any",
            "encrypted": False,
        }

    for profile in SERVICE_PROFILES:
        if contains_any_token(normalized_text, profile["tokens"]):
            resolved = dict(profile)
            if explicit_port:
                resolved["port"] = explicit_port
            return resolved

    if explicit_port:
        return {
            "name": f"port-{explicit_port}",
            "label": f"Port {explicit_port}",
            "protocol": infer_protocol_for_port(explicit_port, normalized_text),
            "port": explicit_port,
            "encrypted": explicit_port in {"22", "443", "3389"},
        }

    if " udp " in f" {normalized_text} ":
        return {"name": "udp", "label": "UDP", "protocol": "udp", "port": "any", "encrypted": False}
    if " tcp " in f" {normalized_text} ":
        return {"name": "tcp", "label": "TCP", "protocol": "tcp", "port": "any", "encrypted": False}
    return {"name": "ip", "label": "IP", "protocol": "ip", "port": "any", "encrypted": False}


def extract_suricata_threshold_count(text, default=10):
    normalized = normalize_prompt_text(text)
    patterns = [
        r'(?:plus de|au moins|at least|more than|over|>=)\s+(\d+)\s+(?:tentatives?|attempts?|requetes?|requests?|connexions?|connections?|paquets?|packets?|flows?|ports?)',
        r'(\d+)\s+(?:tentatives?|attempts?|requetes?|requests?|connexions?|connections?|paquets?|packets?|flows?|ports?)',
    ]
    for pattern in patterns:
        match = re.search(pattern, normalized)
        if match:
            return max(int(match.group(1)), 1)
    return default


def extract_suricata_threshold_seconds(text, default=30):
    normalized = normalize_prompt_text(text)
    match = re.search(r'(\d+)\s*(secondes?|seconds?|sec|minutes?|mins?|heures?|hours?|hrs?)', normalized)
    if not match:
        return default

    value = int(match.group(1))
    unit = match.group(2)
    if unit.startswith(('seconde', 'second', 'sec')):
        return value
    if unit.startswith(('minute', 'min')):
        return value * 60
    if unit.startswith(('heure', 'hour', 'hr')):
        return value * 3600
    return default


def infer_suricata_protocol_and_port(normalized_text):
    profile = infer_service_profile(normalized_text)
    return profile["protocol"], profile["port"]


def enforce_suricata_sid(rule_text, sid):
    rule = re.sub(r"\s+", " ", str(rule_text or "").strip())
    if not rule:
        return ""

    sid_token = f"sid:{int(sid)};"
    if re.search(r"sid\s*:\s*\d+\s*;", rule, flags=re.IGNORECASE):
        return re.sub(r"sid\s*:\s*\d+\s*;", sid_token, rule, count=1, flags=re.IGNORECASE)

    close_index = rule.rfind(")")
    if close_index != -1:
        before = rule[:close_index].rstrip()
        if not before.endswith(";"):
            before += ";"
        return f"{before} {sid_token} rev:1;)"
    return rule


def is_valid_suricata_rule(rule_text):
    rule = str(rule_text or "").strip()
    if not rule:
        return False
    if not re.match(r"^(alert|drop|reject|pass)\s+\w+\s+.+\(.+\)\s*$", rule, flags=re.IGNORECASE):
        return False
    if "sid:" not in rule.lower():
        return False
    return True


def parse_suricata_rule(rule_text):
    rule = re.sub(r"\s+", " ", str(rule_text or "").strip())
    match = re.match(
        r"^(alert|drop|reject|pass)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$",
        rule,
        flags=re.IGNORECASE,
    )
    if not match:
        return None

    option_items = []
    option_map = {}
    options_blob = match.group(8)
    for raw_part in [part.strip() for part in options_blob.split(";") if part.strip()]:
        option_items.append(raw_part)
        if ":" in raw_part:
            key, value = raw_part.split(":", 1)
            option_map[key.strip().lower()] = value.strip()
        else:
            option_map[raw_part.strip().lower()] = True

    return {
        "action": match.group(1).lower(),
        "protocol": match.group(2).lower(),
        "src_addr": match.group(3),
        "src_port": match.group(4),
        "direction": match.group(5),
        "dst_addr": match.group(6),
        "dst_port": match.group(7),
        "options": option_items,
        "option_map": option_map,
        "raw": rule,
    }


def infer_suricata_action(normalized_text):
    if contains_any_token(normalized_text, ALLOW_KEYWORDS):
        return "pass"
    if contains_any_token(normalized_text, REJECT_KEYWORDS):
        return "reject"
    if contains_any_token(normalized_text, BLOCK_KEYWORDS):
        return "drop"
    return "alert"


def prompt_requests_threshold(normalized_text):
    return (
        contains_any_token(normalized_text, BRUTE_FORCE_KEYWORDS)
        or contains_any_token(normalized_text, PORT_SCAN_KEYWORDS)
        or contains_any_token(normalized_text, THRESHOLD_HINT_KEYWORDS)
        or bool(re.search(r"\d+\s+(?:tentatives?|attempts?|requetes?|requests?|connexions?|connections?|paquets?|packets?|flows?|ports?)", normalized_text))
    )


def prompt_requests_content_match(prompt_text, normalized_text):
    if contains_any_token(normalized_text, CONTENT_MATCH_KEYWORDS):
        return True
    return bool(re.search(r'"[^"]+"', str(prompt_text or "")))


def infer_attack_family(normalized_text, service):
    if service["protocol"] == "icmp" or contains_any_token(normalized_text, PING_KEYWORDS):
        if prompt_requests_threshold(normalized_text):
            return "icmp_burst"
        return "icmp_echo"
    if contains_any_token(normalized_text, PORT_SCAN_KEYWORDS):
        return "port_scan"
    if contains_any_token(normalized_text, BRUTE_FORCE_KEYWORDS):
        return "brute_force"
    if prompt_requests_threshold(normalized_text):
        return "connection_threshold"
    if service["port"] != "any" or service["protocol"] != "ip":
        return "service_traffic"
    return "generic_ip"


def build_suricata_intent(prompt_text):
    normalized = normalize_prompt_text(prompt_text)
    service = infer_service_profile(normalized)
    family = infer_attack_family(normalized, service)
    has_threshold = family in {"brute_force", "port_scan", "connection_threshold", "icmp_burst"}
    default_count = 20 if family == "port_scan" else 10
    default_seconds = 60 if family in {"brute_force", "port_scan"} else (5 if family == "icmp_burst" else 30)

    return {
        "prompt": prompt_text,
        "normalized": normalized,
        "service": service,
        "attack_family": family,
        "action": infer_suricata_action(normalized),
        "needs_threshold": has_threshold,
        "threshold_count": extract_suricata_threshold_count(prompt_text, default=default_count) if has_threshold else None,
        "threshold_seconds": extract_suricata_threshold_seconds(prompt_text, default=default_seconds) if has_threshold else None,
        "requires_content_match": prompt_requests_content_match(prompt_text, normalized),
        "prefer_deterministic": family in {"icmp_echo", "icmp_burst", "brute_force", "port_scan", "connection_threshold", "service_traffic"},
    }


def build_suricata_msg_from_intent(intent):
    service_label = intent["service"]["label"]
    family = intent["attack_family"]

    if family == "icmp_echo":
        return "ICMP echo request detected"
    if family == "icmp_burst":
        return "Repeated ICMP echo requests from same source"
    if family == "port_scan":
        return "Potential port scan detected"
    if family == "brute_force":
        return f"{service_label} brute force connection attempts"
    if family == "connection_threshold":
        if intent["service"]["port"] != "any":
            return f"{service_label} connection burst detected"
        return "High-rate network activity detected"
    if family == "service_traffic":
        if intent["action"] == "drop":
            return f"{service_label} traffic blocked"
        return f"{service_label} traffic detected"
    return sanitize_suricata_msg(intent["prompt"])


def build_classtype_from_intent(intent):
    family = intent["attack_family"]
    if family in {"icmp_burst", "port_scan"}:
        return "attempted-recon"
    if family == "brute_force":
        return "attempted-admin"
    if family == "connection_threshold":
        return "attempted-dos"
    return "misc-activity"


def build_priority_from_intent(intent):
    family = intent["attack_family"]
    if family in {"icmp_burst", "port_scan", "brute_force"}:
        return "2"
    return "3"


def build_suricata_header_from_intent(intent):
    action = intent["action"]
    protocol = intent["service"]["protocol"]
    port = intent["service"]["port"]

    if protocol == "icmp":
        return f"{action} icmp any any -> $HOME_NET any"
    if port == "any":
        return f"{action} {protocol} any any -> $HOME_NET any"
    return f"{action} {protocol} any any -> $HOME_NET {port}"


def build_deterministic_suricata_rule(intent, sid):
    options = [f'msg:"{build_suricata_msg_from_intent(intent)}"']
    protocol = intent["service"]["protocol"]
    family = intent["attack_family"]

    if family in {"icmp_echo", "icmp_burst"}:
        options.append("itype:8")
    elif protocol == "tcp" and intent["service"]["port"] != "any":
        options.append("flow:to_server")

    if protocol == "tcp" and family in {"brute_force", "port_scan", "connection_threshold"}:
        options.append("flags:S")

    if intent["needs_threshold"]:
        threshold_count = int(intent["threshold_count"])
        threshold_seconds = int(intent["threshold_seconds"])
        if family == "icmp_burst":
            options.append(
                f"detection_filter:track by_src, count {threshold_count}, seconds {threshold_seconds}"
            )
        else:
            options.append(
                f"threshold:type both, track by_src, count {threshold_count}, seconds {threshold_seconds}"
            )

    options.append(f"classtype:{build_classtype_from_intent(intent)}")
    options.append(f"priority:{build_priority_from_intent(intent)}")

    options.append(f"sid:{int(sid)}")
    options.append("rev:1")

    return f"{build_suricata_header_from_intent(intent)} ({'; '.join(options)};)"


def deterministic_suricata_translation(prompt_text, sid):
    intent = build_suricata_intent(prompt_text)
    rule = build_deterministic_suricata_rule(intent, sid)

    explanation_parts = [
        "Deterministic translation used.",
        f"Recognized {intent['service']['label']} traffic with action {intent['action'].upper()}.",
    ]
    if intent["needs_threshold"]:
        explanation_parts.append(
            f"Applied threshold {intent['threshold_count']} events in {intent['threshold_seconds']} seconds."
        )

    return {
        "rule": rule,
        "explanation": " ".join(explanation_parts) + " Please review before adding.",
        "provider": "deterministic",
        "model": "rule-intent-template",
        "used_fallback": False,
        "intent": intent,
    }


def normalize_llm_suricata_candidate(rule_text, sid, intent):
    rule = enforce_suricata_sid(rule_text, sid)
    rule = re.sub(r"\btrack\s+by\s+src\b", "track by_src", rule, flags=re.IGNORECASE)
    rule = re.sub(r"\btrack\s+by\s+dst\b", "track by_dst", rule, flags=re.IGNORECASE)

    if intent.get("needs_threshold") and intent.get("threshold_count"):
        rule = re.sub(
            r"\bcount\s+(?:minvar|maxvar|var|\w+placeholder)\b",
            f"count {int(intent['threshold_count'])}",
            rule,
            flags=re.IGNORECASE,
        )
        if not re.search(r"\bcount\s+\d+\b", rule, flags=re.IGNORECASE):
            rule = re.sub(
                r"(threshold\s*:\s*type\s+\w+\s*,\s*track\s+by_(?:src|dst))",
                rf"\1, count {int(intent['threshold_count'])}",
                rule,
                count=1,
                flags=re.IGNORECASE,
            )
    return rule


def validate_suricata_candidate(rule_text, intent):
    if not is_valid_suricata_rule(rule_text):
        return False, "Rule failed basic Suricata syntax validation."

    lowered = rule_text.lower()
    if any(token in lowered for token in ("minvar", "<count>", "<seconds>", " times ", " count var", "placeholder")):
        return False, "Rule contains placeholder values."

    parsed = parse_suricata_rule(rule_text)
    if not parsed:
        return False, "Unable to parse rule header and options."

    desired_action = intent["action"]
    if desired_action == "drop" and parsed["action"] not in {"drop", "reject"}:
        return False, "Prompt requested blocking but the rule does not block."
    if desired_action == "pass" and parsed["action"] != "pass":
        return False, "Prompt requested allow/pass behavior."
    if desired_action == "alert" and parsed["action"] not in {"alert", "drop", "reject"}:
        return False, "Rule action is incompatible with detection intent."

    expected_protocol = intent["service"]["protocol"]
    expected_port = intent["service"]["port"]
    if expected_protocol != "ip" and parsed["protocol"] != expected_protocol:
        return False, f"Expected protocol {expected_protocol} but got {parsed['protocol']}."
    if expected_port != "any" and parsed["dst_port"] != expected_port:
        return False, f"Expected destination port {expected_port} but got {parsed['dst_port']}."

    if intent["attack_family"] in {"icmp_echo", "icmp_burst"}:
        if parsed["protocol"] != "icmp":
            return False, "ICMP prompt must translate to an ICMP rule."
        if "itype" in lowered and "itype:8" not in lowered.replace(" ", ""):
            return False, "ICMP ping detection must use echo request type 8."

    if intent["needs_threshold"]:
        threshold_match = re.search(r"\bcount\s+(\d+)\b.*?\bseconds\s+(\d+)\b", lowered)
        if not threshold_match:
            threshold_match = re.search(r"\bseconds\s+(\d+)\b.*?\bcount\s+(\d+)\b", lowered)
            if threshold_match:
                threshold_match = (threshold_match.group(2), threshold_match.group(1))
        if not threshold_match:
            return False, "Prompt requested a threshold but the rule does not contain a numeric threshold."

        if isinstance(threshold_match, tuple):
            count_value, seconds_value = threshold_match
        else:
            count_value, seconds_value = threshold_match.group(1), threshold_match.group(2)

        if int(count_value) != int(intent["threshold_count"]):
            return False, f"Expected threshold count {intent['threshold_count']} but got {count_value}."
        if int(seconds_value) != int(intent["threshold_seconds"]):
            return False, f"Expected threshold seconds {intent['threshold_seconds']} but got {seconds_value}."

    if intent["attack_family"] in {"brute_force", "connection_threshold", "port_scan"} and parsed["protocol"] == "tcp":
        if "flags:s" not in lowered and "flow:to_server" not in lowered.replace(" ", ""):
            return False, "TCP rate-based detections should constrain direction or SYN flags."

    if intent["service"].get("encrypted") and intent["attack_family"] in {"brute_force", "connection_threshold"}:
        if ("content:" in lowered or "pcre:" in lowered) and "flags:s" not in lowered:
            return False, "Encrypted service thresholds should not rely on payload content alone."

    return True, ""


def heuristic_suricata_translation(prompt_text, sid):
    translated = deterministic_suricata_translation(prompt_text, sid)
    translated["used_fallback"] = True
    translated["provider"] = "fallback"
    translated["model"] = "heuristic-template"
    translated["explanation"] = translated["explanation"].replace("Deterministic translation used.", "Fallback deterministic translation used.")
    return translated


def translate_nl_to_suricata_rule(prompt_text, sid):
    fallback = heuristic_suricata_translation(prompt_text, sid)
    deterministic = deterministic_suricata_translation(prompt_text, sid)
    intent = deterministic.get("intent") or build_suricata_intent(prompt_text)

    if intent["prefer_deterministic"] and not intent["requires_content_match"]:
        return deterministic

    if not LLM_ENABLED or LLM_PROVIDER != "ollama":
        return deterministic if intent["prefer_deterministic"] else fallback

    prompt = (
        "Convert the following natural language security requirement into ONE Suricata rule.\n"
        "Return JSON only with keys: rule, explanation.\n"
        "Constraints:\n"
        f"- Must include sid:{int(sid)} and rev:1.\n"
        "- One line only.\n"
        "- Must start with alert, drop, reject, or pass.\n"
        f"- If the requirement asks to block traffic, the rule action must be {intent['action']}.\n"
        f"- Prefer protocol {intent['service']['protocol']} and destination port {intent['service']['port']} when applicable.\n"
        "- If a count/time threshold is requested, use Suricata threshold syntax with numeric count and seconds values.\n"
        "- Never use placeholders such as minvar, maxvar, <count>, <seconds>, or times 12.\n"
        "- Keep rule safe and generic, no offensive instructions.\n"
        "- No markdown.\n\n"
        f"Extracted intent: {json.dumps({'action': intent['action'], 'service': intent['service'], 'attack_family': intent['attack_family'], 'threshold_count': intent['threshold_count'], 'threshold_seconds': intent['threshold_seconds']}, ensure_ascii=True)}\n"
        f"Requirement: {prompt_text}"
    )

    try:
        response = requests.post(
            f"{LLM_BASE_URL}/api/generate",
            json={
                "model": LLM_MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0},
            },
            timeout=LLM_TIMEOUT,
        )
        if not response.ok:
            raise RuntimeError(f"Ollama status {response.status_code}")

        raw = (response.json() or {}).get("response", "")
        parsed = extract_json_object(raw) or {}
        candidate_rule = normalize_llm_suricata_candidate(parsed.get("rule", ""), sid, intent)

        is_valid, validation_reason = validate_suricata_candidate(candidate_rule, intent)
        if not is_valid:
            logger.info("Rejected LLM Suricata translation for prompt '%s': %s", prompt_text, validation_reason)
            return deterministic if intent["prefer_deterministic"] else fallback

        return {
            "rule": candidate_rule,
            "explanation": parsed.get("explanation") or "LLM translation generated.",
            "provider": "ollama",
            "model": LLM_MODEL,
            "used_fallback": False,
        }
    except Exception as e:
        logger.warning(f"Suricata rule translation failed: {str(e)}")
        return deterministic if intent["prefer_deterministic"] else fallback


def llm_agent_reasoning(actions, top_techniques, detect_summary, cognitive_traits, window_hours):
    anomaly_actions = [a for a in actions if a.get("ml_is_anomaly")]
    compact = anomaly_actions[:15] if anomaly_actions else actions[:15]

    base_fallback = {
        "provider": "fallback",
        "model": LLM_MODEL,
        "situation_summary": (
            f"Detected {detect_summary.get('anomaly_actions', 0)} anomalous actions in "
            f"{detect_summary.get('total_actions', 0)} actions over {window_hours}h."
        ),
        "attack_hypotheses": [
            "Reconnaissance or service enumeration may be in progress.",
            "Potential brute-force or repeated remote access attempts."
        ],
        "mitre_candidates": [t.get("technique_id") for t in top_techniques[:5]],
        "response_plan": [
            "Review top anomalous source/destination pairs.",
            "Validate impacted hosts and isolate if suspicious activity persists.",
            "Open or update incident with timeline evidence."
        ],
        "incident": {
            "should_create": detect_summary.get("anomaly_actions", 0) > 0,
            "severity": "high" if detect_summary.get("anomaly_actions", 0) >= 3 else "medium",
            "title": "AI Agent: suspicious network behavior detected",
            "description": "Automated agent flagged anomalous network activity.",
        },
        "confidence": 0.55,
    }

    if not LLM_ENABLED or LLM_PROVIDER != "ollama":
        base_fallback["provider"] = "disabled"
        return base_fallback

    payload = {
        "window_hours": window_hours,
        "detect_summary": detect_summary,
        "top_techniques": top_techniques[:8],
        "cognitive_traits": cognitive_traits,
        "actions": compact,
    }
    prompt = (
        "You are an autonomous SOC reasoning agent.\n"
        "Use the evidence to produce strict JSON with keys:\n"
        "situation_summary, attack_hypotheses, mitre_candidates, cognitive_assessment, "
        "response_plan, incident, confidence.\n"
        "incident must contain: should_create (bool), severity (low|medium|high|critical), title, description.\n"
        "Keep concise, evidence-driven, no markdown.\n\n"
        f"DATA={json.dumps(payload, default=str)}"
    )

    try:
        used_model, raw = generate_with_ollama(prompt)
        parsed = extract_json_object(raw)
        if not parsed:
            raise RuntimeError("Failed to parse LLM JSON")

        cognitive_assessment = parsed.get("cognitive_assessment", cognitive_traits)
        if not isinstance(cognitive_assessment, dict):
            cognitive_assessment = cognitive_traits

        return {
            "provider": "ollama",
            "model": used_model,
            "situation_summary": coerce_summary_text(parsed.get("situation_summary"), base_fallback["situation_summary"]),
            "attack_hypotheses": coerce_string_list(parsed.get("attack_hypotheses"), base_fallback["attack_hypotheses"]),
            "mitre_candidates": coerce_string_list(parsed.get("mitre_candidates"), base_fallback["mitre_candidates"]),
            "cognitive_assessment": cognitive_assessment,
            "response_plan": coerce_string_list(parsed.get("response_plan"), base_fallback["response_plan"]),
            "incident": coerce_incident_payload(parsed.get("incident"), base_fallback["incident"]),
            "confidence": coerce_confidence(parsed.get("confidence"), base_fallback["confidence"]),
        }
    except Exception as e:
        logger.warning(f"LLM reasoning failed: {str(e)}")
        return base_fallback


def llm_device_general_report(device_context):
    """Generate a plain-language per-device security report."""
    device = device_context.get("device") or {}
    fallback_summary = (
        f"Passive report for {device.get('hostname') or device.get('ip_address') or 'device'}: "
        "review OS correlation, observed traffic, open ports, incidents, and CVE status. "
        "This is a correlation report, not exploitation confirmation."
    )
    fallback = {
        "provider": "fallback",
        "model": LLM_MODEL,
        "executive_summary": fallback_summary,
        "key_points": [
            "Status and last seen are telemetry-based and may lag by collection interval.",
            "Traffic/protocol metrics are based on observed flows only.",
            "CVE mapping is OS/OS-version correlation, not proof of compromise."
        ],
        "recommended_actions": [
            "Prioritize patching for critical/high CVEs.",
            "Validate exposed/open ports against approved baseline.",
            "Review matching incidents and alerts for this asset."
        ],
        "confidence": 0.6,
    }

    if not LLM_ENABLED or LLM_PROVIDER != "ollama":
        fallback["provider"] = "disabled"
        return fallback

    prompt = (
        "You are a SOC assistant writing a unified per-device vulnerability report for non-experts.\n"
        "Return strict JSON only with keys:\n"
        "executive_summary (string), key_points (array of short strings), "
        "recommended_actions (array of short strings), confidence (0..1).\n"
        "Rules:\n"
        "- Keep wording clear and non-alarmist.\n"
        "- Explicitly state this is passive OS/CVE correlation, not confirmed exploitation.\n"
        "- Mention status, traffic profile, open ports, incidents, and CVE status.\n"
        "- No markdown.\n\n"
        f"DATA={json.dumps(device_context, default=str)}"
    )

    try:
        used_model, raw = generate_with_ollama(prompt)
        parsed = extract_json_object(raw) or {}
        if not parsed:
            raise RuntimeError("Failed to parse LLM JSON")

        return {
            "provider": "ollama",
            "model": used_model,
            "executive_summary": coerce_summary_text(parsed.get("executive_summary"), fallback["executive_summary"]),
            "key_points": coerce_string_list(parsed.get("key_points"), fallback["key_points"]),
            "recommended_actions": coerce_string_list(parsed.get("recommended_actions"), fallback["recommended_actions"]),
            "confidence": coerce_confidence(parsed.get("confidence"), fallback["confidence"]),
        }
    except Exception as e:
        logger.warning(f"LLM device report failed: {str(e)}")
        return fallback


def maybe_create_incident(reasoning, auto_create):
    incident = reasoning.get("incident") or {}
    should_create = bool(incident.get("should_create"))
    if not auto_create or not should_create:
        return {"attempted": False, "created": False}

    payload = {
        "title": incident.get("title") or "AI Agent Incident",
        "description": incident.get("description") or "Automated incident from AI agent",
        "severity": (incident.get("severity") or "medium").lower(),
        "created_by": "ai-agent",
    }
    try:
        response = requests.post(f"{CORRELATION_SERVICE}/incidents", json=payload, timeout=20)
        if response.ok:
            data = response.json() if response.content else {}
            return {
                "attempted": True,
                "created": True,
                "incident_id": data.get("incident_id"),
                "service_status": response.status_code,
            }
        return {
            "attempted": True,
            "created": False,
            "service_status": response.status_code,
        }
    except Exception as e:
        return {"attempted": True, "created": False, "error": str(e)}


def compute_anomaly_score(actions):
    if not actions:
        return 0
    raw = 0.0
    for action in actions:
        ml_score = float(action.get("ml_score", 0.0))
        if action.get("ml_is_anomaly"):
            raw += 8.0 * ml_score
        sev = action.get("severity_counts", {})
        raw += sev.get("critical", 0) * 4
        raw += sev.get("high", 0) * 2
        raw += sev.get("medium", 0) * 1
    return int(min(100, round(raw)))


def run_agent_workflow(window_hours, max_events, auto_create_incident=False):
    observe_started = datetime.now(timezone.utc)
    live_events = fetch_live_logs(max_events)
    indexed_count = elastic_bulk_index(live_events)
    elastic_events = elastic_fetch_events(window_hours, max_events)
    events = elastic_events if elastic_events else live_events
    events = sorted(events, key=lambda ev: parse_timestamp(ev.get("timestamp")))[:max_events]
    actions = segment_actions(events)

    mapped_per_action, top_techniques = map_attack_techniques(actions)
    technique_by_action = {r["action_id"]: r["techniques"] for r in mapped_per_action}
    for action in actions:
        action["likely_techniques"] = technique_by_action.get(action["action_id"], [])

    detect_summary = detect_with_svm(actions)
    anomaly_score = compute_anomaly_score(actions)
    cognitive_traits = infer_cognitive_traits(actions)
    reasoning = llm_agent_reasoning(actions, top_techniques, detect_summary, cognitive_traits, window_hours)
    act_result = maybe_create_incident(reasoning, auto_create_incident)

    severity_totals = Counter()
    for event in events:
        severity_totals[(event.get("severity") or "low").lower()] += 1

    workflow = {
        "observe": {
            "started_at": observe_started.isoformat(),
            "events_live_fetched": len(live_events),
            "events_indexed": indexed_count,
            "events_analyzed": len(events),
            "elastic_used": bool(elastic_events),
            "elastic_hits": len(elastic_events),
        },
        "detect": detect_summary,
        "reason": {
            "provider": reasoning.get("provider"),
            "model": reasoning.get("model"),
            "confidence": reasoning.get("confidence", 0.5),
        },
        "act": act_result,
    }

    report = {
        "status": "ok",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window_hours": window_hours,
        "workflow": workflow,
        "stats": {
            "events_live_fetched": len(live_events),
            "events_indexed": indexed_count,
            "events_analyzed": len(events),
            "actions_detected": len(actions),
            "anomaly_score": anomaly_score,
            "severity_totals": dict(severity_totals),
        },
        "sources": {
            "elastic_used": bool(elastic_events),
            "elastic_hits": len(elastic_events),
            "traffic_service_events": len(live_events),
        },
        "attack": {"top_techniques": top_techniques},
        "agent": {
            "cognitive_traits": cognitive_traits,
            "reasoning": reasoning,
        },
        # backward-compatible keys for existing UI section
        "llm_report": {
            "provider": reasoning.get("provider"),
            "model": reasoning.get("model"),
            "summary": reasoning.get("situation_summary"),
            "findings": reasoning.get("attack_hypotheses", []),
            "recommendations": reasoning.get("response_plan", []),
            "confidence": reasoning.get("confidence", 0.5),
        },
        "actions": actions[:100],
    }
    return report


def run_analysis(window_hours, max_events):
    # Legacy endpoint now delegates to the full agentic workflow
    return run_agent_workflow(window_hours, max_events, auto_create_incident=False)


@app.route("/health", methods=["GET"])
def health():
    bundle = load_model_bundle()
    return jsonify({
        "status": "healthy",
        "service": "log-llm-analyzer",
        "llm_enabled": LLM_ENABLED,
        "llm_provider": LLM_PROVIDER,
        "llm_model": LLM_MODEL,
        "sklearn_available": SKLEARN_AVAILABLE,
        "model_trained": bool(bundle),
        "elasticsearch": "reachable" if elastic_available() else "unreachable",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/logs/analyze", methods=["POST"])
def analyze_logs():
    global last_report, last_agent_report
    data = request.get_json(silent=True) or {}
    window_hours = int(data.get("window_hours") or DEFAULT_WINDOW_HOURS)
    max_events = int(data.get("max_events") or MAX_EVENTS)
    window_hours = max(1, min(window_hours, 168))
    max_events = max(100, min(max_events, MAX_EVENTS))

    report = run_analysis(window_hours=window_hours, max_events=max_events)
    last_report = report
    last_agent_report = report
    return jsonify(report)


@app.route("/suricata/translate-rule", methods=["POST"])
def translate_suricata_rule():
    data = request.get_json(silent=True) or {}
    prompt_text = (data.get("prompt") or data.get("text") or "").strip()
    if not prompt_text:
        return jsonify({"status": "error", "error": "prompt is required"}), 400

    raw_sid = data.get("sid")
    sid = generate_suricata_sid()
    if raw_sid is not None:
        try:
            sid = int(raw_sid)
        except (TypeError, ValueError):
            sid = generate_suricata_sid()

    translated = translate_nl_to_suricata_rule(prompt_text, sid)
    return jsonify({
        "status": "ok",
        "prompt": prompt_text,
        "sid": sid,
        "rule": translated.get("rule"),
        "provider": translated.get("provider", "fallback"),
        "model": translated.get("model", LLM_MODEL if translated.get("provider") == "ollama" else "heuristic-template"),
        "used_fallback": bool(translated.get("used_fallback", False)),
        "explanation": translated.get("explanation", ""),
        "note": "Generated rule should be reviewed before deployment.",
    })


@app.route("/reports/device-general", methods=["POST"])
def report_device_general():
    """Create a unified per-device report from normalized context."""
    data = request.get_json(silent=True) or {}
    report = llm_device_general_report(data)
    return jsonify({
        "status": "ok",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "llm_report": report,
        "note": "Passive correlation report. Not a confirmation of compromise."
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5004, debug=False)
