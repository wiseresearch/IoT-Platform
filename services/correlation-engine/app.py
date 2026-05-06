from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import redis
import json
import os
import logging
import re
import unicodedata
from datetime import datetime, timedelta
import threading
import time
import requests

app = Flask(__name__)
CORS(app)

# Configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'unified-db'),
    'user': os.getenv('DB_USER', 'security_user'),
    'password': os.getenv('DB_PASS', 'change_me_db_password'),
    'database': os.getenv('DB_NAME', 'unified_security')
}

REDIS_CONFIG = {
    'host': os.getenv('REDIS_HOST', 'redis'),
    'port': 6379,
    'db': 0
}

VULNERABILITY_SERVICE = os.getenv('VULNERABILITY_SERVICE_URL', 'http://vulnerability-scanner:5001')
TRAFFIC_SERVICE = os.getenv('TRAFFIC_SERVICE_URL', 'http://traffic-analyzer:5002')

# Redis connection
redis_client = redis.Redis(**REDIS_CONFIG, decode_responses=True)

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self):
        self.config = DB_CONFIG
    
    def get_connection(self):
        return mysql.connector.connect(**self.config)
    
    def execute_query(self, query, params=None, fetch=False):
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute(query, params or ())
            
            if fetch:
                return cursor.fetchall()
            else:
                conn.commit()
                return cursor.rowcount
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {str(e)}")
            raise
        finally:
            if conn:
                conn.close()

db = DatabaseManager()

ALLOWED_RULE_TYPES = {
    'vulnerability_traffic',
    'anomaly_detection',
    'threat_intelligence',
    'behavioral'
}

ALLOWED_CONDITION_TYPES = {
    'device_has_vulnerability',
    'network_alert_from_device',
    'communication_with_threat_ip',
    'active_threat_intelligence',
    'new_device_discovered',
    'suspicious_network_behavior',
    'port_scanning_detected'
}

SEVERITY_SYNONYMS = {
    'faible': 'low',
    'low': 'low',
    'moyen': 'medium',
    'moyenne': 'medium',
    'medium': 'medium',
    'eleve': 'high',
    'haute': 'high',
    'haut': 'high',
    'high': 'high',
    'critique': 'critical',
    'critical': 'critical'
}

SEVERITY_RANK = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4
}


def normalize_text(value):
    value = value or ""
    value = unicodedata.normalize('NFKD', value)
    value = value.encode('ascii', 'ignore').decode('ascii')
    return value.lower().strip()


def parse_time_window_seconds(text, default_seconds=None):
    normalized = normalize_text(text)

    if "dans l'heure" in normalized or "within the hour" in normalized:
        return 3600

    match = re.search(
        r'(\d+)\s*(secondes?|seconds?|sec|minutes?|mins?|heures?|hours?|jours?|days?)',
        normalized
    )
    if not match:
        return default_seconds

    value = int(match.group(1))
    unit = match.group(2)

    if unit.startswith(('seconde', 'second', 'sec')):
        return value
    if unit.startswith(('minute', 'min')):
        return value * 60
    if unit.startswith(('heure', 'hour')):
        return value * 3600
    if unit.startswith(('jour', 'day')):
        return value * 86400

    return default_seconds


def extract_incident_severity(text, default='medium'):
    normalized = normalize_text(text)
    incident_match = re.search(
        r'(?:incident|severity|severite)\s+(?:is\s+)?(faible|low|moyen|moyenne|medium|eleve|haut|haute|high|critique|critical)',
        normalized
    )
    if incident_match:
        return SEVERITY_SYNONYMS[incident_match.group(1)]

    severity_matches = re.findall(
        r'\b(faible|low|moyen|moyenne|medium|eleve|haut|haute|high|critique|critical)\b',
        normalized
    )
    if severity_matches:
        resolved = [SEVERITY_SYNONYMS[item] for item in severity_matches]
        return max(resolved, key=lambda item: SEVERITY_RANK.get(item, 0))

    return default


def extract_vulnerability_severities(text, default=None):
    normalized = normalize_text(text)
    severities = []

    if re.search(r'\b(critique|critical)\b', normalized):
        severities.append('critical')
    if re.search(r'\b(eleve|haut|haute|high)\b', normalized):
        severities.append('high')
    if re.search(r'\b(moyen|moyenne|medium)\b', normalized):
        severities.append('medium')
    if re.search(r'\b(faible|low)\b', normalized):
        severities.append('low')

    ordered = []
    for severity in severities:
        if severity not in ordered:
            ordered.append(severity)

    if ordered:
        return ordered
    return list(default or [])


def validate_translated_rule(rule):
    if not isinstance(rule, dict):
        raise ValueError("Translated rule must be a JSON object.")

    rule_type = rule.get('rule_type')
    if rule_type not in ALLOWED_RULE_TYPES:
        raise ValueError(f"Unsupported rule_type '{rule_type}'.")

    severity = rule.get('severity')
    if severity not in ('low', 'medium', 'high', 'critical'):
        raise ValueError(f"Unsupported incident severity '{severity}'.")

    condition_query = rule.get('condition_query')
    if not isinstance(condition_query, dict):
        raise ValueError("condition_query must be a JSON object.")

    conditions = condition_query.get('conditions')
    if not isinstance(conditions, list) or not conditions:
        raise ValueError("condition_query.conditions must be a non-empty array.")

    for condition in conditions:
        condition_type = condition.get('type')
        if condition_type not in ALLOWED_CONDITION_TYPES:
            raise ValueError(f"Unsupported condition type '{condition_type}'.")

        if 'severity' in condition:
            severities = condition.get('severity') or []
            if not isinstance(severities, list):
                raise ValueError("severity must be a list when provided in a condition.")
            for item in severities:
                if item not in ('low', 'medium', 'high', 'critical'):
                    raise ValueError(f"Unsupported vulnerability severity '{item}'.")

        for numeric_key in (
            'time_window',
            'min_alert_count',
            'min_event_count',
            'min_port_count',
            'min_connection_attempts',
            'min_flow_count'
        ):
            if numeric_key in condition:
                try:
                    numeric_value = int(condition[numeric_key])
                except (TypeError, ValueError):
                    raise ValueError(f"{numeric_key} must be an integer.")
                if numeric_value <= 0:
                    raise ValueError(f"{numeric_key} must be positive.")


def extract_named_threshold(text, names, default=None):
    normalized = normalize_text(text)
    if isinstance(names, str):
        names = [names]

    for name in names:
        escaped = re.escape(name)
        patterns = [
            rf'(?:plus de|au moins|at least|more than|over)\s+(\d+)\s+{escaped}',
            rf'(?:minimum of|minimum|>=)\s+(\d+)\s+{escaped}',
            rf'{escaped}\s*(?:>=|>|au moins|at least|plus de|over)?\s*(\d+)',
            rf'(\d+)\s*\+?\s+{escaped}'
        ]
        for pattern in patterns:
            match = re.search(pattern, normalized)
            if match:
                return int(match.group(1))

    return default


def extract_alert_threshold(text, default=1):
    return extract_named_threshold(text, ['alertes', 'alerte', 'alerts', 'alert', 'detections', 'detection'], default)


def extract_event_threshold(text, default=100):
    return extract_named_threshold(
        text,
        ['evenements reseau', 'evenements', 'events', 'event', 'network events', 'activite', 'activity'],
        default
    )


def extract_port_threshold(text, default=20):
    return extract_named_threshold(text, ['ports differents', 'ports distincts', 'different ports', 'ports', 'port'], default)


def extract_connection_threshold(text, default=100):
    return extract_named_threshold(
        text,
        [
            'tentatives de connexion',
            'tentatives',
            'connexions',
            'connection attempts',
            'connections',
            'attempts',
            'probes'
        ],
        default
    )


def extract_flow_threshold(text, default=1):
    return extract_named_threshold(
        text,
        ['communications', 'communication', 'flows', 'flux', 'fois', 'sessions'],
        default
    )


def contains_any(normalized_text, tokens):
    return any(token in normalized_text for token in tokens)


def build_translated_rule_name(rule_type, normalized_text):
    if rule_type == 'vulnerability_traffic':
        if contains_any(normalized_text, ('suricata', 'ids', 'signature')):
            return 'Vulnerable Device with Suricata Alerts'
        return 'Vulnerable Device Alert Correlation'

    if rule_type == 'threat_intelligence':
        if contains_any(normalized_text, ('command and control', 'c2', 'botnet')):
            return 'Command-and-Control Communication'
        return 'Threat Intelligence Communication'

    if rule_type == 'anomaly_detection':
        return 'Suspicious Activity from New Device'

    if rule_type == 'behavioral':
        return 'Port Scanning Detection'

    return 'Translated Correlation Rule'


def translate_natural_language_rule(text):
    normalized = normalize_text(text)
    if not normalized:
        raise ValueError("The natural language rule is empty.")

    if re.match(r'^(alert|drop|reject|pass)\s+', normalized) and 'sid:' in normalized and '->' in normalized:
        raise ValueError(
            "This looks like a Suricata IDS signature. "
            "Provide a natural-language correlation rule instead."
        )

    mentions_suricata = contains_any(normalized, ('suricata', 'ids', 'signature'))
    mentions_vulnerability = contains_any(normalized, ('cve', 'vulnerabilite', 'vulnerability', 'cvss', 'patch', 'remediation'))
    mentions_threat_intel = contains_any(
        normalized,
        (
            'threat intelligence',
            'threat intel',
            'ip malveillante',
            'malicious ip',
            'blacklisted ip',
            'ioc',
            'indicator',
            'command and control',
            'c2',
            'botnet'
        )
    )
    mentions_new_device = contains_any(
        normalized,
        (
            'nouvel appareil',
            'new device',
            'recently discovered',
            'recent device',
            'device discovered',
            'first seen',
            'never seen before',
            'appareil inconnu'
        )
    )
    mentions_anomaly = contains_any(
        normalized,
        (
            'suspect',
            'suspicious',
            'anormal',
            'anomaly',
            'anomal',
            'evenement',
            'event',
            'unusual',
            'spike',
            'burst',
            'volume',
            'flood'
        )
    )
    mentions_port_scan = contains_any(
        normalized,
        (
            'port scan',
            'port scanning',
            'scan de ports',
            'scan de port',
            'balayage de ports',
            'balayage port',
            'enumeration de ports',
            'many ports',
            'multiple ports',
            'plusieurs ports'
        )
    )
    mentions_brute_force = contains_any(
        normalized,
        (
            'brute force',
            'failed login',
            'failed logins',
            'login attempt',
            'login attempts',
            'auth failure',
            'authentication failure',
            'password spray',
            'credential stuffing'
        )
    )

    if mentions_brute_force and not any((mentions_vulnerability, mentions_threat_intel, mentions_new_device, mentions_port_scan)):
        raise ValueError(
            "Brute-force or repeated login prompts are better translated as Suricata IDS signatures in the current system. "
            "Use Auto/Suricata mode, or describe a correlation involving vulnerabilities, threat intelligence, new devices, or port scans."
        )

    if mentions_vulnerability:
        translation = {
            'rule_name': build_translated_rule_name('vulnerability_traffic', normalized),
            'rule_type': 'vulnerability_traffic',
            'severity': extract_incident_severity(text, default='high'),
            'description': text,
            'condition_query': {
                'conditions': [
                    {
                        'type': 'device_has_vulnerability',
                        'severity': extract_vulnerability_severities(text, default=['high', 'critical'])
                    },
                    {
                        'type': 'network_alert_from_device',
                        'time_window': parse_time_window_seconds(text, default_seconds=3600),
                        'min_alert_count': extract_alert_threshold(text, default=1)
                    }
                ]
            }
        }
        if mentions_suricata:
            translation['condition_query']['conditions'][1]['source'] = 'suricata'
    elif mentions_threat_intel:
        translation = {
            'rule_name': build_translated_rule_name('threat_intelligence', normalized),
            'rule_type': 'threat_intelligence',
            'severity': extract_incident_severity(text, default='critical'),
            'description': text,
            'condition_query': {
                'conditions': [
                    {
                        'type': 'communication_with_threat_ip',
                        'time_window': parse_time_window_seconds(text, default_seconds=3600),
                        'min_flow_count': extract_flow_threshold(text, default=1)
                    },
                    {
                        'type': 'active_threat_intelligence'
                    }
                ]
            }
        }
    elif mentions_new_device:
        detection_window = parse_time_window_seconds(text, default_seconds=1800)
        translation = {
            'rule_name': build_translated_rule_name('anomaly_detection', normalized),
            'rule_type': 'anomaly_detection',
            'severity': extract_incident_severity(text, default='medium'),
            'description': text,
            'condition_query': {
                'conditions': [
                    {
                        'type': 'new_device_discovered',
                        'time_window': detection_window
                    },
                    {
                        'type': 'suspicious_network_behavior',
                        'time_window': detection_window,
                        'min_event_count': extract_event_threshold(
                            text,
                            default=100 if mentions_anomaly else 50
                        )
                    }
                ]
            }
        }
    elif mentions_port_scan:
        translation = {
            'rule_name': build_translated_rule_name('behavioral', normalized),
            'rule_type': 'behavioral',
            'severity': extract_incident_severity(text, default='medium'),
            'description': text,
            'condition_query': {
                'conditions': [
                    {
                        'type': 'port_scanning_detected',
                        'time_window': parse_time_window_seconds(text, default_seconds=3600),
                        'min_port_count': extract_port_threshold(text, default=20),
                        'min_connection_attempts': extract_connection_threshold(text, default=100)
                    }
                ]
            }
        }
    else:
        raise ValueError(
            "Unable to translate the rule. "
            "Supported patterns currently include: vulnerable device alert correlation, communication with malicious IPs/IOCs, suspicious activity from a new device, and port-scanning behavior."
        )

    validate_translated_rule(translation)
    return translation
def get_request_payload():
    raw = request.get_data(cache=True, as_text=True)
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            text = raw.strip()
            if text:
                return {'natural_language_rule': text}

    data = request.get_json(silent=True, force=True)
    if isinstance(data, dict):
        return data

    if request.form:
        return request.form.to_dict(flat=True)

    if request.args:
        return request.args.to_dict(flat=True)

    return {}
class CorrelationEngine:
    def __init__(self):
        self.correlation_rules = []
        self.load_correlation_rules()
        self.daily_scan_enabled = os.getenv('INCIDENT_DAILY_SCAN', 'true').lower() in ('1', 'true', 'yes')
        self.daily_scan_hour = int(os.getenv('INCIDENT_SCAN_HOUR', '2'))
        self.daily_scan_minute = int(os.getenv('INCIDENT_SCAN_MINUTE', '0'))
        self.daily_scan_window_hours = int(os.getenv('INCIDENT_SCAN_WINDOW_HOURS', '24'))
        self.daily_scan_low_threshold = int(os.getenv('INCIDENT_SCAN_LOW_THRESHOLD', '20'))
        self.daily_scan_medium_threshold = int(os.getenv('INCIDENT_SCAN_MEDIUM_THRESHOLD', '5'))
        
        # Start correlation thread
        self.correlation_thread = threading.Thread(target=self.correlation_worker, daemon=True)
        self.correlation_thread.start()

        if self.daily_scan_enabled:
            self.daily_scan_thread = threading.Thread(target=self.daily_scan_worker, daemon=True)
            self.daily_scan_thread.start()
    
    def load_correlation_rules(self):
        """Load correlation rules from database"""
        try:
            query = """
            SELECT id, rule_name, rule_type, condition_query, severity, enabled
            FROM correlation_rules
            WHERE enabled = TRUE
            """
            
            self.correlation_rules = db.execute_query(query, fetch=True)
            logger.info(f"Loaded {len(self.correlation_rules)} correlation rules")
            
        except Exception as e:
            logger.error(f"Error loading correlation rules: {str(e)}")
    
    def correlation_worker(self):
        """Background worker for correlation processing"""
        while True:
            try:
                self.process_correlations()
                time.sleep(30)  # Run every 30 seconds
            except Exception as e:
                logger.error(f"Correlation worker error: {str(e)}")
                time.sleep(60)  # Wait longer on error

    def daily_scan_worker(self):
        """Run anomaly scan once per day at a fixed time."""
        while True:
            try:
                now = datetime.now()
                next_run = now.replace(hour=self.daily_scan_hour, minute=self.daily_scan_minute, second=0, microsecond=0)
                if next_run <= now:
                    next_run += timedelta(days=1)
                sleep_seconds = max((next_run - now).total_seconds(), 60)
                time.sleep(sleep_seconds)
                self.run_daily_anomaly_scan(triggered_by='scheduler')
            except Exception as e:
                logger.error(f"Daily scan scheduler error: {str(e)}")
                time.sleep(300)

    def run_daily_anomaly_scan(self, triggered_by='scheduler'):
        """Daily anomaly scan for any device ever connected."""
        created = 0
        scanned = 0
        window_hours = self.daily_scan_window_hours

        device_query = """
        SELECT id, ip_address, mac_address, hostname, last_seen
        FROM devices
        WHERE ip_address IS NOT NULL AND ip_address != ''
        """
        devices = db.execute_query(device_query, fetch=True) or []

        for device in devices:
            ip = device.get('ip_address')
            if not ip:
                continue
            scanned += 1

            alert_query = """
            SELECT severity, COUNT(*) as count
            FROM security_alerts
            WHERE (src_ip = %s OR dest_ip = %s)
            AND timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR)
            GROUP BY severity
            """
            severity_rows = db.execute_query(alert_query, (ip, ip, window_hours), fetch=True) or []
            if not severity_rows:
                continue

            counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            total_alerts = 0
            for row in severity_rows:
                sev = row.get('severity')
                cnt = int(row.get('count') or 0)
                if sev in counts:
                    counts[sev] = cnt
                total_alerts += cnt

            severity = 'low'
            if counts['critical'] > 0:
                severity = 'critical'
            elif counts['high'] > 0:
                severity = 'high'
            elif counts['medium'] >= self.daily_scan_medium_threshold:
                severity = 'medium'
            elif total_alerts >= self.daily_scan_low_threshold:
                severity = 'low'
            else:
                continue

            title = f"Daily Anomaly Scan {datetime.utcnow().strftime('%Y-%m-%d')} - {ip}"
            exists_query = """
            SELECT id FROM security_incidents
            WHERE title = %s AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            LIMIT 1
            """
            existing = db.execute_query(exists_query, (title,), fetch=True)
            if existing:
                continue

            recent_alerts_query = """
            SELECT alert_id, signature, severity, src_ip, dest_ip, timestamp
            FROM security_alerts
            WHERE (src_ip = %s OR dest_ip = %s)
            AND timestamp >= DATE_SUB(NOW(), INTERVAL %s HOUR)
            ORDER BY timestamp DESC
            LIMIT 20
            """
            alerts = db.execute_query(recent_alerts_query, (ip, ip, window_hours), fetch=True) or []

            incident_data = {
                'title': title,
                'description': f"Daily anomaly scan detected {total_alerts} alerts for device {ip} in the last {window_hours}h.",
                'severity': severity,
                'device': {
                    'ip_address': ip,
                    'mac_address': device.get('mac_address'),
                    'hostname': device.get('hostname'),
                    'last_seen': device.get('last_seen')
                },
                'alerts': alerts,
                'rule_id': None
            }
            self.create_security_incident(incident_data)
            created += 1

        return {
            'status': 'ok',
            'scanned_devices': scanned,
            'incidents_created': created,
            'window_hours': window_hours,
            'triggered_by': triggered_by
        }
    
    def process_correlations(self):
        """Process all correlation rules"""
        for rule in self.correlation_rules:
            try:
                self.process_correlation_rule(rule)
            except Exception as e:
                logger.error(f"Error processing rule {rule['rule_name']}: {str(e)}")
    
    def process_correlation_rule(self, rule):
        """Process a single correlation rule"""
        rule_type = rule['rule_type']
        conditions = json.loads(rule['condition_query'])
        
        if rule_type == 'vulnerability_traffic':
            self.correlate_vulnerability_traffic(rule, conditions)
        elif rule_type == 'anomaly_detection':
            self.correlate_anomaly_detection(rule, conditions)
        elif rule_type == 'threat_intelligence':
            self.correlate_threat_intelligence(rule, conditions)
        elif rule_type == 'behavioral':
            self.correlate_behavioral_analysis(rule, conditions)

    def get_condition(self, conditions, condition_type):
        if not isinstance(conditions, dict):
            return {}

        for condition in conditions.get('conditions', []):
            if condition.get('type') == condition_type:
                return condition

        return {}

    def correlate_vulnerability_traffic(self, rule, conditions):
        """Correlate vulnerabilities with network traffic alerts"""
        try:
            vuln_condition = self.get_condition(conditions, 'device_has_vulnerability')
            alert_condition = self.get_condition(conditions, 'network_alert_from_device')

            vuln_severities = vuln_condition.get('severity') or ['high', 'critical']
            alert_window = int(alert_condition.get('time_window', 3600))
            min_alert_count = int(alert_condition.get('min_alert_count', 1))

            severity_placeholders = ', '.join(['%s'] * len(vuln_severities))
            vuln_query = f"""
            SELECT DISTINCT d.id, d.ip_address, d.hostname, v.cve_id, v.severity, v.cvss_score
            FROM devices d
            JOIN device_vulnerabilities dv ON d.id = dv.device_id
            JOIN vulnerabilities v ON dv.vulnerability_id = v.id
            WHERE dv.status = 'open'
            AND v.severity IN ({severity_placeholders})
            AND d.last_seen >= DATE_SUB(NOW(), INTERVAL 1 DAY)
            """

            vulnerable_devices = db.execute_query(vuln_query, tuple(vuln_severities), fetch=True)
            if not vulnerable_devices:
                return

            for device in vulnerable_devices:
                count_query = """
                SELECT COUNT(*) as alert_count
                FROM security_alerts
                WHERE (src_ip = %s OR dest_ip = %s)
                AND timestamp >= DATE_SUB(NOW(), INTERVAL %s SECOND)
                AND status = 'open'
                """
                count_row = db.execute_query(
                    count_query,
                    (device['ip_address'], device['ip_address'], alert_window),
                    fetch=True
                ) or []
                alert_count = int(count_row[0]['alert_count']) if count_row else 0

                if alert_count < min_alert_count:
                    continue

                alerts_query = """
                SELECT alert_id, signature, severity, src_ip, dest_ip, timestamp
                FROM security_alerts
                WHERE (src_ip = %s OR dest_ip = %s)
                AND timestamp >= DATE_SUB(NOW(), INTERVAL %s SECOND)
                AND status = 'open'
                ORDER BY timestamp DESC
                LIMIT 20
                """
                alerts = db.execute_query(
                    alerts_query,
                    (device['ip_address'], device['ip_address'], alert_window),
                    fetch=True
                ) or []

                incident_data = {
                    'title': f"{rule['rule_name']} - {device['ip_address']}",
                    'description': (
                        f"Device {device['ip_address']} with vulnerability {device['cve_id']} "
                        f"triggered {alert_count} network alerts in the configured time window."
                    ),
                    'severity': rule.get('severity', 'high'),
                    'device': device,
                    'alerts': alerts,
                    'vulnerabilities': [{
                        'cve_id': device['cve_id'],
                        'severity': device['severity'],
                        'cvss_score': device['cvss_score']
                    }],
                    'rule_id': rule['id']
                }

                self.create_security_incident(incident_data)

        except Exception as e:
            logger.error(f"Vulnerability-traffic correlation error: {str(e)}")
    def correlate_threat_intelligence(self, rule, conditions):
        """Correlate network traffic with threat intelligence"""
        try:
            communication_condition = self.get_condition(conditions, 'communication_with_threat_ip')
            flow_window = int(communication_condition.get('time_window', 3600))
            min_flow_count = int(communication_condition.get('min_flow_count', 1))

            threat_query = """
            SELECT indicator, indicator_type, threat_type, confidence
            FROM threat_intelligence
            WHERE is_active = TRUE
            AND indicator_type = 'ip'
            """

            threat_indicators = db.execute_query(threat_query, fetch=True)
            if not threat_indicators:
                return

            for indicator in threat_indicators:
                threat_ip = indicator['indicator']

                count_query = """
                SELECT COUNT(*) as flow_count
                FROM traffic_flows
                WHERE (src_ip = %s OR dest_ip = %s)
                AND start_time >= DATE_SUB(NOW(), INTERVAL %s SECOND)
                """
                count_row = db.execute_query(count_query, (threat_ip, threat_ip, flow_window), fetch=True) or []
                flow_count = int(count_row[0]['flow_count']) if count_row else 0

                if flow_count < min_flow_count:
                    continue

                flow_query = """
                SELECT src_ip, dest_ip, src_port, dest_port, protocol, start_time, end_time, bytes_to_server, bytes_to_client
                FROM traffic_flows
                WHERE (src_ip = %s OR dest_ip = %s)
                AND start_time >= DATE_SUB(NOW(), INTERVAL %s SECOND)
                ORDER BY start_time DESC
                LIMIT 20
                """

                flows = db.execute_query(flow_query, (threat_ip, threat_ip, flow_window), fetch=True) or []

                incident_data = {
                    'title': f"{rule['rule_name']} - {threat_ip}",
                    'description': (
                        f"Detected {flow_count} communications with known malicious IP {threat_ip} "
                        f"({indicator['threat_type']})."
                    ),
                    'severity': rule.get('severity', 'critical'),
                    'threat_indicator': indicator,
                    'flows': flows,
                    'rule_id': rule['id']
                }

                self.create_security_incident(incident_data)

        except Exception as e:
            logger.error(f"Threat intelligence correlation error: {str(e)}")
    def correlate_anomaly_detection(self, rule, conditions):
        """Detect anomalous behavior patterns"""
        try:
            new_device_condition = self.get_condition(conditions, 'new_device_discovered')
            suspicious_condition = self.get_condition(conditions, 'suspicious_network_behavior')

            new_device_window = int(new_device_condition.get('time_window', 1800))
            suspicious_window = int(suspicious_condition.get('time_window', new_device_window or 1800))
            min_event_count = int(suspicious_condition.get('min_event_count', 100))

            new_device_query = """
            SELECT *
            FROM devices
            WHERE first_seen >= DATE_SUB(NOW(), INTERVAL %s SECOND)
            """

            new_devices = db.execute_query(new_device_query, (new_device_window,), fetch=True)
            if not new_devices:
                return

            for device in new_devices:
                count_query = """
                SELECT COUNT(*) as event_count
                FROM network_events
                WHERE (src_ip = %s OR dest_ip = %s)
                AND timestamp >= DATE_SUB(NOW(), INTERVAL %s SECOND)
                """

                count_row = db.execute_query(
                    count_query,
                    (device['ip_address'], device['ip_address'], suspicious_window),
                    fetch=True
                ) or []
                event_count = int(count_row[0]['event_count']) if count_row else 0

                if event_count < min_event_count:
                    continue

                event_query = """
                SELECT event_type, COUNT(*) as event_count
                FROM network_events
                WHERE (src_ip = %s OR dest_ip = %s)
                AND timestamp >= DATE_SUB(NOW(), INTERVAL %s SECOND)
                GROUP BY event_type
                ORDER BY event_count DESC
                """

                events = db.execute_query(
                    event_query,
                    (device['ip_address'], device['ip_address'], suspicious_window),
                    fetch=True
                ) or []

                incident_data = {
                    'title': f"{rule['rule_name']} - {device['ip_address']}",
                    'description': (
                        f"Newly discovered device {device['ip_address']} generated {event_count} "
                        f"network events in the configured time window."
                    ),
                    'severity': rule.get('severity', 'medium'),
                    'device': device,
                    'anomalous_events': events,
                    'rule_id': rule['id']
                }

                self.create_security_incident(incident_data)

        except Exception as e:
            logger.error(f"Anomaly detection correlation error: {str(e)}")
    def correlate_behavioral_analysis(self, rule, conditions):
        """Analyze device behavioral patterns"""
        try:
            behavioral_condition = self.get_condition(conditions, 'port_scanning_detected')
            behavior_window = int(behavioral_condition.get('time_window', 3600))
            min_port_count = int(behavioral_condition.get('min_port_count', 20))
            min_connection_attempts = int(behavioral_condition.get('min_connection_attempts', 100))

            scan_query = """
            SELECT src_ip, COUNT(DISTINCT dest_port) as port_count,
                   COUNT(*) as connection_attempts
            FROM traffic_flows
            WHERE start_time >= DATE_SUB(NOW(), INTERVAL %s SECOND)
            GROUP BY src_ip
            HAVING port_count >= %s AND connection_attempts >= %s
            """

            potential_scanners = db.execute_query(
                scan_query,
                (behavior_window, min_port_count, min_connection_attempts),
                fetch=True
            )

            for scanner in potential_scanners:
                incident_data = {
                    'title': f"{rule['rule_name']} - {scanner['src_ip']}",
                    'description': (
                        f"Device {scanner['src_ip']} attempted connections to {scanner['port_count']} ports "
                        f"with {scanner['connection_attempts']} connection attempts."
                    ),
                    'severity': rule.get('severity', 'medium'),
                    'scanning_behavior': scanner,
                    'rule_id': rule['id']
                }

                self.create_security_incident(incident_data)

        except Exception as e:
            logger.error(f"Behavioral analysis correlation error: {str(e)}")
    def create_security_incident(self, incident_data):
        """Create a new security incident"""
        try:
            incident_id = f"INC-{int(time.time())}"
            
            query = """
            INSERT INTO security_incidents (incident_id, title, description, severity,
                                          status, affected_devices, related_alerts,
                                          related_vulnerabilities, timeline)
            VALUES (%s, %s, %s, %s, 'open', %s, %s, %s, %s)
            """
            
            timeline = [{
                'timestamp': datetime.utcnow().isoformat(),
                'event': 'Incident created by correlation engine',
                'rule_id': incident_data.get('rule_id')
            }]
            
            params = (
                incident_id,
                incident_data['title'],
                incident_data['description'],
                incident_data['severity'],
                json.dumps(incident_data.get('device', {})),
                json.dumps(incident_data.get('alerts', [])),
                json.dumps(incident_data.get('vulnerabilities', [])),
                json.dumps(timeline)
            )
            
            db.execute_query(query, params)
            
            # Publish incident event
            redis_client.publish('security_events', json.dumps({
                'type': 'new_incident',
                'incident_id': incident_id,
                'severity': incident_data['severity'],
                'title': incident_data['title']
            }))
            
            logger.info(f"Created security incident: {incident_id}")
            
            # Update rule statistics
            self.update_rule_stats(incident_data.get('rule_id'))
            
        except Exception as e:
            logger.error(f"Error creating security incident: {str(e)}")
    
    def update_rule_stats(self, rule_id):
        """Update correlation rule statistics"""
        if not rule_id:
            return
            
        try:
            query = """
            UPDATE correlation_rules
            SET detection_count = detection_count + 1,
                last_triggered = CURRENT_TIMESTAMP
            WHERE id = %s
            """
            
            db.execute_query(query, (rule_id,))
            
        except Exception as e:
            logger.error(f"Error updating rule stats: {str(e)}")

# Initialize correlation engine
correlation_engine = CorrelationEngine()

# Flask routes
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        db.execute_query("SELECT 1", fetch=True)
        
        # Test Redis connection
        redis_client.ping()
        
        return jsonify({
            'status': 'healthy',
            'service': 'correlation-engine',
            'timestamp': datetime.utcnow().isoformat(),
            'active_rules': len(correlation_engine.correlation_rules)
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

@app.route('/incidents', methods=['GET', 'POST'])
def handle_incidents():
    """Handle security incidents"""
    if request.method == 'GET':
        try:
            query = """
            SELECT incident_id, title, description, severity, status, assigned_to,
                   affected_devices, related_alerts,
                   created_at, updated_at, closed_at
            FROM security_incidents
            ORDER BY created_at DESC
            LIMIT 100
            """

            incidents = db.execute_query(query, fetch=True)
            return jsonify({'incidents': incidents})

        except Exception as e:
            logger.error(f"Error fetching incidents: {str(e)}")
            return jsonify({'error': 'Failed to fetch incidents'}), 500

    elif request.method == 'POST':
        try:
            data = get_request_payload()
            incident_id = f"INC-{int(time.time())}"

            query = """
            INSERT INTO security_incidents (incident_id, title, description, severity,
                                          created_by, status)
            VALUES (%s, %s, %s, %s, %s, 'open')
            """

            params = (
                incident_id,
                data.get('title', ''),
                data.get('description', ''),
                data.get('severity', 'medium'),
                data.get('created_by', 'system')
            )

            db.execute_query(query, params)

            return jsonify({
                'incident_id': incident_id,
                'status': 'created'
            }), 201

        except Exception as e:
            logger.error(f"Error creating incident: {str(e)}")
            return jsonify({'error': 'Failed to create incident'}), 500


@app.route('/rules', methods=['GET', 'POST'])
def handle_correlation_rules():
    """Handle correlation rules"""
    if request.method == 'GET':
        try:
            query = """
            SELECT id, rule_name, rule_type, severity, enabled, description,
                   detection_count, last_triggered, created_at
            FROM correlation_rules
            ORDER BY created_at DESC
            """

            rules = db.execute_query(query, fetch=True)
            return jsonify({'rules': rules})

        except Exception as e:
            logger.error(f"Error fetching rules: {str(e)}")
            return jsonify({'error': 'Failed to fetch rules'}), 500

    elif request.method == 'POST':
        try:
            payload = get_request_payload()
            natural_language_rule = (
                payload.get('natural_language_rule')
                or payload.get('text')
                or payload.get('rule')
            )

            if natural_language_rule and not payload.get('rule_type'):
                data = translate_natural_language_rule(natural_language_rule)
                data['enabled'] = payload.get('enabled', True)
                data['created_by'] = payload.get('created_by', 'system')
            else:
                data = dict(payload)
                data['severity'] = data.get('severity', 'medium')
                data['condition_query'] = data.get('condition_query', {})
                validate_translated_rule(data)

            query = """
            INSERT INTO correlation_rules (rule_name, rule_type, condition_query,
                                         severity, description, enabled, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """

            params = (
                data.get('rule_name'),
                data.get('rule_type'),
                json.dumps(data.get('condition_query', {})),
                data.get('severity', 'medium'),
                data.get('description', ''),
                data.get('enabled', True),
                data.get('created_by', 'system')
            )

            db.execute_query(query, params)
            correlation_engine.load_correlation_rules()

            return jsonify({
                'status': 'rule created',
                'rule_name': data.get('rule_name'),
                'rule_type': data.get('rule_type'),
                'translation_type': 'correlation_rule' if natural_language_rule else 'structured_rule'
            }), 201

        except ValueError as e:
            logger.error(f"Rule validation error: {str(e)}")
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            logger.error(f"Error creating rule: {str(e)}")
            return jsonify({'error': 'Failed to create rule'}), 500

@app.route('/rules/translate', methods=['POST'])
def translate_correlation_rule():
    """Translate a natural-language rule into a structured correlation rule"""
    try:
        data = get_request_payload()
        natural_language_rule = (
            data.get('natural_language_rule')
            or data.get('text')
            or data.get('rule')
        )

        if not natural_language_rule:
            return jsonify({'error': 'natural_language_rule is required'}), 400

        translated = translate_natural_language_rule(natural_language_rule)
        return jsonify({
            'status': 'translated',
            'target': 'correlation-engine',
            'translation_type': 'correlation_rule',
            'warning': 'This translation is for the correlation engine, not a Suricata IDS signature.',
            'translation': translated
        })

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error translating rule: {str(e)}")
        return jsonify({'error': 'Failed to translate rule'}), 500
@app.route('/threat-intelligence', methods=['GET', 'POST'])
def handle_threat_intelligence():
    """Handle threat intelligence data"""
    if request.method == 'GET':
        try:
            query = """
            SELECT indicator, indicator_type, threat_type, malware_family,
                   confidence, source, first_seen, last_seen, is_active
            FROM threat_intelligence
            WHERE is_active = TRUE
            ORDER BY last_seen DESC
            LIMIT 1000
            """
            
            threat_intel = db.execute_query(query, fetch=True)
            return jsonify({'threat_intelligence': threat_intel})
            
        except Exception as e:
            logger.error(f"Error fetching threat intelligence: {str(e)}")
            return jsonify({'error': 'Failed to fetch threat intelligence'}), 500
    
    elif request.method == 'POST':
        try:
            data = get_request_payload()
            
            query = """
            INSERT INTO threat_intelligence (indicator, indicator_type, threat_type,
                                           malware_family, confidence, source, description)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            threat_type = VALUES(threat_type),
            confidence = VALUES(confidence),
            last_seen = CURRENT_TIMESTAMP
            """
            
            params = (
                data.get('indicator'),
                data.get('indicator_type'),
                data.get('threat_type', ''),
                data.get('malware_family', ''),
                data.get('confidence', 1.0),
                data.get('source', 'manual'),
                data.get('description', '')
            )
            
            db.execute_query(query, params)
            
            return jsonify({'status': 'threat intelligence added'}), 201
            
        except Exception as e:
            logger.error(f"Error adding threat intelligence: {str(e)}")
            return jsonify({'error': 'Failed to add threat intelligence'}), 500

@app.route('/dashboard/incidents', methods=['GET'])
def get_incident_dashboard():
    """Get incident dashboard data"""
    try:
        query = """
        SELECT 
            COUNT(*) as total_incidents,
            SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_incidents,
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_incidents,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_incidents,
            SUM(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 ELSE 0 END) as incidents_24h
        FROM security_incidents
        """
        
        result = db.execute_query(query, fetch=True)
        return jsonify(result[0] if result else {})
        
    except Exception as e:
        logger.error(f"Error fetching incident dashboard: {str(e)}")
        return jsonify({'error': 'Failed to fetch incident dashboard data'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true')









