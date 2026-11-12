from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import redis
import json
import os
import logging
from datetime import datetime, timezone, timedelta
import threading
import grpc
from concurrent import futures
import time
import sys
import hashlib
import ipaddress

def wait_for_dependencies():
    """Wait for database and Redis to be ready"""
    max_retries = 30
    retry_delay = 2
    
    # Wait for database
    for attempt in range(max_retries):
        try:
            conn = mysql.connector.connect(**{
                'host': os.getenv('DB_HOST', 'unified-db'),
                'user': os.getenv('DB_USER', 'security_user'),
                'password': os.getenv('DB_PASS', 'change_me_db_password'),
                'database': os.getenv('DB_NAME', 'unified_security')
            })
            conn.close()
            print("Database connection successful")
            break
        except Exception as e:
            if attempt == max_retries - 1:
                print(f"Failed to connect to database after {max_retries} attempts: {str(e)}")
                sys.exit(1)
            print(f"Database connection attempt {attempt + 1} failed: {str(e)}")
            time.sleep(retry_delay)
    
    # Wait for Redis 
    redis_config = {
        'host': os.getenv('REDIS_HOST', 'redis'),
        'port': 6379,
        'db': 0
    }
    
    for attempt in range(max_retries):
        try:
            temp_redis = redis.Redis(**redis_config, decode_responses=True)
            temp_redis.ping()
            print("Redis connection successful")
            break
        except Exception as e:
            if attempt == max_retries - 1:
                print(f"Failed to connect to Redis after {max_retries} attempts: {str(e)}")
                sys.exit(1)
            print(f"Redis connection attempt {attempt + 1} failed: {str(e)}")
            time.sleep(retry_delay)

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


def normalize_ip(value):
    """Return a canonical IP string, or None for non-IP endpoints."""
    text = str(value or "").strip().strip("[]")
    if "%" in text:
        text = text.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


_flow_error_log_at = 0.0


def log_flow_error(message):
    """Avoid filling the container log with the same bad flow every 5s."""
    global _flow_error_log_at
    now = time.monotonic()
    if now - _flow_error_log_at >= 60:
        logger.error(message)
        _flow_error_log_at = now


SURICATA_SEVERITY_MAP = {
    1: 'critical',
    2: 'high',
    3: 'medium',
    4: 'low'
}


def parse_suricata_timestamp(value):
    if not value:
        return datetime.utcnow()

    text = str(value).strip()
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'

    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo:
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except Exception:
        logger.warning(f"Failed to parse Suricata timestamp '{value}', using current UTC time.")
        return datetime.utcnow()


def map_suricata_severity(alert_block):
    try:
        numeric = int((alert_block or {}).get('severity'))
    except (TypeError, ValueError):
        numeric = None

    if numeric in SURICATA_SEVERITY_MAP:
        return SURICATA_SEVERITY_MAP[numeric]

    signature = str((alert_block or {}).get('signature') or '').lower()
    category = str((alert_block or {}).get('category') or '').lower()
    combined = f"{signature} {category}"
    if 'critical' in combined:
        return 'critical'
    if 'high' in combined:
        return 'high'
    if 'medium' in combined:
        return 'medium'
    return 'low'


def normalize_suricata_action(alert_block):
    action = str((alert_block or {}).get('action') or 'alert').strip().lower()
    if action in ('drop', 'blocked', 'block'):
        return 'drop'
    if action in ('reject', 'rejected'):
        return 'reject'
    if action in ('pass', 'allowed', 'allow'):
        return 'pass'
    return 'alert'


def build_suricata_alert_id(event, alert_block):
    signature_id = alert_block.get('signature_id') or 'na'
    identity = json.dumps(
        {
            'timestamp': event.get('timestamp'),
            'flow_id': event.get('flow_id'),
            'signature_id': signature_id,
            'src_ip': event.get('src_ip'),
            'src_port': event.get('src_port'),
            'dest_ip': event.get('dest_ip'),
            'dest_port': event.get('dest_port'),
            'proto': event.get('proto'),
        },
        sort_keys=True,
        default=str
    )
    digest = hashlib.sha1(identity.encode('utf-8')).hexdigest()[:20]
    return f"suricata-{signature_id}-{digest}"


def build_suricata_alert_record(event):
    if not isinstance(event, dict) or event.get('event_type') != 'alert':
        return None

    alert_block = event.get('alert') or {}
    src_ip = event.get('src_ip')
    dest_ip = event.get('dest_ip')
    if not src_ip or not dest_ip:
        return None

    signature = str(alert_block.get('signature') or '').strip()
    if not signature:
        signature_id = alert_block.get('signature_id') or 'unknown'
        signature = f"Suricata SID {signature_id}"

    rule_id = alert_block.get('signature_id')
    try:
        rule_id = int(rule_id) if rule_id is not None else None
    except (TypeError, ValueError):
        rule_id = None

    return {
        'alert_id': build_suricata_alert_id(event, alert_block),
        'rule_id': rule_id,
        'signature': signature[:500],
        'category': (alert_block.get('category') or 'Suricata Alert')[:100],
        'severity': map_suricata_severity(alert_block),
        'src_ip': src_ip,
        'dest_ip': dest_ip,
        'src_port': event.get('src_port'),
        'dest_port': event.get('dest_port'),
        'protocol': str(event.get('proto') or event.get('app_proto') or '').lower()[:20] or None,
        'action_taken': normalize_suricata_action(alert_block),
        'timestamp': parse_suricata_timestamp(event.get('timestamp')),
        'metadata': event,
    }

class TrafficAnalyzer:
    def __init__(self):
        self.running = False
        self.analysis_thread = None
        self.eve_monitor_thread = None
        self.suricata_eve_enabled = os.getenv('SURICATA_EVE_MONITOR_ENABLED', 'true').lower() in ('1', 'true', 'yes')
        self.suricata_eve_file = os.getenv('SURICATA_EVE_FILE', '/var/log/suricata/eve.json')
        self.suricata_eve_poll_seconds = float(os.getenv('SURICATA_EVE_POLL_SECONDS', '1'))
        self.suricata_eve_start_position = os.getenv('SURICATA_EVE_START_POSITION', 'end').strip().lower()
        self.last_suricata_alert_at = None
        self.last_suricata_alert_id = None
    
    def start_analysis(self):
        """Start traffic analysis"""
        if not self.running:
            self.running = True
            self.analysis_thread = threading.Thread(target=self.analyze_traffic, daemon=True)
            self.analysis_thread.start()
            if self.suricata_eve_enabled:
                self.eve_monitor_thread = threading.Thread(target=self.monitor_suricata_eve, daemon=True)
                self.eve_monitor_thread.start()
            logger.info("Traffic analysis started")
    
    def analyze_traffic(self):
        """Main traffic analysis loop - now monitors real network connections"""
        while self.running:
            try:
                # Monitor actual network connections instead of generating mock data
                self.monitor_real_connections()
                time.sleep(float(os.getenv('TRAFFIC_POLL_SECONDS', '5')))
            except Exception as e:
                logger.error(f"Traffic analysis error: {str(e)}")
    
    def monitor_real_connections(self):
        """Monitor real network connections using host API"""
        current_flow_ids = None
        try:
            import requests

            current_time = datetime.utcnow()
            logger.debug(f"Monitoring real network connections at {current_time.strftime('%H:%M:%S')}")
            
            # Try to get connections from host API
            try:
                host_api_url = os.getenv('HOST_TRAFFIC_MONITOR_URL', 'http://host.docker.internal:5556')
                response = requests.get(f"{host_api_url}/connections", timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        connections = data.get('connections', [])
                        logger.debug(f"Found {len(connections)} active network connections from host")
                        current_flow_ids = []
                        
                        # Log first connection to verify byte data
                        if connections:
                            first = connections[0]
                            logger.debug(f"Sample connection: {first.get('src_ip')}:{first.get('src_port')} -> {first.get('dest_ip')}:{first.get('dest_port')} | bytes_sent={first.get('bytes_sent', 0)}, bytes_recv={first.get('bytes_recv', 0)}")
                        
                        for connection in connections:
                            connection['timestamp'] = current_time
                            flow_id = self.flow_id_for(connection)
                            # Only advertise flows that actually reached the DB;
                            # otherwise a rejected row keeps its old copy active
                            # forever because reconciliation thinks it still exists.
                            if not self.save_real_traffic_flow(connection):
                                continue
                            current_flow_ids.append(flow_id)
                            
                            # Publish to Redis for real-time updates
                            redis_client.publish('traffic_events', json.dumps({
                                'event_type': 'connection',
                                'src_ip': normalize_ip(connection.get('src_ip')),
                                'dest_ip': normalize_ip(connection.get('dest_ip')),
                                'src_port': connection.get('src_port'),
                                'dest_port': connection.get('dest_port'),
                                'protocol': connection.get('protocol'),
                                'state': connection.get('state'),
                                'timestamp': current_time.isoformat()
                            }))

                        # Reconcile exactly against this snapshot so the
                        # "active" table cannot accumulate closed sockets.
                        self.close_stale_flows(current_flow_ids)
                    else:
                        logger.warning(f"Host API returned error: {data.get('message')}")
                else:
                    logger.warning(f"Host API returned status {response.status_code}")
                    
            except requests.exceptions.ConnectionError:
                logger.warning("Cannot connect to host traffic monitor API (service not running on port 5556)")
            except requests.exceptions.Timeout:
                logger.warning("Host traffic monitor API timed out")
            except Exception as e:
                logger.warning(f"Could not get connections from host API: {str(e)}")
                
        except Exception as e:
            logger.error(f"Error monitoring real connections: {str(e)}")
        finally:
            # If no usable snapshot was received, age out rows by timestamp
            # instead of leaving sockets active forever after a monitor outage.
            if current_flow_ids is None:
                self.close_stale_flows(None)

    def monitor_suricata_eve(self):
        """Tail Suricata EVE logs and ingest alert events into security_alerts."""
        handle = None
        current_inode = None
        initial_seek_done = False

        while self.running:
            try:
                if not os.path.exists(self.suricata_eve_file):
                    time.sleep(self.suricata_eve_poll_seconds)
                    continue

                stat = os.stat(self.suricata_eve_file)
                needs_reopen = handle is None or current_inode != stat.st_ino
                is_truncated = handle is not None and handle.tell() > stat.st_size
                if needs_reopen or is_truncated:
                    if handle:
                        handle.close()
                    handle = open(self.suricata_eve_file, 'r', encoding='utf-8', errors='replace')
                    current_inode = stat.st_ino

                    if not initial_seek_done and self.suricata_eve_start_position == 'end':
                        handle.seek(0, os.SEEK_END)
                    else:
                        handle.seek(0)

                    initial_seek_done = True
                    logger.info(f"Monitoring Suricata EVE file: {self.suricata_eve_file}")

                line = handle.readline()
                if not line:
                    time.sleep(self.suricata_eve_poll_seconds)
                    continue

                self.process_suricata_eve_line(line)
            except Exception as e:
                logger.error(f"Suricata EVE monitor error: {str(e)}")
                time.sleep(max(self.suricata_eve_poll_seconds, 1))
        if handle:
            handle.close()

    def process_suricata_eve_line(self, line):
        try:
            event = json.loads((line or '').strip())
        except json.JSONDecodeError:
            return

        if event.get('event_type') != 'alert':
            return

        self.save_suricata_alert(event)

    def save_suricata_alert(self, event):
        """Persist a Suricata alert event to the unified security_alerts table."""
        alert = build_suricata_alert_record(event)
        if not alert:
            return

        try:
            query = """
            INSERT INTO security_alerts (
                alert_id, rule_id, signature, category, severity, src_ip, dest_ip,
                src_port, dest_port, protocol, action_taken, timestamp, metadata
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                signature = VALUES(signature),
                category = VALUES(category),
                severity = VALUES(severity),
                action_taken = VALUES(action_taken),
                metadata = VALUES(metadata),
                updated_at = CURRENT_TIMESTAMP
            """

            params = (
                alert['alert_id'],
                alert['rule_id'],
                alert['signature'],
                alert['category'],
                alert['severity'],
                alert['src_ip'],
                alert['dest_ip'],
                alert['src_port'],
                alert['dest_port'],
                alert['protocol'],
                alert['action_taken'],
                alert['timestamp'],
                json.dumps(alert['metadata'], default=str)
            )

            db.execute_query(query, params)
            self.last_suricata_alert_at = alert['timestamp'].isoformat()
            self.last_suricata_alert_id = alert['alert_id']

            redis_client.publish('traffic_events', json.dumps({
                'event_type': 'alert',
                'alert_id': alert['alert_id'],
                'signature': alert['signature'],
                'severity': alert['severity'],
                'src_ip': alert['src_ip'],
                'dest_ip': alert['dest_ip'],
                'src_port': alert['src_port'],
                'dest_port': alert['dest_port'],
                'protocol': alert['protocol'],
                'timestamp': self.last_suricata_alert_at,
            }))
        except Exception as e:
            logger.error(f"Error saving Suricata alert: {str(e)}")
    
    def parse_netstat_output(self, netstat_output, timestamp):
        """Parse netstat output to extract network connections"""
        connections = []
        
        try:
            lines = netstat_output.split('\n')
            for line in lines:
                # Look for TCP connections (established, listening)
                if 'tcp' in line.lower() and ('established' in line.lower() or 'listen' in line.lower()):
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            local_addr = parts[1] if len(parts) > 1 else ""
                            foreign_addr = parts[2] if len(parts) > 2 else ""
                            state = parts[3] if len(parts) > 3 else "UNKNOWN"
                            
                            # Parse local address
                            if ':' in local_addr:
                                local_ip, local_port = local_addr.rsplit(':', 1)
                                local_ip = local_ip.strip('[]')  # Remove IPv6 brackets
                            else:
                                continue
                                
                            # Parse foreign address  
                            if ':' in foreign_addr:
                                foreign_ip, foreign_port = foreign_addr.rsplit(':', 1)
                                foreign_ip = foreign_ip.strip('[]')  # Remove IPv6 brackets
                            else:
                                continue
                            
                            # Only include connections with real IPs (not 0.0.0.0, 127.0.0.1)
                            if (local_ip not in ['0.0.0.0', '127.0.0.1', '::1', '*'] and 
                                foreign_ip not in ['0.0.0.0', '127.0.0.1', '::1', '*'] and
                                state.upper() == 'ESTABLISHED'):
                                
                                connections.append({
                                    'src_ip': local_ip,
                                    'dest_ip': foreign_ip,
                                    'src_port': int(local_port) if local_port.isdigit() else 0,
                                    'dest_port': int(foreign_port) if foreign_port.isdigit() else 0,
                                    'protocol': 'tcp',
                                    'state': state.lower(),
                                    'timestamp': timestamp
                                })
                        except (ValueError, IndexError) as e:
                            continue  # Skip malformed lines
                            
        except Exception as e:
            logger.error(f"Error parsing netstat output: {str(e)}")
            
        return connections
    
    def save_network_event(self, event):
        """Save network event to database"""
        try:
            query = """
            INSERT INTO network_events (event_type, src_ip, dest_ip, src_port, 
                                      dest_port, protocol, timestamp, raw_data)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            params = (
                event.get('event_type'),
                event.get('src_ip'),
                event.get('dest_ip'),
                event.get('src_port'),
                event.get('dest_port'),
                event.get('protocol'),
                event.get('timestamp'),
                json.dumps(event)
            )
            
            db.execute_query(query, params)
            
        except Exception as e:
            logger.error(f"Error saving network event: {str(e)}")
    
    @staticmethod
    def flow_id_for(connection):
        """Stable flow id: monitor-provided, else deterministic 5-tuple hash."""
        flow_id = str(connection.get('flow_id') or '').strip()
        if flow_id:
            return flow_id
        import hashlib
        raw = "|".join(str(connection.get(k, '')) for k in (
            'protocol', 'src_ip', 'src_port', 'dest_ip', 'dest_port'))
        return "flow_" + hashlib.sha1(raw.encode('utf-8', 'replace')).hexdigest()[:16]

    def save_real_traffic_flow(self, connection):
        """Save a real flow; return True only when the row reached the DB."""
        try:
            # Reuse the host monitor's stable flow id so repeated polls update
            # the same row instead of inserting a new copy every 5 seconds.
            flow_id = self.flow_id_for(connection)[:100]
            src_ip = normalize_ip(connection.get('src_ip'))
            dest_ip = normalize_ip(connection.get('dest_ip'))
            if not src_ip or not dest_ip:
                log_flow_error(
                    "Skipping traffic flow with an invalid endpoint: "
                    f"src={connection.get('src_ip')!r} dest={connection.get('dest_ip')!r}"
                )
                return False

            def as_int(value, default=0):
                try:
                    return max(0, int(value))
                except (TypeError, ValueError):
                    return default

            def as_port(value):
                try:
                    port = int(value)
                    return port if 0 <= port <= 65535 else None
                except (TypeError, ValueError):
                    return None

            query = """
            INSERT INTO traffic_flows (flow_id, src_ip, dest_ip, src_port, dest_port, 
                                     protocol, bytes_to_server, bytes_to_client, 
                                     packets_to_server, packets_to_client, 
                                     start_time, end_time, duration_seconds, state)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            bytes_to_server = VALUES(bytes_to_server),
            bytes_to_client = VALUES(bytes_to_client),
            packets_to_server = VALUES(packets_to_server),
            packets_to_client = VALUES(packets_to_client),
            end_time = VALUES(end_time),
            duration_seconds = TIMESTAMPDIFF(SECOND, start_time, VALUES(end_time)),
            state = VALUES(state)
            """

            protocol = str(connection.get('protocol') or 'tcp').strip().lower()[:20] or 'tcp'
            state = str(connection.get('state') or 'established').strip()[:50] or 'established'
            timestamp = connection.get('timestamp') or datetime.utcnow()
            params = (
                flow_id,
                src_ip,
                dest_ip,
                as_port(connection.get('src_port')),
                as_port(connection.get('dest_port')),
                protocol,
                as_int(connection.get('bytes_sent', 0)),
                as_int(connection.get('bytes_recv', 0)),
                as_int(connection.get('packets_sent', 1), 1),
                as_int(connection.get('packets_recv', 1), 1),
                timestamp,  # start_time
                timestamp,  # end_time (same as start for a snapshot)
                0,          # duration_seconds is recalculated on update
                state
            )
            
            db.execute_query(query, params)
            return True
            
        except Exception as e:
            log_flow_error(f"Error saving real traffic flow: {str(e)}")
            return False

    def close_stale_flows(self, active_flow_ids=None):
        """Close flows absent from the latest host snapshot, or by age if no snapshot."""
        try:
            if active_flow_ids is not None:
                params = []
                placeholders = ''
                if active_flow_ids:
                    placeholders = ', '.join(['%s'] * len(active_flow_ids))
                    params = list(active_flow_ids)
                query = """
                UPDATE traffic_flows
                SET state = 'closed',
                    end_time = GREATEST(end_time, UTC_TIMESTAMP()),
                    duration_seconds = TIMESTAMPDIFF(SECOND, start_time, GREATEST(end_time, UTC_TIMESTAMP()))
                WHERE COALESCE(state, '') <> 'closed'
                """
                if placeholders:
                    query += f" AND flow_id NOT IN ({placeholders})"
                db.execute_query(query, tuple(params))
            else:
                db.execute_query(
                    """
                    UPDATE traffic_flows
                    SET state = 'closed',
                        end_time = GREATEST(end_time, UTC_TIMESTAMP()),
                        duration_seconds = TIMESTAMPDIFF(SECOND, start_time, GREATEST(end_time, UTC_TIMESTAMP()))
                    WHERE COALESCE(state, '') <> 'closed'
                      AND end_time < (UTC_TIMESTAMP() - INTERVAL 15 SECOND)
                    """
                )
        except Exception as e:
            logger.error(f"Error closing stale traffic flows: {str(e)}")
    
    def save_traffic_flow(self, flow):
        """Save traffic flow to database for dashboard"""
        try:
            import uuid
            # Generate a unique flow_id
            flow_id = f"flow_{str(uuid.uuid4())[:8]}"
            
            query = """
            INSERT INTO traffic_flows (flow_id, src_ip, dest_ip, src_port, dest_port, protocol,
                                     bytes_to_server, bytes_to_client, packets_to_server, 
                                     packets_to_client, start_time, end_time, duration_seconds, state)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            params = (
                flow_id,
                flow.get('src_ip'),
                flow.get('dest_ip'),
                flow.get('src_port'),
                flow.get('dest_port'),
                flow.get('protocol'),
                flow.get('bytes_to_server'),
                flow.get('bytes_to_client'),
                flow.get('packets_to_server'),
                flow.get('packets_to_client'),
                flow.get('start_time'),
                flow.get('end_time'),
                flow.get('duration_seconds'),
                flow.get('state')
            )
            
            db.execute_query(query, params)
            
        except Exception as e:
            logger.error(f"Error saving traffic flow: {str(e)}")

# Initialize traffic analyzer
traffic_analyzer = TrafficAnalyzer()

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
            'service': 'traffic-analyzer',
            'suricata_eve_enabled': traffic_analyzer.suricata_eve_enabled,
            'suricata_eve_file': traffic_analyzer.suricata_eve_file,
            'last_suricata_alert_at': traffic_analyzer.last_suricata_alert_at,
            'last_suricata_alert_id': traffic_analyzer.last_suricata_alert_id,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

@app.route('/alerts', methods=['GET'])
def get_alerts():
    """Get security alerts"""
    try:
        window_hours = request.args.get('window_hours', default=24, type=int) or 24
        window_hours = max(1, min(window_hours, 720))
        limit = request.args.get('limit', default=300, type=int) or 300
        limit = max(20, min(limit, 2000))
        include_closed = str(request.args.get('include_closed', '0')).lower() in ('1', 'true', 'yes')
        cutoff_time = datetime.utcnow() - timedelta(hours=window_hours)

        if include_closed:
            query = """
            SELECT alert_id, signature, severity, src_ip, dest_ip, src_port, dest_port,
                   protocol, timestamp, status, acknowledged
            FROM security_alerts
            WHERE timestamp >= %s
            ORDER BY timestamp DESC
            LIMIT %s
            """
            alerts = db.execute_query(query, (cutoff_time, limit), fetch=True)
        else:
            query = """
            SELECT alert_id, signature, severity, src_ip, dest_ip, src_port, dest_port,
                   protocol, timestamp, status, acknowledged
            FROM security_alerts
            WHERE status = 'open' AND timestamp >= %s
            ORDER BY timestamp DESC
            LIMIT %s
            """
            alerts = db.execute_query(query, (cutoff_time, limit), fetch=True)

        return jsonify({
            'alerts': alerts,
            'window_hours': window_hours,
            'limit': limit,
            'include_closed': include_closed
        })
        
    except Exception as e:
        logger.error(f"Error fetching alerts: {str(e)}")
        return jsonify({'error': 'Failed to fetch alerts'}), 500

@app.route('/traffic/flows', methods=['GET'])
def get_traffic_flows():
    """Get network traffic flows"""
    try:
        window_hours = request.args.get('window_hours', default=1, type=int) or 1
        window_hours = max(1, min(window_hours, 720))
        limit = request.args.get('limit', default=100, type=int) or 100
        limit = max(20, min(limit, 2000))
        include_closed = str(request.args.get('include_closed', 'false')).lower() in ('1', 'true', 'yes')
        cutoff_time = datetime.utcnow() - timedelta(hours=window_hours)

        query = """
        SELECT flow_id, src_ip, dest_ip, src_port, dest_port, protocol,
               bytes_to_server, bytes_to_client, packets_to_server, packets_to_client,
               start_time, end_time, duration_seconds, state
        FROM traffic_flows
        WHERE end_time >= %s
        """
        params = [cutoff_time]
        if not include_closed:
            query += " AND state IN ('established', 'ESTABLISHED', 'udp')"
        query += " ORDER BY end_time DESC LIMIT %s"
        params.append(limit)

        flows = db.execute_query(query, tuple(params), fetch=True)
        return jsonify({
            'flows': flows,
            'window_hours': window_hours,
            'limit': limit,
            'active_only': not include_closed,
            'count': len(flows or [])
        })
        
    except Exception as e:
        logger.error(f"Error fetching traffic flows: {str(e)}")
        return jsonify({'error': 'Failed to fetch traffic flows'}), 500

@app.route('/events/stream', methods=['GET'])
def event_stream():
    """Real-time event stream"""
    def generate():
        pubsub = redis_client.pubsub()
        pubsub.subscribe('traffic_events')
        
        try:
            for message in pubsub.listen():
                if message['type'] == 'message':
                    yield f"data: {message['data']}\n\n"
        except Exception as e:
            logger.error(f"Event stream error: {str(e)}")
        finally:
            pubsub.close()
    
    return app.response_class(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        }
    )

@app.route('/dashboard/alerts', methods=['GET'])
def get_alert_dashboard():
    """Get alert dashboard data"""
    try:
        query = """
        SELECT 
            COUNT(*) as total_alerts,
            SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_alerts,
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_alerts,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_alerts,
            SUM(CASE WHEN timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 ELSE 0 END) as alerts_24h
        FROM security_alerts
        """
        
        result = db.execute_query(query, fetch=True)
        return jsonify(result[0] if result else {})
        
    except Exception as e:
        logger.error(f"Error fetching alert dashboard: {str(e)}")
        return jsonify({'error': 'Failed to fetch alert dashboard data'}), 500

if __name__ == '__main__':
    # Wait for dependencies to be ready
    wait_for_dependencies()
    
    # Start traffic analysis
    traffic_analyzer.start_analysis()
    
    # Start Flask app
    app.run(host='0.0.0.0', port=5002,
            debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true',
            threaded=True, use_reloader=False)
