from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import redis
import json
import os
import logging
from datetime import datetime
import threading
import grpc
from concurrent import futures
import time
import sys

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
                'password': os.getenv('DB_PASS', 'security_pass'),
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
    'password': os.getenv('DB_PASS', 'security_pass'),
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

class TrafficAnalyzer:
    def __init__(self):
        self.running = False
        self.analysis_thread = None
    
    def start_analysis(self):
        """Start traffic analysis"""
        if not self.running:
            self.running = True
            self.analysis_thread = threading.Thread(target=self.analyze_traffic, daemon=True)
            self.analysis_thread.start()
            logger.info("Traffic analysis started")
    
    def analyze_traffic(self):
        """Main traffic analysis loop - now monitors real network connections"""
        while self.running:
            try:
                # Monitor actual network connections instead of generating mock data
                self.monitor_real_connections()
                time.sleep(30)  # Check every 30 seconds
            except Exception as e:
                logger.error(f"Traffic analysis error: {str(e)}")
    
    def monitor_real_connections(self):
        """Monitor real network connections using host API"""
        try:
            import requests
            
            current_time = datetime.utcnow()
            logger.info(f"Monitoring real network connections at {current_time.strftime('%H:%M:%S')}")
            
            # Try to get connections from host API
            try:
                host_api_url = "http://host.docker.internal:5556"
                response = requests.get(f"{host_api_url}/connections", timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        connections = data.get('connections', [])
                        logger.info(f"Found {len(connections)} active network connections from host")
                        
                        # Log first connection to verify byte data
                        if connections:
                            first = connections[0]
                            logger.info(f"Sample connection: {first.get('src_ip')}:{first.get('src_port')} -> {first.get('dest_ip')}:{first.get('dest_port')} | bytes_sent={first.get('bytes_sent', 0)}, bytes_recv={first.get('bytes_recv', 0)}")
                        
                        for connection in connections:
                            connection['timestamp'] = current_time
                            self.save_real_traffic_flow(connection)
                            
                            # Publish to Redis for real-time updates
                            redis_client.publish('traffic_events', json.dumps({
                                'event_type': 'connection',
                                'src_ip': connection['src_ip'],
                                'dest_ip': connection['dest_ip'],
                                'src_port': connection['src_port'],
                                'dest_port': connection['dest_port'],
                                'protocol': connection['protocol'],
                                'state': connection['state'],
                                'timestamp': current_time.isoformat()
                            }))
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
    
    def save_real_traffic_flow(self, connection):
        """Save real traffic flow to database for dashboard"""
        try:
            import uuid
            # Generate a unique flow_id
            flow_id = f"flow_{str(uuid.uuid4())[:8]}"
            
            query = """
            INSERT INTO traffic_flows (flow_id, src_ip, dest_ip, src_port, dest_port, 
                                     protocol, bytes_to_server, bytes_to_client, 
                                     packets_to_server, packets_to_client, 
                                     start_time, end_time, duration_seconds, state)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
            end_time = VALUES(end_time),
            duration_seconds = VALUES(duration_seconds),
            state = VALUES(state)
            """
            
            # Get real byte and packet counts from host monitor (TShark data)
            bytes_sent = connection.get('bytes_sent', 0)
            bytes_recv = connection.get('bytes_recv', 0)
            packets_sent = connection.get('packets_sent', 1)
            packets_recv = connection.get('packets_recv', 1)
            
            params = (
                flow_id,
                connection.get('src_ip'),
                connection.get('dest_ip'),
                connection.get('src_port'),
                connection.get('dest_port'),
                connection.get('protocol', 'tcp'),
                bytes_sent,  # Real bytes from TShark
                bytes_recv,  # Real bytes from TShark
                packets_sent,  # Real packet count from TShark
                packets_recv,  # Real packet count from TShark
                connection.get('timestamp'),  # start_time
                connection.get('timestamp'),  # end_time (same as start for netstat snapshot)
                0,  # duration_seconds (unknown for netstat snapshot)
                connection.get('state', 'established')
            )
            
            db.execute_query(query, params)
            
        except Exception as e:
            logger.error(f"Error saving real traffic flow: {str(e)}")
    
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
        query = """
        SELECT alert_id, signature, severity, src_ip, dest_ip, src_port, dest_port,
               protocol, timestamp, status, acknowledged
        FROM security_alerts
        WHERE status = 'open'
        ORDER BY timestamp DESC
        LIMIT 100
        """
        
        alerts = db.execute_query(query, fetch=True)
        return jsonify({'alerts': alerts})
        
    except Exception as e:
        logger.error(f"Error fetching alerts: {str(e)}")
        return jsonify({'error': 'Failed to fetch alerts'}), 500

@app.route('/traffic/flows', methods=['GET'])
def get_traffic_flows():
    """Get network traffic flows"""
    try:
        query = """
        SELECT flow_id, src_ip, dest_ip, src_port, dest_port, protocol,
               bytes_to_server, bytes_to_client, packets_to_server, packets_to_client,
               start_time, end_time, duration_seconds, state
        FROM traffic_flows
        WHERE start_time >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
        ORDER BY start_time DESC
        LIMIT 100
        """
        
        flows = db.execute_query(query, fetch=True)
        return jsonify({'flows': flows})
        return jsonify({'flows': flows})
        
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
    app.run(host='0.0.0.0', port=5002, debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true')