from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import redis
import json
import os
import logging
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
    'password': os.getenv('DB_PASS', 'security_pass'),
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

class CorrelationEngine:
    def __init__(self):
        self.correlation_rules = []
        self.load_correlation_rules()
        
        # Start correlation thread
        self.correlation_thread = threading.Thread(target=self.correlation_worker, daemon=True)
        self.correlation_thread.start()
    
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
    
    def correlate_vulnerability_traffic(self, rule, conditions):
        """Correlate vulnerabilities with network traffic alerts"""
        try:
            # Find devices with high/critical vulnerabilities
            vuln_query = """
            SELECT DISTINCT d.id, d.ip_address, v.cve_id, v.severity, v.cvss_score
            FROM devices d
            JOIN device_vulnerabilities dv ON d.id = dv.device_id
            JOIN vulnerabilities v ON dv.vulnerability_id = v.id
            WHERE dv.status = 'open' 
            AND v.severity IN ('high', 'critical')
            AND d.last_seen >= DATE_SUB(NOW(), INTERVAL 1 DAY)
            """
            
            vulnerable_devices = db.execute_query(vuln_query, fetch=True)
            
            if not vulnerable_devices:
                return
            
            # Check for recent network alerts from these devices
            for device in vulnerable_devices:
                alert_query = """
                SELECT * FROM security_alerts
                WHERE (src_ip = %s OR dest_ip = %s)
                AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
                AND status = 'open'
                """
                
                alerts = db.execute_query(alert_query, (device['ip_address'], device['ip_address']), fetch=True)
                
                if alerts:
                    # Create security incident
                    incident_data = {
                        'title': f"Vulnerable Device Network Alert - {device['ip_address']}",
                        'description': f"Device with {device['severity']} vulnerability {device['cve_id']} has generated network security alerts",
                        'severity': 'high',
                        'device': device,
                        'alerts': alerts,
                        'rule_id': rule['id']
                    }
                    
                    self.create_security_incident(incident_data)
                    
        except Exception as e:
            logger.error(f"Vulnerability-traffic correlation error: {str(e)}")
    
    def correlate_threat_intelligence(self, rule, conditions):
        """Correlate network traffic with threat intelligence"""
        try:
            # Get active threat intel indicators
            threat_query = """
            SELECT indicator, indicator_type, threat_type, confidence
            FROM threat_intelligence
            WHERE is_active = TRUE
            AND indicator_type = 'ip'
            """
            
            threat_indicators = db.execute_query(threat_query, fetch=True)
            
            if not threat_indicators:
                return
            
            # Check for communications with threat IPs
            for indicator in threat_indicators:
                threat_ip = indicator['indicator']
                
                # Check traffic flows
                flow_query = """
                SELECT * FROM traffic_flows
                WHERE (src_ip = %s OR dest_ip = %s)
                AND start_time >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
                """
                
                flows = db.execute_query(flow_query, (threat_ip, threat_ip), fetch=True)
                
                if flows:
                    # Create high-priority incident
                    incident_data = {
                        'title': f"Communication with Threat Intelligence IP - {threat_ip}",
                        'description': f"Network communication detected with known malicious IP {threat_ip} ({indicator['threat_type']})",
                        'severity': 'critical',
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
            # Find recently discovered devices
            new_device_query = """
            SELECT * FROM devices
            WHERE first_seen >= DATE_SUB(NOW(), INTERVAL 30 MINUTE)
            """
            
            new_devices = db.execute_query(new_device_query, fetch=True)
            
            if not new_devices:
                return
            
            # Check for suspicious network behavior from new devices
            for device in new_devices:
                # Check for high volume of network events
                event_query = """
                SELECT COUNT(*) as event_count, event_type
                FROM network_events
                WHERE (src_ip = %s OR dest_ip = %s)
                AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
                GROUP BY event_type
                HAVING event_count > 100
                """
                
                events = db.execute_query(event_query, (device['ip_address'], device['ip_address']), fetch=True)
                
                if events:
                    incident_data = {
                        'title': f"Anomalous Traffic from New Device - {device['ip_address']}",
                        'description': f"Recently discovered device showing unusual network activity patterns",
                        'severity': 'medium',
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
            # This would implement more sophisticated behavioral analysis
            # For now, we'll implement a simple version
            
            # Find devices with unusual port scanning behavior
            scan_query = """
            SELECT src_ip, COUNT(DISTINCT dest_port) as port_count,
                   COUNT(*) as connection_attempts
            FROM traffic_flows
            WHERE start_time >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
            GROUP BY src_ip
            HAVING port_count > 20 AND connection_attempts > 100
            """
            
            potential_scanners = db.execute_query(scan_query, fetch=True)
            
            for scanner in potential_scanners:
                incident_data = {
                    'title': f"Potential Port Scanning Activity - {scanner['src_ip']}",
                    'description': f"Device attempting connections to {scanner['port_count']} ports with {scanner['connection_attempts']} attempts",
                    'severity': 'medium',
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
            data = request.get_json()
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
            data = request.get_json()
            
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
            
            # Reload rules
            correlation_engine.load_correlation_rules()
            
            return jsonify({'status': 'rule created'}), 201
            
        except Exception as e:
            logger.error(f"Error creating rule: {str(e)}")
            return jsonify({'error': 'Failed to create rule'}), 500

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
            data = request.get_json()
            
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