from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
import os
import logging

app = Flask(__name__)
CORS(app)

# Configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'unified-db'),
    'user': os.getenv('DB_USER', 'security_user'),
    'password': os.getenv('DB_PASS', 'security_pass'),
    'database': os.getenv('DB_NAME', 'unified_security')
}

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
                result = cursor.fetchall()
                return result
            else:
                conn.commit()
                return cursor.rowcount
                
        except Exception as e:
            logger.error(f"Database error: {str(e)}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()

db = DatabaseManager()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        db.execute_query("SELECT 1", fetch=True)
        
        return jsonify({
            'status': 'healthy',
            'timestamp': os.getenv('TIMESTAMP', 'unknown')
        })
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

@app.route('/traffic/flows', methods=['GET'])
def get_traffic_flows():
    """Get network traffic flows"""
    try:
        query = """
        SELECT flow_id, src_ip, dest_ip, src_port, dest_port, protocol,
               bytes_to_server, bytes_to_client, packets_to_server, packets_to_client,
               start_time, end_time, duration_seconds, state
        FROM traffic_flows
        ORDER BY start_time DESC
        LIMIT 100
        """
        
        flows = db.execute_query(query, fetch=True)
        return jsonify({'flows': flows})
        
    except Exception as e:
        logger.error(f"Error fetching traffic flows: {str(e)}")
        return jsonify({'error': 'Failed to fetch traffic flows'}), 500

@app.route('/alerts', methods=['GET'])
def get_alerts():
    """Get security alerts"""
    try:
        query = """
        SELECT alert_id, signature, severity, src_ip, dest_ip, src_port, dest_port,
               protocol, timestamp, rule_id, classification, message
        FROM security_alerts 
        ORDER BY timestamp DESC
        LIMIT 50
        """
        
        alerts = db.execute_query(query, fetch=True)
        return jsonify({'alerts': alerts})
        
    except Exception as e:
        logger.error(f"Error fetching alerts: {str(e)}")
        return jsonify({'error': 'Failed to fetch alerts'}), 500

if __name__ == '__main__':
    logger.info("Starting simplified Traffic Analyzer...")
    app.run(host='0.0.0.0', port=5002, debug=False)