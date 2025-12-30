from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import requests
import os
import redis
import json
from datetime import datetime, timedelta
import jwt
from functools import wraps
import logging

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Configuration
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET', 'unified-security-platform-secret')
app.config['JWT_EXPIRATION_DELTA'] = timedelta(hours=24)

# Service URLs
VULNERABILITY_SERVICE = os.getenv('VULNERABILITY_SERVICE_URL', 'http://vulnerability-scanner:5001')
TRAFFIC_SERVICE = os.getenv('TRAFFIC_SERVICE_URL', 'http://traffic-analyzer:5002')
CORRELATION_SERVICE = os.getenv('CORRELATION_SERVICE_URL', 'http://correlation-engine:5003')

# Redis connection for caching and pub/sub
redis_client = redis.Redis(
    host=os.getenv('REDIS_HOST', 'redis'),
    port=6379,
    db=0,
    decode_responses=True
)

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Authentication decorator
def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            try:
                token = auth_header.split(" ")[1]  # Bearer <token>
            except IndexError:
                return jsonify({'message': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

# Rate limiting decorator
def rate_limit(max_requests=100, window=3600):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            client_ip = request.remote_addr
            key = f"rate_limit:{client_ip}:{f.__name__}"
            
            current_requests = redis_client.get(key)
            if current_requests is None:
                redis_client.setex(key, window, 1)
            else:
                if int(current_requests) >= max_requests:
                    return jsonify({'error': 'Rate limit exceeded'}), 429
                redis_client.incr(key)
            
            return f(*args, **kwargs)
        return decorated
    return decorator

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    services_status = {}
    
    # Check vulnerability service
    try:
        response = requests.get(f"{VULNERABILITY_SERVICE}/health", timeout=5)
        services_status['vulnerability-scanner'] = {
            'status': 'healthy' if response.status_code == 200 else 'unhealthy',
            'response_time': response.elapsed.total_seconds()
        }
    except Exception as e:
        services_status['vulnerability-scanner'] = {
            'status': 'unhealthy',
            'error': str(e)
        }
    
    # Check traffic service
    try:
        response = requests.get(f"{TRAFFIC_SERVICE}/health", timeout=5)
        services_status['traffic-analyzer'] = {
            'status': 'healthy' if response.status_code == 200 else 'unhealthy',
            'response_time': response.elapsed.total_seconds()
        }
    except Exception as e:
        services_status['traffic-analyzer'] = {
            'status': 'unhealthy',
            'error': str(e)
        }
    
    # Check correlation service
    try:
        response = requests.get(f"{CORRELATION_SERVICE}/health", timeout=5)
        services_status['correlation-engine'] = {
            'status': 'healthy' if response.status_code == 200 else 'unhealthy',
            'response_time': response.elapsed.total_seconds()
        }
    except Exception as e:
        services_status['correlation-engine'] = {
            'status': 'unhealthy',
            'error': str(e)
        }
    
    # Check Redis
    try:
        redis_client.ping()
        services_status['redis'] = {'status': 'healthy'}
    except Exception as e:
        services_status['redis'] = {'status': 'unhealthy', 'error': str(e)}
    
    overall_status = 'healthy' if all(
        service['status'] == 'healthy' for service in services_status.values()
    ) else 'degraded'
    
    return jsonify({
        'status': overall_status,
        'timestamp': datetime.utcnow().isoformat(),
        'services': services_status
    })

# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@app.route('/api/auth/login', methods=['POST'])
@rate_limit(max_requests=10, window=300)  # 10 requests per 5 minutes
def login():
    """Authenticate user and return JWT token"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        # Forward to vulnerability service for user authentication
        response = requests.post(
            f"{VULNERABILITY_SERVICE}/auth/login",
            json={'username': username, 'password': password},
            timeout=10
        )
        
        if response.status_code == 200:
            user_data = response.json()
            
            # Generate JWT token
            token_payload = {
                'user_id': user_data['user_id'],
                'username': username,
                'role': user_data['role'],
                'exp': datetime.utcnow() + app.config['JWT_EXPIRATION_DELTA']
            }
            
            token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
            
            return jsonify({
                'token': token,
                'user': user_data,
                'expires_at': token_payload['exp'].isoformat()
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500

# ============================================================================
# VULNERABILITY SCANNER ENDPOINTS
# ============================================================================

@app.route('/api/scans', methods=['GET', 'POST'])
@rate_limit()
def handle_scans():
    """Proxy requests to vulnerability scanner service"""
    try:
        if request.method == 'GET':
            response = requests.get(f"{VULNERABILITY_SERVICE}/scans", timeout=30)
        else:
            response = requests.post(
                f"{VULNERABILITY_SERVICE}/scans",
                json=request.get_json(),
                timeout=30
            )
        
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Scan proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/scans/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status and results"""
    try:
        response = requests.get(f"{VULNERABILITY_SERVICE}/scans/{scan_id}", timeout=30)
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Scan status error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/devices', methods=['GET'])
def get_devices():
    """Get discovered devices"""
    try:
        response = requests.get(f"{VULNERABILITY_SERVICE}/devices", timeout=30)
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Devices proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/test', methods=['GET'])
def test_endpoint():
    """Test endpoint without auth"""
    return jsonify({'message': 'Test successful', 'timestamp': datetime.utcnow().isoformat()})

@app.route('/api/vulnerabilities', methods=['GET'])
# @auth_required  # Temporarily disabled for testing
def get_vulnerabilities():
    """Get vulnerability data"""
    try:
        response = requests.get(f"{VULNERABILITY_SERVICE}/vulnerabilities", timeout=30)
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Vulnerabilities proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

# ============================================================================
# TRAFFIC ANALYZER ENDPOINTS
# ============================================================================

@app.route('/api/alerts', methods=['GET'])
@auth_required
def get_alerts():
    """Get security alerts from traffic analyzer"""
    try:
        response = requests.get(f"{TRAFFIC_SERVICE}/alerts", timeout=30)
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Alerts proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/traffic/flows', methods=['GET'])
# @auth_required  # Temporarily disabled for testing
def get_traffic_flows():
    """Get network traffic flows"""
    try:
        # Try to get data from traffic analyzer service first
        response = requests.get(f"{TRAFFIC_SERVICE}/traffic/flows", timeout=10)
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Traffic flows proxy error: {str(e)}, falling back to direct database access")
        
        # Fallback: Get data directly from database
        try:
            import mysql.connector
            
            # Database configuration - should match your vulnerability scanner
            db_config = {
                'host': os.getenv('DB_HOST', 'unified-db'),
                'user': os.getenv('DB_USER', 'security_user'), 
                'password': os.getenv('DB_PASS', 'security_pass'),
                'database': os.getenv('DB_NAME', 'unified_security')
            }
            
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)
            
            query = """
            SELECT flow_id, src_ip, dest_ip, src_port, dest_port, protocol,
                   bytes_to_server, bytes_to_client, packets_to_server, packets_to_client,
                   start_time, end_time, duration_seconds, state
            FROM traffic_flows
            ORDER BY start_time DESC
            LIMIT 100
            """
            
            cursor.execute(query)
            flows = cursor.fetchall()
            
            # Convert datetime objects to strings for JSON serialization
            for flow in flows:
                if flow.get('start_time'):
                    flow['start_time'] = flow['start_time'].isoformat()
                if flow.get('end_time'):
                    flow['end_time'] = flow['end_time'].isoformat()
            
            cursor.close()
            conn.close()
            
            return jsonify({'flows': flows})
            
        except Exception as db_error:
            logger.error(f"Database fallback error: {str(db_error)}")
            return jsonify({'error': 'Traffic service unavailable and database fallback failed'}), 503

@app.route('/api/traffic/stream')
@auth_required
def traffic_stream():
    """Real-time traffic stream"""
    def generate():
        pubsub = redis_client.pubsub()
        pubsub.subscribe('traffic_events')
        
        try:
            for message in pubsub.listen():
                if message['type'] == 'message':
                    yield f"data: {message['data']}\n\n"
        except Exception as e:
            logger.error(f"Traffic stream error: {str(e)}")
        finally:
            pubsub.close()
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        }
    )

# ============================================================================
# CORRELATION ENGINE ENDPOINTS
# ============================================================================

@app.route('/api/incidents', methods=['GET', 'POST'])
# @auth_required  # Temporarily disabled for testing
def handle_incidents():
    """Proxy requests to correlation engine for security incidents"""
    try:
        if request.method == 'GET':
            response = requests.get(f"{CORRELATION_SERVICE}/incidents", timeout=30)
        else:
            response = requests.post(
                f"{CORRELATION_SERVICE}/incidents",
                json=request.get_json(),
                timeout=30
            )
        
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Incidents proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/correlation/rules', methods=['GET', 'POST'])
@auth_required
def handle_correlation_rules():
    """Manage correlation rules"""
    try:
        if request.method == 'GET':
            response = requests.get(f"{CORRELATION_SERVICE}/rules", timeout=30)
        else:
            response = requests.post(
                f"{CORRELATION_SERVICE}/rules",
                json=request.get_json(),
                timeout=30
            )
        
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Correlation rules proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/threat-intelligence', methods=['GET'])
@auth_required
def get_threat_intelligence():
    """Get threat intelligence data"""
    try:
        response = requests.get(f"{CORRELATION_SERVICE}/threat-intelligence", timeout=30)
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Threat intelligence proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

# ============================================================================
# DASHBOARD ENDPOINTS
# ============================================================================

@app.route('/api/dashboard/overview', methods=['GET'])
# @auth_required  # Temporarily disabled for testing
def get_dashboard_overview():
    """Get consolidated dashboard data"""
    try:
        # Get data from all services in parallel
        import concurrent.futures
        
        def fetch_service_data(service_url, endpoint):
            try:
                response = requests.get(f"{service_url}/{endpoint}", timeout=10)
                return response.json() if response.status_code == 200 else {}
            except:
                return {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                'devices': executor.submit(fetch_service_data, VULNERABILITY_SERVICE, 'dashboard/devices'),
                'vulnerabilities': executor.submit(fetch_service_data, VULNERABILITY_SERVICE, 'dashboard/vulnerabilities'),
                'alerts': executor.submit(fetch_service_data, TRAFFIC_SERVICE, 'dashboard/alerts'),
                'incidents': executor.submit(fetch_service_data, CORRELATION_SERVICE, 'dashboard/incidents')
            }
            
            dashboard_data = {}
            for key, future in futures.items():
                dashboard_data[key] = future.result()
        
        return jsonify({
            'timestamp': datetime.utcnow().isoformat(),
            'data': dashboard_data
        })
        
    except Exception as e:
        logger.error(f"Dashboard overview error: {str(e)}")
        return jsonify({'error': 'Failed to fetch dashboard data'}), 500

# ============================================================================
# WEBSOCKET EVENTS
# ============================================================================

@app.route('/api/events/subscribe')
# @auth_required  # Temporarily disabled for testing
def subscribe_to_events():
    """Subscribe to real-time security events"""
    def generate():
        pubsub = redis_client.pubsub()
        pubsub.subscribe(['security_events', 'scan_updates', 'alert_updates'])
        
        try:
            for message in pubsub.listen():
                if message['type'] == 'message':
                    event_data = {
                        'channel': message['channel'],
                        'timestamp': datetime.utcnow().isoformat(),
                        'data': json.loads(message['data']) if message['data'] else {}
                    }
                    yield f"data: {json.dumps(event_data)}\n\n"
        except Exception as e:
            logger.error(f"Event stream error: {str(e)}")
        finally:
            pubsub.close()
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive'
        }
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true')