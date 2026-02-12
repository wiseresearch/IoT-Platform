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
HOST_TRAFFIC_MONITOR = os.getenv('HOST_TRAFFIC_MONITOR_URL', 'http://host.docker.internal:5556')
HOST_SCANNER_API = os.getenv('HOST_SCANNER_API_URL', 'http://host.docker.internal:5555')

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

@app.route('/api/dhcp/devices', methods=['GET'])
def get_dhcp_devices():
    """Get DHCP fingerprint devices from host traffic monitor"""
    try:
        response = requests.get(f"{HOST_TRAFFIC_MONITOR}/dhcp/devices", timeout=10)
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"DHCP devices proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/dhcp/restart', methods=['POST'])
def restart_dhcp_capture():
    """Restart DHCP capture on host traffic monitor"""
    try:
        restart_response = requests.post(f"{HOST_TRAFFIC_MONITOR}/restart-capture", timeout=15)
        if restart_response.status_code == 200:
            return Response(
                restart_response.content,
                status=restart_response.status_code,
                content_type=restart_response.headers.get('content-type', 'application/json')
            )

        stop_response = requests.post(f"{HOST_TRAFFIC_MONITOR}/stop-capture", timeout=10)
        start_response = requests.post(f"{HOST_TRAFFIC_MONITOR}/start-capture", timeout=10)
        return jsonify({
            'status': 'restarted',
            'stop_status': stop_response.status_code,
            'start_status': start_response.status_code
        })
    except Exception as e:
        logger.error(f"DHCP restart error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/neighbors', methods=['GET'])
def get_neighbors():
    """Proxy ARP neighbors from host scanner API"""
    try:
        response = requests.get(f"{HOST_SCANNER_API}/neighbors", timeout=10)
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Neighbors proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/reachability', methods=['POST'])
def get_reachability():
    """Proxy active reachability checks to host scanner API"""
    try:
        payload = request.get_json(silent=True) or {}
        response = requests.post(f"{HOST_SCANNER_API}/reachability", json=payload, timeout=30)
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Reachability proxy error: {str(e)}")
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
        if response.ok:
            payload = response.json()
            if payload.get('vulnerabilities'):
                return Response(
                    response.content,
                    status=response.status_code,
                    content_type=response.headers.get('content-type', 'application/json')
                )
        else:
            payload = {}

        # Fallback: derive OS-based CVE correlations from DHCP devices
        version_threshold = int(os.getenv('VERSION_CONFIDENCE_THRESHOLD', '70'))
        dhcp_response = requests.get(f"{HOST_TRAFFIC_MONITOR}/dhcp/devices", timeout=10)
        dhcp_payload = dhcp_response.json() if dhcp_response.ok else {}
        dhcp_devices = dhcp_payload.get('devices', []) or []

        results = []
        os_summary_cache = {}

        for device in dhcp_devices:
            os_name = (device.get('os') or '').strip()
            os_version = (device.get('os_version') or '').strip()
            confidence = int(device.get('os_confidence') or 0)
            version_confidence = int(device.get('version_confidence') or 0)
            if not os_name or os_name.lower() == 'unknown' or confidence < 75:
                continue

            os_key = f"{os_name}::{os_version}"
            if os_key not in os_summary_cache:
                summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                last_checked = None
                explanation = "Passive OS-level correlation; not a confirmed vulnerability"
                correlation_mode = "os-level"
                cve_list = None
                use_version = os_version and os_version.lower() != 'unknown' and version_confidence >= version_threshold

                try:
                    summary_response = requests.post(
                        f"{VULNERABILITY_SERVICE}/os-summary",
                        json={
                            'os_name': os_name,
                            'os_version': os_version,
                            'version_confidence': version_confidence,
                            'include_cves': use_version
                        },
                        timeout=20
                    )
                    if summary_response.ok:
                        summary_payload = summary_response.json()
                        summary = summary_payload.get('summary', summary)
                        last_checked = summary_payload.get('last_checked')
                        correlation_mode = summary_payload.get('correlation_mode', correlation_mode)
                        cve_list = summary_payload.get('cve_list')
                    else:
                        explanation = "Passive OS-level correlation; OS mapping not supported"
                except Exception:
                    explanation = "Passive OS-level correlation; CVE lookup unavailable"

                if correlation_mode == "os-version-level":
                    explanation = "Passive OS-version correlation; not a confirmed vulnerability"
                os_summary_cache[os_key] = (summary, last_checked, explanation, correlation_mode, cve_list)

            summary, last_checked, explanation, correlation_mode, cve_list = os_summary_cache[os_key]
            detected_os = os_name + (f" {os_version}" if os_version else "")
            device_label = device.get('hostname') or device.get('mac_address') or device.get('ip_address') or 'Unknown'

            results.append({
                'affected_device': device_label,
                'detected_os': detected_os,
                'eligible': True,
                'os': os_name,
                'os_version': os_version or 'unknown',
                'os_confidence': confidence,
                'version_confidence': version_confidence,
                'correlation_mode': correlation_mode,
                'vulnerability_summary': summary,
                'last_checked': last_checked,
                'cve_list': cve_list,
                'correlation_explanation': explanation
            })

        return jsonify({'vulnerabilities': results})
    except Exception as e:
        logger.error(f"Vulnerabilities proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

# ============================================================================
# TRAFFIC ANALYZER ENDPOINTS
# ============================================================================

@app.route('/api/alerts', methods=['GET'])
# @auth_required  # Temporarily disabled for testing
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
