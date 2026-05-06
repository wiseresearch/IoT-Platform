from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import requests
import os
import redis
import json
import secrets
from datetime import datetime, timedelta
import jwt
from functools import wraps
import logging

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Configuration
# Use env-provided JWT secret; fallback is ephemeral per process to avoid publishing static secrets.
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET') or secrets.token_hex(32)
app.config['JWT_EXPIRATION_DELTA'] = timedelta(hours=24)

# Service URLs
VULNERABILITY_SERVICE = os.getenv('VULNERABILITY_SERVICE_URL', 'http://vulnerability-scanner:5001')
TRAFFIC_SERVICE = os.getenv('TRAFFIC_SERVICE_URL', 'http://traffic-analyzer:5002')
CORRELATION_SERVICE = os.getenv('CORRELATION_SERVICE_URL', 'http://correlation-engine:5003')
LOG_ANALYZER_SERVICE = os.getenv('LOG_LLM_ANALYZER_URL', 'http://log-llm-analyzer:5004')
NAT_ROUTER_SERVICE = os.getenv('NAT_ROUTER_SERVICE_URL', 'http://nat-router:5050')
HOST_TRAFFIC_MONITOR = os.getenv('HOST_TRAFFIC_MONITOR_URL', 'http://host.docker.internal:5556')
HOST_SCANNER_API = os.getenv('HOST_SCANNER_API_URL', 'http://host.docker.internal:5555')
SURICATA_TRANSLATION_PROXY_TIMEOUT = int(os.getenv('SURICATA_TRANSLATION_PROXY_TIMEOUT_SECONDS', '100'))

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

    # Check log analyzer service
    try:
        response = requests.get(f"{LOG_ANALYZER_SERVICE}/health", timeout=5)
        services_status['log-llm-analyzer'] = {
            'status': 'healthy' if response.status_code == 200 else 'unhealthy',
            'response_time': response.elapsed.total_seconds()
        }
    except Exception as e:
        services_status['log-llm-analyzer'] = {
            'status': 'unhealthy',
            'error': str(e)
        }

    # Check NAT router service
    try:
        response = requests.get(f"{NAT_ROUTER_SERVICE}/health", timeout=5)
        services_status['nat-router'] = {
            'status': 'healthy' if response.status_code == 200 else 'unhealthy',
            'response_time': response.elapsed.total_seconds()
        }
    except Exception as e:
        services_status['nat-router'] = {
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
@rate_limit(max_requests=300, window=60)
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

@app.route('/api/devices/manual-os', methods=['POST'])
def set_manual_os_version():
    """Proxy manual OS version updates to vulnerability scanner."""
    try:
        response = requests.post(
            f"{VULNERABILITY_SERVICE}/devices/manual-os",
            json=request.get_json(silent=True) or {},
            timeout=15
        )
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Manual OS proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/agent/report', methods=['POST'])
# @auth_required  # Temporarily disabled for testing
def agent_report():
    """Proxy agent-reported OS/version data to vulnerability scanner"""
    try:
        response = requests.post(
            f"{VULNERABILITY_SERVICE}/agent/report",
            json=request.get_json(silent=True) or {},
            timeout=10
        )
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Agent report proxy error: {str(e)}")
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

@app.route('/api/host-info', methods=['GET'])
def get_host_info():
    """Proxy host IP/MAC info from host scanner API"""
    try:
        response = requests.get(f"{HOST_SCANNER_API}/host-info", timeout=10)
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Host info proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/host-scanner/restart', methods=['POST'])
def restart_host_scanner():
    """Restart host scanner API service."""
    try:
        response = requests.post(f"{HOST_SCANNER_API}/restart", timeout=10)
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Host scanner restart error: {str(e)}")
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

@app.route('/api/suricata/rules', methods=['GET', 'POST'])
def handle_suricata_rules():
    """Proxy Suricata rule list/add operations to NAT router service."""
    try:
        if request.method == 'GET':
            response = requests.get(f"{NAT_ROUTER_SERVICE}/api/list-rules", timeout=15)
        else:
            response = requests.post(
                f"{NAT_ROUTER_SERVICE}/api/add-rule",
                json=request.get_json(silent=True) or {},
                timeout=15
            )
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Suricata rules proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/suricata/rules/remove', methods=['POST'])
def remove_suricata_rule():
    """Proxy Suricata rule removal by SID."""
    try:
        response = requests.post(
            f"{NAT_ROUTER_SERVICE}/api/remove-rule",
            json=request.get_json(silent=True) or {},
            timeout=15
        )
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Suricata rule removal proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/suricata/rules/translate', methods=['POST'])
def translate_suricata_rule():
    """Translate natural language into a Suricata rule via LLM service."""
    try:
        payload = request.get_json(silent=True) or {}
        response = requests.post(
            f"{LOG_ANALYZER_SERVICE}/suricata/translate-rule",
            json=payload,
            timeout=SURICATA_TRANSLATION_PROXY_TIMEOUT
        )
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except requests.exceptions.Timeout:
        logger.error(
            "Suricata rule translation proxy timed out after %ss",
            SURICATA_TRANSLATION_PROXY_TIMEOUT
        )
        return jsonify({
            'error': (
                'Suricata rule translation timed out before the AI service responded. '
                'Please retry, or shorten the prompt if Ollama is slow.'
            )
        }), 504
    except Exception as e:
        logger.error(f"Suricata rule translation proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/suricata/reload', methods=['POST'])
def reload_suricata():
    """Proxy Suricata reload command."""
    try:
        response = requests.post(f"{NAT_ROUTER_SERVICE}/api/reload-suricata", timeout=15)
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Suricata reload proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503


@app.route('/api/suricata/quarantine-events', methods=['GET'])
def get_suricata_quarantine_events():
    """Proxy Suricata quarantine events from NAT router."""
    try:
        response = requests.get(
            f"{NAT_ROUTER_SERVICE}/api/quarantine-events",
            params={
                'limit': request.args.get('limit', '25'),
                'ip': request.args.get('ip', ''),
            },
            timeout=15
        )
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Suricata quarantine events proxy error: {str(e)}")
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
        force_refresh = str(request.args.get('force_refresh', '0')).lower() in ('1', 'true', 'yes')
        base_vulns = []
        try:
            response = requests.get(
                f"{VULNERABILITY_SERVICE}/vulnerabilities",
                params={'force_refresh': '1' if force_refresh else '0'},
                timeout=30
            )
            if response.ok:
                payload = response.json()
                base_vulns = payload.get('vulnerabilities', []) or []
        except Exception:
            base_vulns = []

        # Always merge DHCP devices so all connected devices appear
        version_threshold = int(os.getenv('VERSION_CONFIDENCE_THRESHOLD', '70'))
        dhcp_response = requests.get(f"{HOST_TRAFFIC_MONITOR}/dhcp/devices", timeout=10)
        dhcp_payload = dhcp_response.json() if dhcp_response.ok else {}
        dhcp_devices = dhcp_payload.get('devices', []) or []

        def normalize_mac(value):
            if not value:
                return ''
            return value.strip().lower().replace('-', ':')

        def normalize_text(value):
            return (value or '').strip()

        def network_prefix(ip):
            if not ip:
                return ''
            parts = str(ip).split('.')
            if len(parts) != 4:
                return ''
            try:
                int_parts = [int(p) for p in parts]
            except ValueError:
                return ''
            return f"{int_parts[0]}.{int_parts[1]}.{int_parts[2]}.0/24"

        def vuln_key(item):
            mac = normalize_mac(item.get('mac_address') or '')
            if mac:
                return f"mac:{mac}"
            hostname = normalize_text(item.get('hostname') or '').lower()
            if hostname and hostname != '-':
                return f"host:{hostname}"
            ip = normalize_text(item.get('ip_address') or '')
            if ip and ip != '-':
                return f"ip:{ip}"
            affected = normalize_text(item.get('affected_device') or '').lower()
            if affected and affected != 'unknown':
                return f"dev:{affected}"
            return f"row:{item.get('device_id') or item.get('id') or id(item)}"

        def merge_item(existing, incoming):
            merged = dict(existing)
            for field in (
                'ip_address', 'mac_address', 'hostname', 'vendor',
                'device_type', 'network_prefix', 'detected_os'
            ):
                if not merged.get(field) and incoming.get(field):
                    merged[field] = incoming.get(field)
            return merged

        results_map = {}
        for item in base_vulns:
            key = vuln_key(item)
            results_map[key] = item

        os_summary_cache = {}
        for device in dhcp_devices:
            os_name = (device.get('os') or '').strip()
            os_version = (device.get('os_version') or '').strip()
            confidence = int(device.get('os_confidence') or 0)
            version_confidence = int(device.get('version_confidence') or 0)
            eligible = bool(os_name) and os_name.lower() != 'unknown' and confidence >= 75

            summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            last_checked = None
            explanation = "OS unknown or low confidence; CVE correlation skipped"
            correlation_mode = "none"
            cve_list = None
            detected_os = os_name + (f" {os_version}" if os_version else "")

            if eligible:
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
                                # Always ask for CVE list so UI can show examples
                                'include_cves': True,
                                'force_refresh': force_refresh
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

            device_label = device.get('hostname') or device.get('mac_address') or device.get('ip_address') or 'Unknown'
            item = {
                'affected_device': device_label,
                'detected_os': detected_os,
                'eligible': eligible,
                'os': os_name,
                'os_version': os_version or 'unknown',
                'os_confidence': confidence,
                'version_confidence': version_confidence,
                'correlation_mode': correlation_mode,
                'vulnerability_summary': summary,
                'last_checked': last_checked,
                'cve_list': cve_list,
                'correlation_explanation': explanation,
                'ip_address': device.get('ip_address'),
                'mac_address': device.get('mac_address'),
                'hostname': device.get('hostname'),
                'vendor': device.get('vendor_class') or device.get('vendor') or '',
                'device_type': device.get('device_type') or 'DHCP Fingerprint',
                'network_prefix': network_prefix(device.get('ip_address'))
            }

            key = vuln_key(item)
            if key in results_map:
                results_map[key] = merge_item(results_map[key], item)
            else:
                results_map[key] = item

        return jsonify({'vulnerabilities': list(results_map.values())})
    except Exception as e:
        logger.error(f"Vulnerabilities proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/cve/<cve_id>', methods=['GET'])
def get_cve_details(cve_id):
    """Proxy CVE detail lookup to vulnerability scanner"""
    try:
        response = requests.get(f"{VULNERABILITY_SERVICE}/cve/{cve_id}", timeout=20)
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"CVE proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/cve/<cve_id>/remediation', methods=['GET'])
def get_cve_remediation(cve_id):
    """Proxy CVE remediation lookup to vulnerability scanner"""
    try:
        response = requests.get(
            f"{VULNERABILITY_SERVICE}/cve/{cve_id}/remediation",
            params=request.args,
            timeout=30
        )
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"CVE remediation proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/cve/source-status', methods=['GET'])
def get_cve_source_status():
    """Proxy CVE source reachability/freshness status."""
    try:
        response = requests.get(
            f"{VULNERABILITY_SERVICE}/cve/source-status",
            params=request.args,
            timeout=20
        )
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"CVE source status proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

# ============================================================================
# TRAFFIC ANALYZER ENDPOINTS
# ============================================================================

@app.route('/api/logs/analysis', methods=['POST'])
def run_logs_analysis():
    """Run LLM-driven logs analysis."""
    try:
        response = requests.post(
            f"{LOG_ANALYZER_SERVICE}/logs/analyze",
            json=request.get_json(silent=True) or {},
            timeout=120
        )
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Logs analysis proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/logs/analysis/latest', methods=['GET'])
def get_latest_logs_analysis():
    """Get latest LLM logs analysis report."""
    try:
        response = requests.get(f"{LOG_ANALYZER_SERVICE}/logs/analysis/latest", timeout=20)
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Latest logs analysis proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/agent/run', methods=['POST'])
def run_ai_agent():
    """Run the AI security agent workflow."""
    try:
        response = requests.post(
            f"{LOG_ANALYZER_SERVICE}/agent/run",
            json=request.get_json(silent=True) or {},
            timeout=120
        )
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"AI agent run proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/agent/train', methods=['POST'])
def train_ai_agent():
    """Train/update the AI agent SVM model."""
    try:
        response = requests.post(
            f"{LOG_ANALYZER_SERVICE}/agent/train",
            json=request.get_json(silent=True) or {},
            timeout=180
        )
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"AI agent train proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/agent/status', methods=['GET'])
def get_ai_agent_status():
    """Get AI agent status and model metadata."""
    try:
        response = requests.get(f"{LOG_ANALYZER_SERVICE}/agent/status", timeout=20)
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"AI agent status proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

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
                'password': os.getenv('DB_PASS', 'change_me_db_password'),
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

@app.route('/api/incidents/scan', methods=['POST'])
def run_incident_scan():
    """Proxy manual anomaly scan trigger to correlation engine"""
    try:
        response = requests.post(f"{CORRELATION_SERVICE}/incidents/scan", timeout=60)
        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Incident scan proxy error: {str(e)}")
        return jsonify({'error': 'Service unavailable'}), 503

@app.route('/api/correlation/rules', methods=['GET', 'POST'])
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


@app.route('/api/correlation/rules/translate', methods=['POST'])
def translate_correlation_rule():
    """Translate a natural-language correlation rule"""
    try:
        response = requests.post(
            f"{CORRELATION_SERVICE}/rules/translate",
            json=request.get_json(),
            timeout=30
        )

        return Response(
            response.content,
            status=response.status_code,
            content_type=response.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.error(f"Correlation rule translation proxy error: {str(e)}")
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


@app.route('/api/siem/posture', methods=['GET'])
def get_siem_posture():
    """Return SIEM implementation posture aligned with best-practice checkpoints."""
    try:
        os_threshold = int(os.getenv('SIEM_OS_CONFIDENCE_THRESHOLD', '75'))
        version_threshold = int(os.getenv('SIEM_VERSION_CONFIDENCE_THRESHOLD', '75'))

        def safe_get(url, timeout=10):
            try:
                response = requests.get(url, timeout=timeout)
                payload = {}
                try:
                    payload = response.json()
                except Exception:
                    payload = {}
                return {
                    'ok': response.status_code == 200,
                    'status_code': response.status_code,
                    'payload': payload
                }
            except Exception as e:
                return {
                    'ok': False,
                    'status_code': None,
                    'payload': {},
                    'error': str(e)
                }

        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = {
                'vuln_health': executor.submit(safe_get, f"{VULNERABILITY_SERVICE}/health", 8),
                'traffic_health': executor.submit(safe_get, f"{TRAFFIC_SERVICE}/health", 8),
                'corr_health': executor.submit(safe_get, f"{CORRELATION_SERVICE}/health", 8),
                'agent_health': executor.submit(safe_get, f"{LOG_ANALYZER_SERVICE}/health", 8),
                'nat_health': executor.submit(safe_get, f"{NAT_ROUTER_SERVICE}/health", 8),
                'devices': executor.submit(safe_get, f"{VULNERABILITY_SERVICE}/devices", 20),
                'vulns': executor.submit(safe_get, f"{VULNERABILITY_SERVICE}/vulnerabilities", 30),
                'alerts': executor.submit(safe_get, f"{TRAFFIC_SERVICE}/alerts", 20),
                'incidents': executor.submit(safe_get, f"{CORRELATION_SERVICE}/incidents", 20),
                'agent_status': executor.submit(safe_get, f"{LOG_ANALYZER_SERVICE}/agent/status", 20)
            }
            result = {name: future.result() for name, future in futures.items()}

        service_checks = {
            'vulnerability_scanner': result['vuln_health'],
            'traffic_analyzer': result['traffic_health'],
            'correlation_engine': result['corr_health'],
            'log_llm_analyzer': result['agent_health'],
            'nat_router': result['nat_health']
        }
        healthy_services = sum(1 for item in service_checks.values() if item.get('ok'))

        redis_status = 'healthy'
        redis_error = None
        try:
            redis_client.ping()
        except Exception as e:
            redis_status = 'unhealthy'
            redis_error = str(e)

        devices = result['devices'].get('payload', {}).get('devices', []) or []
        vulnerabilities = result['vulns'].get('payload', {}).get('vulnerabilities', []) or []
        alerts = result['alerts'].get('payload', {}).get('alerts', []) or []
        incidents = result['incidents'].get('payload', {}).get('incidents', []) or []

        def non_empty(value):
            return value not in (None, '', '-', 'N/A', 'unknown', 'Unknown')

        total_devices = len(devices)
        online_devices = sum(1 for d in devices if str(d.get('status', '')).lower() == 'online')
        with_mac = sum(1 for d in devices if non_empty(d.get('mac_address')))
        with_os = sum(1 for d in devices if non_empty(d.get('os_name')))
        high_conf_os = sum(1 for d in devices if int(d.get('os_confidence') or 0) >= os_threshold)
        version_ready = sum(
            1 for d in devices
            if int(d.get('os_confidence') or 0) >= os_threshold
            and int(d.get('version_confidence') or 0) >= version_threshold
            and non_empty(d.get('os_version'))
        )

        eligible_rows = sum(1 for row in vulnerabilities if bool(row.get('eligible')))
        os_level_rows = sum(1 for row in vulnerabilities if row.get('correlation_mode') == 'os-level')
        os_version_rows = sum(1 for row in vulnerabilities if row.get('correlation_mode') == 'os-version-level')

        severity_totals = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for row in vulnerabilities:
            summary = row.get('vulnerability_summary') or {}
            for sev in severity_totals.keys():
                severity_totals[sev] += int(summary.get(sev) or 0)

        open_incidents = sum(1 for i in incidents if str(i.get('status', '')).lower() == 'open')
        critical_incidents = sum(1 for i in incidents if str(i.get('severity', '')).lower() == 'critical')
        high_incidents = sum(1 for i in incidents if str(i.get('severity', '')).lower() == 'high')
        open_alerts = sum(1 for a in alerts if str(a.get('status', 'open')).lower() == 'open')

        agent_status_payload = result['agent_status'].get('payload', {}) or {}
        ai_agent = {
            'service_ok': result['agent_status'].get('ok', False),
            'model_trained': bool(agent_status_payload.get('model_trained')),
            'last_run_at': agent_status_payload.get('last_run_at'),
            'llm_enabled': bool(agent_status_payload.get('llm_enabled', False))
        }

        recommendations = []
        if total_devices == 0:
            recommendations.append("No assets are currently visible. Validate capture sources and onboarding scope.")
        if healthy_services < len(service_checks):
            recommendations.append("One or more SIEM services are unhealthy. Fix service health before tuning detections.")
        if high_conf_os == 0 and total_devices > 0:
            recommendations.append("OS confidence is low across visible assets. Improve passive fingerprint quality.")
        if eligible_rows == 0 and with_os > 0:
            recommendations.append("CVE correlation has no eligible rows. Check confidence thresholds and OS mapping.")
        if os_version_rows == 0 and high_conf_os > 0:
            recommendations.append("No version-level correlation yet. Improve OS version inference coverage.")

        return jsonify({
            'status': 'ok',
            'generated_at': datetime.utcnow().isoformat(),
            'source': {
                'best_practice_references': [
                    'https://www.connectwise.com/platform/siem',
                    'https://www.paloaltonetworks.com/cyberpedia/what-are-SIEM-implementation-best-practices'
                ],
                'note': 'This posture is passive SIEM alignment telemetry, not proof of compromise.'
            },
            'service_health': {
                'healthy_services': healthy_services,
                'total_services': len(service_checks),
                'services': {
                    name: {
                        'status': 'healthy' if item.get('ok') else 'unhealthy',
                        'status_code': item.get('status_code'),
                        'error': item.get('error')
                    }
                    for name, item in service_checks.items()
                },
                'redis': {
                    'status': redis_status,
                    'error': redis_error
                }
            },
            'asset_visibility': {
                'total_devices': total_devices,
                'online_devices': online_devices,
                'with_mac': with_mac,
                'with_os': with_os,
                'high_confidence_os': high_conf_os,
                'version_ready_devices': version_ready,
                'os_confidence_threshold': os_threshold,
                'version_confidence_threshold': version_threshold
            },
            'detection_and_response': {
                'open_alerts': open_alerts,
                'open_incidents': open_incidents,
                'critical_incidents': critical_incidents,
                'high_incidents': high_incidents
            },
            'cve_correlation': {
                'rows_total': len(vulnerabilities),
                'rows_eligible': eligible_rows,
                'os_level_rows': os_level_rows,
                'os_version_level_rows': os_version_rows,
                'severity_totals': severity_totals,
                'note': 'CVE data is OS/OS-version correlation only, not confirmed exploitation.'
            },
            'ai_agent': ai_agent,
            'recommendations': recommendations
        })
    except Exception as e:
        logger.error(f"SIEM posture endpoint error: {str(e)}")
        return jsonify({'error': 'Failed to build SIEM posture'}), 500

# ============================================================================
# WEBSOCKET EVENTS
# ============================================================================

@app.route('/api/events/subscribe')
# @auth_required  # Temporarily disabled for testing
def subscribe_to_events():
    """Subscribe to real-time security events"""
    def generate():
        pubsub = redis_client.pubsub()
        pubsub.subscribe(['security_events', 'scan_updates', 'alert_updates', 'traffic_events'])
        
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

