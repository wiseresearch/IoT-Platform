from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import requests
import os
import redis
import json
import secrets
import concurrent.futures
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
vulnerabilities_cache = {
    'items': [],
    'updated_at': None
}
device_cve_alerts_cache = {
    'items': [],
    'updated_at': None
}

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
    """Get vulnerability data (fast proxy + stale cache fallback)."""
    global vulnerabilities_cache
    force_refresh = str(request.args.get('force_refresh', '0')).lower() in ('1', 'true', 'yes')
    try:
        response = requests.get(
            f"{VULNERABILITY_SERVICE}/vulnerabilities",
            params={'force_refresh': '1' if force_refresh else '0'},
            timeout=25
        )
        if response.ok:
            payload = response.json() or {}
            items = payload.get('vulnerabilities', []) or []
            vulnerabilities_cache = {
                'items': items,
                'updated_at': datetime.utcnow().isoformat()
            }
            return jsonify({'vulnerabilities': items})

        logger.warning(f"Vulnerability scanner returned status {response.status_code}; using cache if available")
    except Exception as e:
        logger.error(f"Vulnerabilities proxy error: {str(e)}")

    # Fallback to the last successful response instead of returning empty.
    cached_items = vulnerabilities_cache.get('items') or []
    if cached_items:
        return jsonify({
            'vulnerabilities': cached_items,
            'cache_mode': 'stale-fallback',
            'cached_at': vulnerabilities_cache.get('updated_at')
        })

    # Last-resort fallback: derive minimal per-device rows from local device-alerts.
    try:
        alerts_resp = requests.get(
            f"{VULNERABILITY_SERVICE}/vulnerabilities/device-alerts",
            params={'limit': 500},
            timeout=10
        )
        if alerts_resp.ok:
            alerts_payload = alerts_resp.json() or {}
            alerts = alerts_payload.get('alerts') or []
            by_device = {}
            for row in alerts:
                ip = row.get('device_ip') or ''
                hostname = row.get('hostname') or ''
                mac = row.get('mac_address') or ''
                key = (str(mac).strip().lower() or str(ip).strip().lower() or str(hostname).strip().lower() or 'unknown')
                item = by_device.get(key)
                if not item:
                    item = {
                        'device_id': row.get('device_id'),
                        'ip_address': ip,
                        'hostname': hostname,
                        'mac_address': mac,
                        'affected_device': hostname or mac or ip or 'Unknown',
                        'detected_os': 'Unknown',
                        'eligible': False,
                        'last_checked': row.get('time'),
                        'correlation_explanation': 'Derived from local CVE status records while correlation service is unavailable.',
                        'vulnerability_summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                        'cve_list': []
                    }
                    by_device[key] = item
                severity = str(row.get('severity') or '').strip().lower()
                if severity in item['vulnerability_summary']:
                    item['vulnerability_summary'][severity] += 1
                cve_id = str(row.get('cve_id') or '').strip().upper()
                if cve_id and cve_id not in item['cve_list']:
                    item['cve_list'].append(cve_id)
            synthesized = list(by_device.values())
            if synthesized:
                vulnerabilities_cache = {
                    'items': synthesized,
                    'updated_at': datetime.utcnow().isoformat()
                }
                return jsonify({
                    'vulnerabilities': synthesized,
                    'cache_mode': 'derived-from-device-alerts',
                    'cached_at': vulnerabilities_cache.get('updated_at')
                })
    except Exception as fallback_error:
        logger.warning(f"Vulnerabilities fallback synthesis failed: {str(fallback_error)}")

    return jsonify({'vulnerabilities': [], 'cache_mode': 'empty'})


@app.route('/api/vulnerabilities/device-alerts', methods=['GET'])
def get_device_cve_alerts():
    """Return per-device CVE alerts (correlated CVEs + local fixed status when available)."""
    global device_cve_alerts_cache
    try:
        limit_raw = request.args.get('limit', '300')
        try:
            limit = max(1, min(int(limit_raw), 2000))
        except ValueError:
            limit = 300

        # 1) Correlated CVE rows from vulnerability view (usually much larger than local DB links)
        corr_resp = requests.get(f"{VULNERABILITY_SERVICE}/vulnerabilities", timeout=12)
        corr_payload = {}
        if corr_resp.ok:
            try:
                corr_payload = corr_resp.json() or {}
            except Exception:
                corr_payload = {}
        correlated_rows = corr_payload.get('vulnerabilities', []) or []

        # 2) Local DB status rows (open/patched/mitigated) for fixed/not-fixed mapping
        local_resp = requests.get(
            f"{VULNERABILITY_SERVICE}/vulnerabilities/device-alerts",
            params={'limit': max(limit, 1000)},
            timeout=10
        )
        local_payload = {}
        if local_resp.ok:
            try:
                local_payload = local_resp.json() or {}
            except Exception:
                local_payload = {}
        local_rows = local_payload.get('alerts', []) or []

        def normalize_mac(value):
            if not value:
                return ''
            return str(value).strip().lower().replace('-', ':')

        def device_key(ip_value, mac_value, host_value):
            ip = (ip_value or '').strip().lower()
            mac = normalize_mac(mac_value)
            host = (host_value or '').strip().lower()
            return mac or ip or host or 'unknown'

        # index local status by (device_key, cve_id)
        local_status_map = {}
        for row in local_rows:
            cve_id = str(row.get('cve_id') or '').strip().upper()
            if not cve_id:
                continue
            key = device_key(row.get('device_ip'), row.get('mac_address'), row.get('hostname'))
            local_status_map[(key, cve_id)] = {
                'status': str(row.get('status') or 'open').strip().lower(),
                'time': row.get('time')
            }

        alerts = []
        seen = set()
        for vuln in correlated_rows:
            cve_list = vuln.get('cve_list') or []
            if not isinstance(cve_list, list) or len(cve_list) == 0:
                continue

            ip_address = vuln.get('ip_address')
            mac_address = vuln.get('mac_address')
            hostname = vuln.get('hostname') or vuln.get('affected_device')
            dkey = device_key(ip_address, mac_address, hostname)
            time_value = vuln.get('last_checked')

            sev_summary = vuln.get('vulnerability_summary') or {}
            default_severity = 'unknown'
            if (sev_summary.get('critical') or 0) > 0:
                default_severity = 'critical'
            elif (sev_summary.get('high') or 0) > 0:
                default_severity = 'high'
            elif (sev_summary.get('medium') or 0) > 0:
                default_severity = 'medium'
            elif (sev_summary.get('low') or 0) > 0:
                default_severity = 'low'

            for cve in cve_list:
                cve_id = str(cve or '').strip().upper()
                if not cve_id:
                    continue
                uniq = (dkey, cve_id)
                if uniq in seen:
                    continue
                seen.add(uniq)

                local = local_status_map.get((dkey, cve_id))
                status = (local or {}).get('status', 'open')
                fixed = status in ('patched', 'mitigated')

                alerts.append({
                    'time': (local or {}).get('time') or time_value,
                    'device_id': vuln.get('device_id'),
                    'device_ip': ip_address,
                    'hostname': hostname,
                    'mac_address': mac_address,
                    'cve_id': cve_id,
                    'severity': default_severity,
                    'cvss_score': None,
                    'status': status,
                    'fixed': fixed
                })

        # fallback to local rows if no correlated list available
        if not alerts and local_rows:
            alerts = local_rows

        alerts.sort(key=lambda x: str(x.get('time') or ''), reverse=True)
        alerts = alerts[:limit]
        device_cve_alerts_cache = {
            'items': alerts,
            'updated_at': datetime.utcnow().isoformat()
        }
        return jsonify({'alerts': alerts})
    except Exception as e:
        logger.error(f"Device CVE alerts proxy error: {str(e)}")
        cached_items = device_cve_alerts_cache.get('items') or []
        if cached_items:
            return jsonify({
                'alerts': cached_items[:max(1, min(int(request.args.get("limit", "300") or "300"), 2000))],
                'cache_mode': 'stale-fallback',
                'cached_at': device_cve_alerts_cache.get('updated_at')
            })
        return jsonify({'alerts': []})


@app.route('/api/vulnerabilities/general-report', methods=['POST'])
def get_device_general_report():
    """Build a unified per-device vulnerability report and LLM summary."""
    try:
        data = request.get_json(silent=True) or {}
        device_id = data.get('device_id')
        ip_address = (data.get('ip_address') or '').strip()
        mac_address = (data.get('mac_address') or '').strip()
        hostname = (data.get('hostname') or '').strip()
        os_name = (data.get('os') or '').strip()
        os_version = (data.get('os_version') or '').strip()
        corr_summary = data.get('vulnerability_summary') or {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        corr_cve_list = data.get('cve_list') or []
        telemetry_window_hours = request.args.get('window_hours', default=72, type=int) or 72
        telemetry_window_hours = max(24, min(telemetry_window_hours, 720))
        telemetry_limit = request.args.get('telemetry_limit', default=2000, type=int) or 2000
        telemetry_limit = max(200, min(telemetry_limit, 4000))

        if not any([device_id, ip_address, mac_address, hostname]):
            return jsonify({'error': 'At least one device identifier is required'}), 400

        # 1) Pull device context (status, open ports, existing CVE statuses)
        context_params = {}
        if device_id is not None:
            context_params['device_id'] = str(device_id)
        if ip_address:
            context_params['ip_address'] = ip_address
        if mac_address:
            context_params['mac_address'] = mac_address
        if hostname:
            context_params['hostname'] = hostname

        device = {}
        open_ports = []
        cve_entries = []
        cve_status_summary = {'open': 0, 'patched': 0, 'mitigated': 0, 'false_positive': 0}
        try:
            device_context_resp = requests.get(
                f"{VULNERABILITY_SERVICE}/device-report-context",
                params=context_params,
                timeout=4
            )
            if device_context_resp.ok:
                context_payload = device_context_resp.json() or {}
                device = context_payload.get('device') or {}
                open_ports = context_payload.get('open_ports') or []
                cve_status_summary = context_payload.get('cve_status_summary') or cve_status_summary
                cve_entries = context_payload.get('cve_entries') or []
        except Exception:
            pass

        if not device:
            device = {
                'id': device_id,
                'ip_address': ip_address,
                'mac_address': mac_address,
                'hostname': hostname,
                'os_name': os_name or 'Unknown',
                'os_version': os_version or 'unknown',
                'status': 'unknown',
                'risk_level': 'low',
                'last_seen': None
            }

        device_ip = (device.get('ip_address') or ip_address or '').strip()
        device_mac = (device.get('mac_address') or mac_address or '').strip().lower().replace('-', ':')
        device_host = (device.get('hostname') or hostname or '').strip().lower()

        # 2) Pull telemetry in parallel with short timeouts to keep UI responsive
        def safe_get_json(url, timeout_seconds=3):
            try:
                resp = requests.get(url, timeout=timeout_seconds)
                if resp.ok:
                    return resp.json() or {}
            except Exception:
                pass
            return {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_flows = executor.submit(
                safe_get_json,
                f"{TRAFFIC_SERVICE}/traffic/flows?window_hours={telemetry_window_hours}&limit={telemetry_limit}",
                4
            )
            future_alerts = executor.submit(
                safe_get_json,
                f"{TRAFFIC_SERVICE}/alerts?window_hours={telemetry_window_hours}&limit={telemetry_limit}&include_closed=1",
                4
            )
            future_incidents = executor.submit(safe_get_json, f"{CORRELATION_SERVICE}/incidents", 3)
            flows_payload = future_flows.result()
            alerts_payload = future_alerts.result()
            incidents_payload = future_incidents.result()

        flows = flows_payload.get('flows') or []
        alerts = alerts_payload.get('alerts') or []
        incidents = incidents_payload.get('incidents') or []

        def match_ip(candidate):
            return bool(device_ip) and str(candidate or '').strip().lower() == device_ip.lower()

        matched_flows = []
        protocols = {}
        observed_ports = set()
        total_bytes = 0
        inbound_bytes = 0
        outbound_bytes = 0
        telemetry_source = 'traffic-analyzer'
        for flow in flows:
            src_ip = (flow.get('src_ip') or '').strip().lower()
            dst_ip = (flow.get('dest_ip') or '').strip().lower()
            if not device_ip:
                continue
            if src_ip != device_ip.lower() and dst_ip != device_ip.lower():
                continue
            matched_flows.append(flow)
            bytes_total = int(flow.get('bytes_to_server') or 0) + int(flow.get('bytes_to_client') or 0)
            total_bytes += bytes_total
            if src_ip == device_ip.lower():
                outbound_bytes += bytes_total
                if flow.get('src_port'):
                    observed_ports.add(int(flow.get('src_port')))
            if dst_ip == device_ip.lower():
                inbound_bytes += bytes_total
                if flow.get('dest_port'):
                    observed_ports.add(int(flow.get('dest_port')))
            proto = (flow.get('protocol') or 'unknown').lower()
            bucket = protocols.setdefault(proto, {'protocol': proto, 'bytes': 0, 'flows': 0})
            bucket['bytes'] += bytes_total
            bucket['flows'] += 1

        # Fallback to host monitor snapshot when traffic_flows table has no matching rows.
        if not matched_flows and device_ip:
            try:
                host_conn_resp = requests.get(f"{HOST_TRAFFIC_MONITOR}/connections", timeout=4)
                if host_conn_resp.ok:
                    host_payload = host_conn_resp.json() or {}
                    for conn in host_payload.get('connections') or []:
                        src_ip = (conn.get('src_ip') or '').strip().lower()
                        dst_ip = (conn.get('dest_ip') or '').strip().lower()
                        if src_ip != device_ip.lower() and dst_ip != device_ip.lower():
                            continue
                        matched_flows.append(conn)
                        bytes_total = int(conn.get('bytes_sent') or 0) + int(conn.get('bytes_recv') or 0)
                        total_bytes += bytes_total
                        if src_ip == device_ip.lower():
                            outbound_bytes += bytes_total
                            if conn.get('src_port'):
                                observed_ports.add(int(conn.get('src_port')))
                        if dst_ip == device_ip.lower():
                            inbound_bytes += bytes_total
                            if conn.get('dest_port'):
                                observed_ports.add(int(conn.get('dest_port')))
                        proto = (conn.get('protocol') or 'unknown').lower()
                        bucket = protocols.setdefault(proto, {'protocol': proto, 'bytes': 0, 'flows': 0})
                        bucket['bytes'] += bytes_total
                        bucket['flows'] += 1
                    if matched_flows:
                        telemetry_source = 'host-monitor-fallback'
            except Exception:
                pass

        protocol_rows = sorted(protocols.values(), key=lambda x: (x['bytes'], x['flows']), reverse=True)
        most_used_protocols = [p['protocol'] for p in protocol_rows[:3]]

        matched_alerts = []
        top_alert_signatures = {}
        for alert in alerts:
            src_ip = (alert.get('src_ip') or '').strip().lower()
            dst_ip = (alert.get('dest_ip') or '').strip().lower()
            if not device_ip:
                continue
            if src_ip != device_ip.lower() and dst_ip != device_ip.lower():
                continue
            matched_alerts.append(alert)
            sig = (alert.get('signature') or 'unknown').strip()
            top_alert_signatures[sig] = top_alert_signatures.get(sig, 0) + 1
        top_alert_rows = sorted(
            [{'signature': k, 'count': v} for k, v in top_alert_signatures.items()],
            key=lambda x: x['count'],
            reverse=True
        )[:5]

        # If upstream correlation summary is empty but local device CVE rows exist, infer counts for visibility.
        if isinstance(cve_entries, list) and cve_entries and not any(int(corr_summary.get(k) or 0) for k in ('critical', 'high', 'medium', 'low')):
            inferred = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for item in cve_entries:
                severity = str((item or {}).get('severity') or '').strip().lower()
                if severity in inferred:
                    inferred[severity] += 1
            if any(inferred.values()):
                corr_summary = inferred

        def flatten_affected_devices(value):
            if not value:
                return []
            parsed = value
            if isinstance(value, str):
                try:
                    parsed = json.loads(value)
                except Exception:
                    return []
            if isinstance(parsed, dict):
                return [parsed]
            if isinstance(parsed, list):
                return [x for x in parsed if isinstance(x, dict)]
            return []

        def incident_matches(incident):
            assets = flatten_affected_devices(incident.get('affected_devices'))
            if not assets:
                return False
            for asset in assets:
                a_ip = (asset.get('ip_address') or '').strip().lower()
                a_mac = (asset.get('mac_address') or '').strip().lower().replace('-', ':')
                a_host = (asset.get('hostname') or '').strip().lower()
                if device_ip and a_ip == device_ip.lower():
                    return True
                if device_mac and a_mac == device_mac:
                    return True
                if device_host and a_host == device_host:
                    return True
            return False

        matched_incidents = [inc for inc in incidents if incident_matches(inc)]
        open_incidents = [
            inc for inc in matched_incidents
            if str(inc.get('status') or 'open').strip().lower() in ('open', 'investigating', 'contained', 'triage', 'in_progress')
        ]

        port_rows = []
        for port in open_ports:
            port_num = port.get('port_number')
            proto = (port.get('protocol') or '').lower()
            service = port.get('service_name') or ''
            label = f"{port_num}/{proto}" if proto else str(port_num)
            if service:
                label = f"{label} ({service})"
            port_rows.append(label)
        if not port_rows and observed_ports:
            port_rows = [str(p) for p in sorted(observed_ports)]
        open_ports_total = len(port_rows)
        if open_ports_total > 25:
            remaining = open_ports_total - 25
            port_rows = port_rows[:25] + [f"+{remaining} more"]

        report_payload = {
            'device': {
                'device_id': device.get('id') or device_id,
                'status': device.get('status') or 'unknown',
                'ip_address': device.get('ip_address') or ip_address,
                'mac_address': device.get('mac_address') or mac_address,
                'hostname': device.get('hostname') or hostname,
                'vendor': device.get('vendor'),
                'device_type': device.get('device_type'),
                'risk_level': device.get('risk_level') or 'low',
                'os': os_name or device.get('os_name') or 'Unknown',
                'os_version': os_version or device.get('os_version') or 'unknown',
                'last_seen': device.get('last_seen'),
            },
            'traffic': {
                'window': f'last {telemetry_window_hours} hours',
                'total_flows': len(matched_flows),
                'total_bytes': total_bytes,
                'inbound_bytes': inbound_bytes,
                'outbound_bytes': outbound_bytes,
                'protocol_distribution': protocol_rows,
                'most_used_protocols': most_used_protocols,
                'open_ports': port_rows,
                'open_ports_total': open_ports_total,
            },
            'alerts': {
                'open_alerts': len(matched_alerts),
                'top_signatures': top_alert_rows,
            },
            'data_quality': {
                'flows_matched': len(matched_flows),
                'alerts_matched': len(matched_alerts),
                'incidents_matched': len(matched_incidents),
                'open_ports_identified': len(port_rows),
                'telemetry_window': f'{telemetry_window_hours}h',
                'telemetry_source': telemetry_source,
                'requested_telemetry_limit': telemetry_limit
            },
            'incidents': {
                'related_total': len(matched_incidents),
                'open_total': len(open_incidents),
                'recent': [
                    {
                        'incident_id': inc.get('incident_id'),
                        'title': inc.get('title'),
                        'severity': inc.get('severity'),
                        'status': inc.get('status'),
                        'created_at': inc.get('created_at')
                    }
                    for inc in sorted(
                        matched_incidents,
                        key=lambda x: str(x.get('created_at') or ''),
                        reverse=True
                    )[:5]
                ]
            },
            'cve': {
                'correlation_summary': {
                    'critical': int(corr_summary.get('critical') or 0),
                    'high': int(corr_summary.get('high') or 0),
                    'medium': int(corr_summary.get('medium') or 0),
                    'low': int(corr_summary.get('low') or 0),
                },
                'existing_status': {
                    'open': int(cve_status_summary.get('open') or 0),
                    'patched': int(cve_status_summary.get('patched') or 0),
                    'mitigated': int(cve_status_summary.get('mitigated') or 0),
                    'false_positive': int(cve_status_summary.get('false_positive') or 0),
                },
                'correlated_cve_ids': corr_cve_list[:20] if isinstance(corr_cve_list, list) else [],
                'existing_entries': cve_entries[:20] if isinstance(cve_entries, list) else []
            },
            'limitations': [
                'Passive telemetry and OS/CVE correlation only.',
                'This report does not confirm exploitation of a specific device.'
            ]
        }

        include_llm = str(request.args.get('include_llm', '1')).lower() in ('1', 'true', 'yes')
        llm_block = {
            'provider': 'disabled',
            'model': 'n/a',
            'executive_summary': 'Quick report generated without extended LLM analysis.',
            'key_points': [],
            'recommended_actions': [],
            'confidence': 0.0
        }
        if include_llm:
            llm_fallback = {
                'provider': 'fallback',
                'model': 'heuristic-template',
                'executive_summary': (
                    f"Passive report for {report_payload['device'].get('hostname') or report_payload['device'].get('ip_address') or 'device'}: "
                    "review OS/CVE correlation, observed traffic, and open alerts/incidents. "
                    "This does not confirm exploitation."
                ),
                'key_points': [
                    'No direct exploit validation is performed in this report.',
                    'Traffic and protocol metrics depend on observed telemetry window.',
                    'Prioritize patching based on CVE severity and business impact.'
                ],
                'recommended_actions': [
                    'Verify asset exposure and open ports against baseline.',
                    'Patch critical/high CVEs first, then medium.',
                    'Correlate with Suricata alerts and incidents before escalation.'
                ],
                'confidence': 0.45
            }
            try:
                llm_resp = requests.post(
                    f"{LOG_ANALYZER_SERVICE}/reports/device-general",
                    json=report_payload,
                    timeout=8
                )
                if llm_resp.ok:
                    llm_payload = llm_resp.json() or {}
                    llm_block = llm_payload.get('llm_report') or llm_fallback
                else:
                    llm_block = llm_fallback
            except Exception as llm_error:
                logger.warning(f"Device general report LLM call failed: {str(llm_error)}")
                llm_block = llm_fallback

        return jsonify({
            'status': 'ok',
            'generated_at': datetime.utcnow().isoformat(),
            'report': report_payload,
            'llm_report': llm_block,
            'figures': {
                'protocol_distribution': report_payload['traffic']['protocol_distribution'],
                'cve_status_distribution': report_payload['cve']['existing_status'],
                'cve_severity_distribution': report_payload['cve']['correlation_summary'],
            },
            'note': 'Passive, correlation-based report. Not exploitation confirmation.'
        })
    except Exception as e:
        logger.error(f"General device vulnerability report error: {str(e)}")
        return jsonify({'error': 'Failed to generate general report'}), 500


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
        response = requests.get(
            f"{TRAFFIC_SERVICE}/alerts",
            params=request.args,
            timeout=30
        )
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
        response = requests.get(
            f"{TRAFFIC_SERVICE}/traffic/flows",
            params=request.args,
            timeout=10
        )
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
            
            window_hours = request.args.get('window_hours', default=24, type=int) or 24
            window_hours = max(1, min(window_hours, 720))
            limit = request.args.get('limit', default=300, type=int) or 300
            limit = max(20, min(limit, 2000))
            cutoff_sql = datetime.utcnow() - timedelta(hours=window_hours)

            query = """
            SELECT flow_id, src_ip, dest_ip, src_port, dest_port, protocol,
                   bytes_to_server, bytes_to_client, packets_to_server, packets_to_client,
                   start_time, end_time, duration_seconds, state
            FROM traffic_flows
            WHERE start_time >= %s
            ORDER BY start_time DESC
            LIMIT %s
            """
            
            cursor.execute(query, (cutoff_sql, limit))
            flows = cursor.fetchall()
            
            # Convert datetime objects to strings for JSON serialization
            for flow in flows:
                if flow.get('start_time'):
                    flow['start_time'] = flow['start_time'].isoformat()
                if flow.get('end_time'):
                    flow['end_time'] = flow['end_time'].isoformat()
            
            cursor.close()
            conn.close()
            
            return jsonify({'flows': flows, 'window_hours': window_hours, 'limit': limit})
            
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
        payload = request.get_json(silent=True)
        request_kwargs = {
            'params': request.args.to_dict(flat=True),
            'timeout': 90
        }
        if payload is not None:
            request_kwargs['json'] = payload

        response = requests.post(f"{CORRELATION_SERVICE}/incidents/scan", **request_kwargs)
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
        pubsub.subscribe(['security_events', 'scan_updates', 'alert_updates', 'traffic_events', 'cve_updates'])
        
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

