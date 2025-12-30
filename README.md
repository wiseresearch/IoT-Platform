# Unified Security Platform

A comprehensive IoT security platform that integrates vulnerability scanning, network traffic analysis, and intelligent correlation to provide unified security monitoring and incident response.

## Architecture

The platform consists of the following microservices:

### Core Services
- **API Gateway** (`api-gateway/`) - Central entry point and request routing
- **Vulnerability Scanner** (`services/vulnerability-scanner/`) - Network scanning and vulnerability assessment
- **Traffic Analyzer** (`services/traffic-analyzer/`) - Network traffic monitoring with Suricata IDS
- **Correlation Engine** (`services/correlation-engine/`) - Security event correlation and incident management
- **Web Dashboard** (`web-dashboard/`) - Unified web interface

### Supporting Infrastructure
- **MySQL Database** - Unified data storage
- **Redis** - Caching and message queuing
- **Elasticsearch & Kibana** - Log analytics and visualization

## Features

### 🔍 Network Discovery & Vulnerability Assessment
- Automated network device discovery
- Port scanning and service fingerprinting
- CVE vulnerability matching
- Risk assessment and prioritization

### 🌐 Network Traffic Analysis
- Real-time traffic monitoring with Suricata IDS
- Protocol analysis (HTTP, DNS, TLS, SSH)
- Anomaly detection and alerting
- Traffic flow analysis

### 🧠 Intelligent Correlation
- Cross-correlation of vulnerabilities and network events
- Behavioral analysis and anomaly detection
- Threat intelligence integration
- Automated incident creation and management

### 📊 Unified Dashboard
- Real-time security overview
- Interactive charts and metrics
- Device inventory management
- Security incident tracking
- Live event streaming

## Quick Start

### Prerequisites
- Docker and Docker Compose
- At least 8GB RAM
- 20GB free disk space

### Installation

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd UnifiedSecurityPlatform
   ```

2. **Configure environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env file with your settings
   ```

3. **Start the platform:**
   ```bash
   docker-compose up -d
   ```

4. **Verify deployment:**
   ```bash
   # Check service health
   curl http://localhost:8000/health
   
   # Access web dashboard
   open http://localhost:8080
   ```

### Default Access

- **Web Dashboard**: http://localhost:8080
- **API Gateway**: http://localhost:8000
- **Kibana**: http://localhost:5601
- **Database**: localhost:3306

**Default Login:**
- Username: `admin`
- Password: `admin123` (⚠️ Change this immediately!)

## Configuration

### Environment Variables

Create a `.env` file with the following variables:

```bash
# Database Configuration
DB_HOST=unified-db
DB_USER=security_user
DB_PASS=security_pass
DB_NAME=unified_security
DB_ROOT_PASS=rootpassword

# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379

# Security Configuration
JWT_SECRET=your-secret-key-here
FLASK_DEBUG=false

# Network Configuration
FALLBACK_SUBNET=192.168.1.0/24
SCAN_INTERFACE=eth0

# Service URLs (for internal communication)
VULNERABILITY_SERVICE_URL=http://vulnerability-scanner:5001
TRAFFIC_SERVICE_URL=http://traffic-analyzer:5002
CORRELATION_SERVICE_URL=http://correlation-engine:5003
```

### Network Scanning Configuration

Edit `config/scanner-config.yml`:

```yaml
scanner:
  default_range: "192.168.1.0/24"
  scan_timeout: 300
  max_concurrent_scans: 3
  
vulnerability_matching:
  cve_database_url: "https://services.nvd.nist.gov/rest/json/cves/1.0/"
  update_interval: 86400  # 24 hours
  
correlation:
  rules_enabled: true
  processing_interval: 30
  max_incident_age: 30
```

## Usage

### Starting a Network Scan

#### Via Web Dashboard
1. Navigate to the "Scans" section
2. Click "New Scan"
3. Enter target network range (e.g., `192.168.1.0/24`)
4. Click "Start Scan"

#### Via API
```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target_range": "192.168.1.0/24"}'
```

### Viewing Results

#### Dashboard Overview
- Navigate to http://localhost:8080
- View real-time metrics and charts
- Monitor security incidents and alerts

#### Detailed Analysis
- **Devices**: View discovered devices and their security status
- **Vulnerabilities**: Browse detected vulnerabilities by severity
- **Traffic**: Analyze network flows and security alerts
- **Incidents**: Review correlated security incidents

### API Documentation

The platform provides RESTful APIs for all functionality:

#### Authentication
```bash
# Login
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

#### Scanning
```bash
# Start scan
curl -X POST http://localhost:8000/api/scans \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"target_range": "192.168.1.0/24"}'

# Get scan status
curl http://localhost:8000/api/scans/<scan_id> \
  -H "Authorization: Bearer <token>"
```

#### Device Management
```bash
# List devices
curl http://localhost:8000/api/devices \
  -H "Authorization: Bearer <token>"

# Get vulnerabilities
curl http://localhost:8000/api/vulnerabilities \
  -H "Authorization: Bearer <token>"
```

## Advanced Configuration

### Custom Correlation Rules

Create custom correlation rules to detect specific threat patterns:

```json
{
  "rule_name": "Brute Force Detection",
  "rule_type": "behavioral",
  "condition_query": {
    "conditions": [
      {
        "type": "failed_login_attempts",
        "threshold": 10,
        "time_window": 300
      }
    ]
  },
  "severity": "high",
  "description": "Detects potential brute force attacks"
}
```

### Threat Intelligence Integration

Add threat intelligence feeds:

```bash
curl -X POST http://localhost:8000/api/threat-intelligence \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "indicator": "192.168.100.100",
    "indicator_type": "ip",
    "threat_type": "botnet",
    "confidence": 0.9,
    "source": "manual"
  }'
```

### Suricata Rules

Custom Suricata rules can be added to `services/traffic-analyzer/suricata-config/rules/`:

```
alert tcp any any -> any 22 (msg:"SSH Brute Force Attempt"; flow:to_server; threshold:type both, track by_src, count 10, seconds 60; sid:1000001; rev:1;)
```

## Monitoring and Maintenance

### Health Monitoring

Check service health:
```bash
# Overall platform health
curl http://localhost:8000/health

# Individual service health
curl http://localhost:5001/health  # Vulnerability Scanner
curl http://localhost:5002/health  # Traffic Analyzer
curl http://localhost:5003/health  # Correlation Engine
```

### Log Management

View service logs:
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f vulnerability-scanner
docker-compose logs -f traffic-analyzer
docker-compose logs -f correlation-engine
```

### Database Backup

Backup the unified database:
```bash
docker-compose exec unified-db mysqldump -u root -p unified_security > backup.sql
```

### Performance Tuning

#### Resource Allocation
Adjust container resources in `docker-compose.yml`:

```yaml
services:
  vulnerability-scanner:
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '1.0'
```

#### Database Optimization
For large deployments, tune MySQL configuration:

```ini
[mysqld]
innodb_buffer_pool_size = 2G
max_connections = 200
query_cache_size = 256M
```

## Troubleshooting

### Common Issues

1. **Services fail to start**
   ```bash
   # Check Docker resources
   docker system df
   docker system prune -f
   
   # Verify network connectivity
   docker-compose exec api-gateway ping unified-db
   ```

2. **Database connection errors**
   ```bash
   # Check database status
   docker-compose logs unified-db
   
   # Verify credentials
   docker-compose exec unified-db mysql -u security_user -p unified_security
   ```

3. **Network scanning not working**
   ```bash
   # Check scanner permissions
   docker-compose logs vulnerability-scanner
   
   # Verify network access
   docker-compose exec vulnerability-scanner nmap -sP 192.168.1.0/24
   ```

### Debug Mode

Enable debug logging:
```bash
# Set environment variable
export FLASK_DEBUG=true

# Restart services
docker-compose restart
```

## Security Considerations

### Production Deployment

⚠️ **Important Security Settings for Production:**

1. **Change default passwords**
   - Database root password
   - Default admin user password
   - JWT secret key

2. **Network Security**
   - Use HTTPS with valid SSL certificates
   - Implement network segmentation
   - Configure firewall rules

3. **Access Control**
   - Enable authentication for all services
   - Implement role-based access control
   - Use strong password policies

4. **Data Protection**
   - Enable database encryption at rest
   - Configure secure backup procedures
   - Implement audit logging

### Security Best Practices

- Regularly update container images
- Monitor security advisories for dependencies
- Implement network monitoring
- Use secrets management for sensitive data
- Regular security assessments

## Development

### Local Development Setup

1. **Install development dependencies:**
   ```bash
   pip install -r requirements-dev.txt
   ```

2. **Run services locally:**
   ```bash
   # Start database and Redis
   docker-compose up -d unified-db redis
   
   # Run services locally for development
   cd services/vulnerability-scanner && python app.py
   cd services/correlation-engine && python app.py
   ```

### Adding New Services

1. Create service directory under `services/`
2. Implement Flask application with health endpoint
3. Add service to `docker-compose.yml`
4. Update API Gateway routing
5. Add service monitoring

### Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit a pull request

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review logs for error details

## Changelog

### Version 1.0.0
- Initial release with unified platform
- Vulnerability scanning integration
- Traffic analysis with Suricata
- Correlation engine implementation
- Web dashboard interface