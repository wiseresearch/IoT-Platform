# IoT Security Platform

A comprehensive security monitoring platform designed for IoT environments, featuring real-time network traffic analysis, vulnerability scanning, and device discovery capabilities.

## Overview

This platform provides enterprise-grade security monitoring through a microservices architecture, combining host-based scanning with containerized analysis services to deliver accurate network visibility and threat detection.

## Architecture

### Core Components

**Host-Based Services**
- **Device Scanner** (Port 5555) - Network device discovery using ARP and ICMP
- **Traffic Monitor** (Port 5556) - Packet-level traffic capture with Wireshark TShark
  - TCP and UDP protocol support
  - Accurate byte-level measurements
  - Real-time connection tracking

**Containerized Services**
- **API Gateway** (Port 5001) - Unified REST API endpoint
- **Traffic Analyzer** - Flow processing and database persistence
- **Vulnerability Scanner** - Asynchronous scanning with Celery task queue
- **Correlation Engine** - Security event analysis and correlation
- **Web Dashboard** (Port 8090) - Interactive monitoring interface

**Infrastructure Services**
- MySQL 8.0 - Persistent data storage
- Redis 6 - Message broker and caching
- Elasticsearch & Kibana - Log aggregation and visualization

## Key Features

### Network Discovery
- Active device discovery on local network segments
- Service identification and port enumeration
- Real-time device inventory management
- Historical scan result tracking

### Traffic Monitoring
- Live TCP and UDP flow tracking
- Per-connection byte and packet counting
- Protocol-aware traffic classification
- 30-minute rolling window visualization
- Sub-second data refresh rates

### Vulnerability Management
- Automated network vulnerability scanning
- CVE database integration
- Risk-based prioritization
- Scan scheduling with Celery workers

### Security Correlation
- Cross-service event correlation
- Behavioral anomaly detection
- Automated incident creation
- Threat intelligence integration

### Web Dashboard
- Real-time statistics and metrics
- Interactive line charts with Chart.js
- Live traffic flow table
- Device inventory management
- Responsive design with loading indicators
- Cache-busting for fresh data delivery

## Prerequisites

**Required Software**
- Docker Desktop 4.x or higher
- Docker Compose 2.x or higher
- Python 3.11 or higher (for host-based services)
- Wireshark/TShark 4.x (for traffic monitoring)

**System Requirements**
- Windows 10/11 (tested) or Linux
- 8GB RAM minimum (16GB recommended)
- 20GB free disk space
- Administrator/root privileges for packet capture

## Installation

### 1. Clone Repository
```bash
git clone https://github.com/wiseresearch/IoT-Platform.git
cd IoT-Platform
```

### 2. Install Wireshark (Windows)
Download and install from: https://www.wireshark.org/download.html
- Select "Install TShark" during setup
- Add to PATH: `C:\Program Files\Wireshark`

### 3. Configure Environment
```bash
cp .env.example .env
```

Edit `.env` with your configuration:
```bash
# Database Configuration
DB_HOST=unified-db
DB_USER=security_user
DB_PASS=change_me_db_password
DB_NAME=unified_security_db

# Redis Configuration
REDIS_HOST=redis
REDIS_PORT=6379

# API Configuration
API_PORT=5001
DASHBOARD_PORT=8090
```

### 4. Start Docker Services
```bash
docker-compose up -d
```

Wait for all services to initialize (approximately 60 seconds).

### 5. Start Host-Based Services

**Device Scanner:**
```bash
python host_scanner_api.py
```
Service will run on port 5555.

**Traffic Monitor (requires Administrator):**
```powershell
# Run PowerShell as Administrator
python host_traffic_monitor_tshark.py
```
Service will run on port 5556.

### 6. Access Dashboard
Open browser: http://localhost:8090

## Service Endpoints

| Service | Port | Endpoint | Description |
|---------|------|----------|-------------|
| Web Dashboard | 8090 | http://localhost:8090 | Main UI |
| API Gateway | 5001 | http://localhost:5001 | REST API |
| Device Scanner | 5555 | http://localhost:5555 | Host scanner |
| Traffic Monitor | 5556 | http://localhost:5556 | TShark capture |
| Kibana | 5601 | http://localhost:5601 | Log viewer |
| MySQL | 3306 | localhost:3306 | Database |

## Configuration

### Network Interface Selection

Edit `host_traffic_monitor_tshark.py` to set your network interface:
```python
interface_name = 'Wi-Fi 2'  # Change to your interface name
```

Find your interface name:
```powershell
# Windows
Get-NetAdapter | Select-Object Name, InterfaceDescription

# Linux
ip link show
```

### Database Configuration

Connection settings in `.env`:
```bash
DB_HOST=unified-db
DB_PORT=3306
DB_USER=security_user
DB_PASS=change_me_db_password
DB_NAME=unified_security_db
```

## API Documentation

### Device Scanner API

**Get Network Devices**
```http
GET http://localhost:5555/scan
```

Response:
```json
{
  "status": "success",
  "devices": [
    {
      "ip": "192.168.1.100",
      "mac": "AA:BB:CC:DD:EE:FF",
      "hostname": "device-name",
      "is_gateway": false
    }
  ]
}
```

### Traffic Monitor API

**Get Active Connections**
```http
GET http://localhost:5556/connections
```

Response:
```json
{
  "status": "success",
  "total_connections": 45,
  "capture_active": true,
  "connections": [
    {
      "protocol": "tcp",
      "src_ip": "192.168.1.100",
      "dest_ip": "1.2.3.4",
      "src_port": 54321,
      "dest_port": 443,
      "bytes_sent": 15240,
      "bytes_recv": 98750,
      "state": "established"
    }
  ]
}
```

## Usage Guide

### Starting a Network Scan

1. Navigate to Dashboard (http://localhost:8090)
2. Click "Start Scan" button
3. Wait for scan completion (typically 30-60 seconds)
4. View discovered devices in the table below

### Monitoring Traffic

1. Ensure TShark monitor is running (port 5556)
2. Click "Traffic" in the navigation menu
3. View real-time traffic statistics and flows
4. Charts update every 5 seconds automatically

## Troubleshooting

### TShark Not Capturing Packets

**Symptom:** Traffic flows showing 0 bytes

**Solution:**
1. Verify TShark is running as Administrator
2. Check interface name is correct in `host_traffic_monitor_tshark.py`
3. Test TShark manually:
   ```powershell
   tshark -i "Wi-Fi 2" -c 10
   ```

### Docker Services Not Starting

**Symptom:** Services fail to start or show unhealthy

**Solution:**
1. Check Docker Desktop is running
2. Verify port availability:
   ```powershell
   netstat -ano | findstr "3306 5001 8090"
   ```
3. Review logs:
   ```bash
   docker-compose logs -f [service-name]
   ```

### Database Connection Errors

**Symptom:** API returns database connection errors

**Solution:**
1. Verify MySQL container is running:
   ```bash
   docker ps | grep unified_security_db
   ```
2. Test database connection:
   ```bash
   docker exec unified_security_db mysql -u security_user -p<your_db_password> -e "SELECT 1"
   ```
3. Restart services if needed:
   ```bash
   docker-compose restart traffic_analyzer_service
   ```

## Development

### Project Structure
```
IoTSecurityPlatform/
├── api-gateway/              # API Gateway service
├── services/
│   ├── traffic-analyzer/     # Traffic flow processing
│   ├── vulnerability-scanner/# Vulnerability scanning
│   ├── correlation-engine/   # Event correlation
│   └── network-scanner/      # Network scanning scripts
├── shared/
│   └── database/             # Database schemas
├── web-dashboard/            # Frontend application
├── host_scanner_api.py       # Host device scanner
├── host_traffic_monitor_tshark.py  # TShark monitor
└── docker-compose.yml        # Service orchestration
```

### Database Schema

Tables:
- `devices` - Discovered network devices
- `traffic_flows` - Network traffic records
- `vulnerabilities` - Detected vulnerabilities
- `incidents` - Security incidents
- `scans` - Scan history

See `shared/database/init.sql` for complete schema.

## Security Considerations

### Production Deployment

1. **Change Default Credentials**
   - Update database passwords in `.env`
   - Use strong passwords (16+ characters)

2. **Network Segmentation**
   - Deploy in isolated VLAN
   - Restrict access to management interfaces
   - Use firewall rules for service access

3. **TLS/SSL Configuration**
   - Enable HTTPS for web dashboard
   - Configure certificate for API Gateway

4. **Access Control**
   - Implement authentication for API endpoints
   - Use role-based access control (RBAC)
   - Enable audit logging

## License

This project is licensed under the MIT License - see LICENSE file for details.

## Acknowledgments

- Wireshark/TShark for packet capture capabilities
- Chart.js for visualization components
- Docker and Docker Compose for containerization
- Flask framework for microservices
- Celery for asynchronous task processing
