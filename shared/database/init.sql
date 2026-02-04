-- Unified Security Platform Database Schema
-- Combines vulnerability scanning, traffic analysis, and correlation data

-- ============================================================================
-- DEVICE MANAGEMENT TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    mac_address VARCHAR(17),
    hostname VARCHAR(255),
    device_type VARCHAR(100),
    vendor VARCHAR(100),
    os_name VARCHAR(100),
    os_version VARCHAR(50),
    firmware_version VARCHAR(100),
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    status ENUM('online', 'offline', 'unknown') DEFAULT 'unknown',
    risk_level ENUM('low', 'medium', 'high', 'critical') DEFAULT 'low',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_device (ip_address, mac_address),
    INDEX idx_ip_address (ip_address),
    INDEX idx_mac_address (mac_address),
    INDEX idx_status (status),
    INDEX idx_risk_level (risk_level)
);

CREATE TABLE IF NOT EXISTS device_ports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    port_number INT NOT NULL,
    protocol ENUM('tcp', 'udp') NOT NULL,
    service_name VARCHAR(100),
    service_version VARCHAR(100),
    state ENUM('open', 'closed', 'filtered') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
    UNIQUE KEY unique_port (device_id, port_number, protocol),
    INDEX idx_port_state (state)
);

-- ============================================================================
-- VULNERABILITY MANAGEMENT TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL UNIQUE,
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(200),
    severity ENUM('low', 'medium', 'high', 'critical'),
    summary TEXT,
    description TEXT,
    published_date DATE,
    modified_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_cve_id (cve_id),
    INDEX idx_severity (severity),
    INDEX idx_cvss_score (cvss_score)
);

CREATE TABLE IF NOT EXISTS device_vulnerabilities (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    vulnerability_id INT NOT NULL,
    detection_method VARCHAR(100),
    confidence_level DECIMAL(3,2) DEFAULT 1.00,
    status ENUM('open', 'patched', 'mitigated', 'false_positive') DEFAULT 'open',
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    UNIQUE KEY unique_device_vuln (device_id, vulnerability_id),
    INDEX idx_status (status),
    INDEX idx_confidence (confidence_level)
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id VARCHAR(100) NOT NULL,
    scan_type ENUM('network', 'vulnerability', 'port', 'service') NOT NULL,
    target_range VARCHAR(100),
    status ENUM('pending', 'running', 'completed', 'failed') DEFAULT 'pending',
    devices_found INT DEFAULT 0,
    vulnerabilities_found INT DEFAULT 0,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    error_message TEXT,
    scan_options JSON,
    results_summary JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_scan_id (scan_id),
    INDEX idx_scan_type (scan_type),
    INDEX idx_status (status)
);

-- ============================================================================
-- TRAFFIC ANALYSIS TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS network_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_type ENUM('alert', 'flow', 'http', 'dns', 'tls', 'ssh', 'anomaly') NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    src_ip VARCHAR(45) NOT NULL,
    dest_ip VARCHAR(45) NOT NULL,
    src_port INT,
    dest_port INT,
    protocol VARCHAR(20),
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'low',
    signature VARCHAR(500),
    classification VARCHAR(100),
    raw_data JSON,
    processed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_event_type (event_type),
    INDEX idx_timestamp (timestamp),
    INDEX idx_src_ip (src_ip),
    INDEX idx_dest_ip (dest_ip),
    INDEX idx_severity (severity),
    INDEX idx_processed (processed)
);

CREATE TABLE IF NOT EXISTS security_alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alert_id VARCHAR(100) NOT NULL UNIQUE,
    rule_id INT,
    signature VARCHAR(500) NOT NULL,
    category VARCHAR(100),
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    dest_ip VARCHAR(45) NOT NULL,
    src_port INT,
    dest_port INT,
    protocol VARCHAR(20),
    action_taken ENUM('alert', 'drop', 'reject', 'pass') DEFAULT 'alert',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by VARCHAR(100),
    acknowledged_at TIMESTAMP NULL,
    status ENUM('open', 'investigating', 'resolved', 'false_positive') DEFAULT 'open',
    notes TEXT,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_alert_id (alert_id),
    INDEX idx_severity (severity),
    INDEX idx_src_ip (src_ip),
    INDEX idx_dest_ip (dest_ip),
    INDEX idx_status (status),
    INDEX idx_timestamp (timestamp)
);

CREATE TABLE IF NOT EXISTS traffic_flows (
    id INT AUTO_INCREMENT PRIMARY KEY,
    flow_id VARCHAR(100) NOT NULL,
    src_ip VARCHAR(45) NOT NULL,
    dest_ip VARCHAR(45) NOT NULL,
    src_port INT,
    dest_port INT,
    protocol VARCHAR(20),
    bytes_to_server BIGINT DEFAULT 0,
    bytes_to_client BIGINT DEFAULT 0,
    packets_to_server INT DEFAULT 0,
    packets_to_client INT DEFAULT 0,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP NULL,
    duration_seconds INT DEFAULT 0,
    state VARCHAR(50),
    reason VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_flow_id (flow_id),
    INDEX idx_src_ip (src_ip),
    INDEX idx_dest_ip (dest_ip),
    INDEX idx_start_time (start_time)
);

-- ============================================================================
-- CORRELATION AND INTELLIGENCE TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS security_incidents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    incident_id VARCHAR(100) NOT NULL UNIQUE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    status ENUM('open', 'investigating', 'contained', 'resolved') DEFAULT 'open',
    assigned_to VARCHAR(100),
    created_by VARCHAR(100),
    affected_devices JSON,
    related_alerts JSON,
    related_vulnerabilities JSON,
    timeline JSON,
    mitigation_steps TEXT,
    lessons_learned TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    closed_at TIMESTAMP NULL,
    INDEX idx_incident_id (incident_id),
    INDEX idx_severity (severity),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at)
);

CREATE TABLE IF NOT EXISTS correlation_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    rule_name VARCHAR(255) NOT NULL,
    rule_type ENUM('vulnerability_traffic', 'anomaly_detection', 'threat_intelligence', 'behavioral') NOT NULL,
    condition_query JSON NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    false_positive_rate DECIMAL(5,4) DEFAULT 0.0000,
    detection_count INT DEFAULT 0,
    last_triggered TIMESTAMP NULL,
    created_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_rule_type (rule_type),
    INDEX idx_enabled (enabled),
    INDEX idx_severity (severity)
);

CREATE TABLE IF NOT EXISTS threat_intelligence (
    id INT AUTO_INCREMENT PRIMARY KEY,
    indicator VARCHAR(255) NOT NULL,
    indicator_type ENUM('ip', 'domain', 'hash', 'url', 'email') NOT NULL,
    threat_type VARCHAR(100),
    malware_family VARCHAR(100),
    confidence DECIMAL(3,2) DEFAULT 1.00,
    source VARCHAR(100),
    description TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    tags JSON,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_indicator (indicator, indicator_type),
    INDEX idx_indicator (indicator),
    INDEX idx_indicator_type (indicator_type),
    INDEX idx_threat_type (threat_type),
    INDEX idx_is_active (is_active)
);

-- ============================================================================
-- SYSTEM AND AUDIT TABLES
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin', 'analyst', 'viewer') DEFAULT 'viewer',
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    last_login TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_role (role)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(100),
    details JSON,
    ip_address VARCHAR(45),
    user_agent TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_action (action),
    INDEX idx_timestamp (timestamp)
);

CREATE TABLE IF NOT EXISTS system_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) NOT NULL UNIQUE,
    config_value TEXT,
    description TEXT,
    data_type ENUM('string', 'integer', 'boolean', 'json') DEFAULT 'string',
    is_sensitive BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_config_key (config_key)
);

-- ============================================================================
-- INSERT DEFAULT DATA
-- ============================================================================

-- Default admin user (password: admin123 - change this!)
INSERT INTO users (username, email, password_hash, role, first_name, last_name) VALUES 
('admin', 'admin@security.local', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewsK1iD4YvR9D/Bu', 'admin', 'System', 'Administrator')
ON DUPLICATE KEY UPDATE username = username;

-- Default system configuration
INSERT INTO system_config (config_key, config_value, description, data_type) VALUES 
('scan_interval_minutes', '60', 'Default interval for automated scans in minutes', 'integer'),
('max_concurrent_scans', '3', 'Maximum number of concurrent scan operations', 'integer'),
('alert_retention_days', '90', 'Number of days to retain security alerts', 'integer'),
('vulnerability_sync_enabled', 'true', 'Enable automatic vulnerability database synchronization', 'boolean'),
('threat_intel_feeds', '[]', 'List of threat intelligence feed URLs', 'json'),
('correlation_enabled', 'true', 'Enable automatic correlation between vulnerabilities and network events', 'boolean')
ON DUPLICATE KEY UPDATE config_key = config_key;

-- Default correlation rules
INSERT INTO correlation_rules (rule_name, rule_type, condition_query, severity, description, created_by) VALUES 
('Vulnerable Device Network Alert', 'vulnerability_traffic', 
 '{"conditions": [{"type": "device_has_vulnerability", "severity": ["high", "critical"]}, {"type": "network_alert_from_device", "time_window": 3600}]}', 
 'high', 'Correlates network security alerts with devices that have known high/critical vulnerabilities', 'system'),
 
('Anomalous Traffic from New Device', 'anomaly_detection', 
 '{"conditions": [{"type": "new_device_discovered", "time_window": 1800}, {"type": "suspicious_network_behavior", "time_window": 3600}]}', 
 'medium', 'Detects suspicious network behavior from recently discovered devices', 'system'),
 
('Threat Intel IP Communication', 'threat_intelligence', 
 '{"conditions": [{"type": "communication_with_threat_ip"}, {"type": "active_threat_intelligence"}]}', 
 'critical', 'Alerts when any device communicates with known malicious IP addresses', 'system')
ON DUPLICATE KEY UPDATE rule_name = rule_name;