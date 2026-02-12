// Unified Security Platform - Main JavaScript
const MOCK_TRAFFIC = false;

class UnifiedSecurityPlatform {
    constructor() {
        this.apiGateway = 'http://localhost:8080/api';
        this.eventSource = null;
        this.charts = {};
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadDashboard();
        this.setupRealTimeUpdates();
    }

    setupEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                this.navigate(e.target.dataset.section);
            });
        });

        // Refresh buttons
        document.querySelectorAll('.btn-refresh').forEach(btn => {
            btn.addEventListener('click', () => {
                this.loadDashboard();
            });
        });

        // Network and time range selectors
        document.addEventListener('DOMContentLoaded', () => {
            const networkSelector = document.getElementById('networkSelector');
            const timeRangeSelector = document.getElementById('timeRangeSelector');
            
            /*if (networkSelector) {
                networkSelector.addEventListener('change', () => this.loadNetworkTraffic());
            }
            
            if (timeRangeSelector) {
                timeRangeSelector.addEventListener('change', () => this.loadNetworkTraffic());
            }*/
        });

        // Scan buttons
        document.getElementById('startScan')?.addEventListener('click', () => {
            this.startVulnerabilityScan();
        });
    }

    navigate(section) {
        // Hide all sections
        document.querySelectorAll('.content-section').forEach(s => {
            s.style.display = 'none';
        });

        // Show selected section
        const targetSection = document.getElementById(section);
        if (targetSection) {
            targetSection.style.display = 'block';
            
            // Update active nav
            document.querySelectorAll('.nav-link').forEach(link => {
                link.classList.remove('active');
            });
            document.querySelector(`[data-section="${section}"]`).classList.add('active');

            // Load section specific data
            this.loadSectionData(section);
        }
    }

    async loadDashboard() {
        try {
            await Promise.all([
                this.loadMetrics(),
                this.loadRecentAlerts(),
                this.loadDeviceStatus(),
                this.loadNetworkTraffic()
            ]);
        } catch (error) {
            console.error('Error loading dashboard:', error);
            this.showError('Failed to load dashboard data');
        }
    }

    async loadMetrics() {
        try {
            const response = await fetch(`${this.apiGateway}/metrics`);
            const metrics = await response.json();

            document.getElementById('totalDevices').textContent = metrics.total_devices || 0;
            document.getElementById('activeAlerts').textContent = metrics.active_alerts || 0;
            document.getElementById('vulnerabilities').textContent = metrics.vulnerabilities || 0;
            document.getElementById('networkEvents').textContent = metrics.network_events || 0;
        } catch (error) {
            console.error('Error loading metrics:', error);
        }
    }

    async loadRecentAlerts() {
        try {
            const response = await fetch(`${this.apiGateway}/alerts/recent`);
            const alerts = await response.json();

            const alertsContainer = document.getElementById('recentAlerts');
            alertsContainer.innerHTML = '';

            alerts.forEach(alert => {
                const alertElement = document.createElement('div');
                alertElement.className = `alert-item alert-${alert.severity}`;
                alertElement.innerHTML = `
                    <div class="d-flex justify-content-between">
                        <div>
                            <strong>${alert.title}</strong>
                            <p class="mb-0">${alert.description}</p>
                        </div>
                        <small class="text-muted">${this.formatTime(alert.timestamp)}</small>
                    </div>
                `;
                alertsContainer.appendChild(alertElement);
            });
        } catch (error) {
            console.error('Error loading alerts:', error);
        }
    }

    async loadDeviceStatus() {
        try {
            const response = await fetch(`${this.apiGateway}/devices/status`);
            const devices = await response.json();

            const devicesContainer = document.getElementById('deviceStatus');
            devicesContainer.innerHTML = '';

            devices.forEach(device => {
                const deviceElement = document.createElement('div');
                deviceElement.className = 'device-item mb-2 p-2 border rounded';
                deviceElement.innerHTML = `
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <span class="device-status device-${device.status}"></span>
                            <strong>${device.hostname || device.ip}</strong>
                            <span class="text-muted">(${device.ip})</span>
                        </div>
                        <span class="badge badge-${this.getRiskBadgeClass(device.risk_score)}">
                            Risk: ${device.risk_score}
                        </span>
                    </div>
                `;
                devicesContainer.appendChild(deviceElement);
            });
        } catch (error) {
            console.error('Error loading device status:', error);
        }
    }

    /*async loadNetworkTraffic() {
    try {
        // === MOCK MODE ===
        if (MOCK_TRAFFIC) {
            console.warn('MOCK TRAFFIC MODE ENABLED');

            const processedData = this.processTrafficFlows([]);
            this.createTrafficChart(processedData);
            return; // STOP ICI
        }

        // === REAL DATA MODE ===
        const networkFilter = document.getElementById('networkSelector')?.value || 'all';
        const timeRange = document.getElementById('timeRangeSelector')?.value || '1h';

        const response = await fetch(
            `${this.apiGateway}/traffic/flows?network=${networkFilter}&timeRange=${timeRange}`
        );
        const result = await response.json();

        const processedData = this.getMockTrafficData();
        this.createTrafficChart(processedData);
        } catch (error) {
        console.error('Error loading network traffic:', error);
        }
    }*/

    async loadNetworkTraffic() {
        try {
            if (MOCK_TRAFFIC) {
                console.warn('MOCK TRAFFIC MODE ENABLED');
                const data = this.getMockTrafficData();
                this.createTrafficChart(data);
                return;
            }

            const networkFilter = document.getElementById('networkSelector')?.value || 'all';
            const timeRange = document.getElementById('timeRangeSelector')?.value || '1h';

            const response = await fetch(
                `${this.apiGateway}/traffic/flows?network=${networkFilter}&timeRange=${timeRange}`
            );
            const result = await response.json();
            const flows = result.flows || [];

            const processedData = this.processTrafficFlows(flows, networkFilter);
            this.createTrafficChart(processedData);
        } catch (error) {
            console.error('Error loading network traffic:', error);
        }
    }
    

    getMockTrafficData() {
        const now = new Date();
        const timestamps = [];
        const inbound = [];
        const outbound = [];

        for (let i = 10; i >= 0; i--) {
            const t = new Date(now.getTime() - i * 60000);
            timestamps.push(
                t.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })
            );

            inbound.push(100 + Math.random() * 500);
            outbound.push(50 + Math.random() * 300);
        }

        return { timestamps, inbound, outbound };
    }


    refreshTraffic() {
        this.loadNetworkTraffic();
    }

    processTrafficFlows(flows, networkFilter = 'all') {
        const timestamps = [];
        const inbound = [];
        const outbound = [];

        if (!Array.isArray(flows) || flows.length === 0) {
            return { timestamps, inbound, outbound };
        }

        let filtered = flows;
        if (networkFilter !== 'all') {
            const prefix = networkFilter.split('/')[0];
            filtered = flows.filter(flow => {
                const src = flow.src_ip || '';
                const dst = flow.dest_ip || '';
                return src.startsWith(prefix) || dst.startsWith(prefix);
            });
        }

        filtered.sort((a, b) => {
            const ta = new Date(a.start_time || a.timestamp || 0).getTime();
            const tb = new Date(b.start_time || b.timestamp || 0).getTime();
            return ta - tb;
        });

        const buckets = new Map();
        filtered.forEach(flow => {
            const ts = new Date(flow.start_time || flow.timestamp || Date.now()).getTime();
            if (!ts || Number.isNaN(ts)) return;
            const bucket = Math.floor(ts / 60000) * 60000;
            if (!buckets.has(bucket)) {
                buckets.set(bucket, { inbound: 0, outbound: 0 });
            }
            const entry = buckets.get(bucket);
            const inboundBytes = Number(flow.bytes_to_client || 0);
            const outboundBytes = Number(flow.bytes_to_server || 0);
            if (inboundBytes || outboundBytes) {
                entry.inbound += inboundBytes;
                entry.outbound += outboundBytes;
            } else {
                const bytes = Number(flow.bytes || flow.bytes_total || 0);
                entry.inbound += bytes / 2;
                entry.outbound += bytes / 2;
            }
        });

        Array.from(buckets.entries())
            .sort((a, b) => a[0] - b[0])
            .forEach(([ts, val]) => {
                const t = new Date(ts);
                timestamps.push(
                    t.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })
                );
                inbound.push(Number((val.inbound / 1024).toFixed(2)));
                outbound.push(Number((val.outbound / 1024).toFixed(2)));
            });

        return { timestamps, inbound, outbound };
    }


    createTrafficChart(data) {
        console.log('Rendering traffic chart with:', data); 

        const ctx = document.getElementById('trafficChart');
        if (!ctx) return;

        if (this.charts.traffic) {
            this.charts.traffic.destroy();
        }

        this.charts.traffic = new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.timestamps,
                datasets: [{
                    label: 'Inbound Traffic',
                    data: data.inbound,
                    borderColor: '#3498db',
                    backgroundColor: 'rgba(52, 152, 219, 0.1)',
                    fill: true
                }, {
                    label: 'Outbound Traffic',
                    data: data.outbound,
                    borderColor: '#e74c3c',
                    backgroundColor: 'rgba(231, 76, 60, 0.1)',
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }

    setupRealTimeUpdates() {
        if (this.eventSource) {
            this.eventSource.close();
        }

        this.eventSource = new EventSource(`${this.apiGateway}/events/stream`);
        
        this.eventSource.onmessage = (event) => {
            const data = JSON.parse(event.data);
            this.handleRealTimeEvent(data);
        };

        this.eventSource.onerror = (error) => {
            console.error('EventSource error:', error);
        };
    }

    handleRealTimeEvent(event) {
        switch (event.type) {
            case 'new_alert':
                this.addNewAlert(event.data);
                break;
            case 'device_status_change':
                this.updateDeviceStatus(event.data);
                break;
            case 'scan_complete':
                this.handleScanComplete(event.data);
                break;
            default:
                console.log('Unknown event type:', event.type);
        }
    }

    addNewAlert(alert) {
        const alertsContainer = document.getElementById('recentAlerts');
        const alertElement = document.createElement('div');
        alertElement.className = `alert-item alert-${alert.severity} fade-in`;
        alertElement.innerHTML = `
            <div class="d-flex justify-content-between">
                <div>
                    <strong>${alert.title}</strong>
                    <p class="mb-0">${alert.description}</p>
                </div>
                <small class="text-muted">Just now</small>
            </div>
        `;
        alertsContainer.insertBefore(alertElement, alertsContainer.firstChild);

        // Update alerts counter
        const counter = document.getElementById('activeAlerts');
        counter.textContent = parseInt(counter.textContent) + 1;
    }

    async startVulnerabilityScan() {
        try {
            const response = await fetch(`${this.apiGateway}/scans`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    network_range: '172.20.10.0/28',
                    scan_type: 'network'
                })
            });

            const result = await response.json();
            
            if (result.success) {
                this.showSuccess('Vulnerability scan started successfully');
            } else {
                this.showError('Failed to start vulnerability scan');
            }
        } catch (error) {
            console.error('Error starting scan:', error);
            this.showError('Error starting vulnerability scan');
        }
    }

    async loadSectionData(section) {
        switch (section) {
            case 'vulnerabilities':
                await this.loadVulnerabilityData();
                break;
            case 'network':
                await this.loadNetworkData();
                break;
            case 'devices':
                await this.loadDevicesData();
                break;
            case 'settings':
                await this.loadSettingsData();
                break;
        }
    }

    async loadVulnerabilityData() {
        // Load vulnerability scan results
        try {
            const response = await fetch(`${this.apiGateway}/vulnerabilities`);
            const vulns = await response.json();
            // Update vulnerability table
        } catch (error) {
            console.error('Error loading vulnerabilities:', error);
        }
    }

    getRiskBadgeClass(riskScore) {
        if (riskScore >= 8) return 'danger';
        if (riskScore >= 5) return 'warning';
        return 'success';
    }

    formatTime(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleTimeString();
    }

    showSuccess(message) {
        this.showToast(message, 'success');
    }

    showError(message) {
        this.showToast(message, 'danger');
    }

    showToast(message, type) {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `
            <div class="toast-body">
                ${message}
            </div>
        `;
        
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.remove();
        }, 5000);
    }
}

// Initialize the platform when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new UnifiedSecurityPlatform();
});

// Utility functions
function updateTimestamps() {
    document.querySelectorAll('[data-timestamp]').forEach(element => {
        const timestamp = element.dataset.timestamp;
        element.textContent = new Date(timestamp).toLocaleString();
    });
}

// Update timestamps every minute
setInterval(updateTimestamps, 60000);

