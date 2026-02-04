// Unified Security Platform - Main JavaScript

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
            
            if (networkSelector) {
                networkSelector.addEventListener('change', () => this.loadNetworkTraffic());
            }
            
            if (timeRangeSelector) {
                timeRangeSelector.addEventListener('change', () => this.loadNetworkTraffic());
            }
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

    async loadNetworkTraffic() {
        try {
            const networkFilter = document.getElementById('networkSelector')?.value || 'all';
            const timeRange = document.getElementById('timeRangeSelector')?.value || '1h';
            
            const response = await fetch(`${this.apiGateway}/traffic/flows?network=${networkFilter}&timeRange=${timeRange}`);
            const result = await response.json();
            
            // Process the flows data for the chart
            const flows = result.flows || [];
            const processedData = this.processTrafficFlows(flows, networkFilter);
            
            // Create network traffic chart
            this.createTrafficChart(processedData);
        } catch (error) {
            console.error('Error loading network traffic:', error);
        }
    }

    refreshTraffic() {
        this.loadNetworkTraffic();
    }

    processTrafficFlows(flows, networkFilter = 'all') {
        // Filter flows by network if specified
        let filteredFlows = flows;
        if (networkFilter !== 'all') {
            const networkPrefix = networkFilter.split('/')[0].substring(0, networkFilter.lastIndexOf('.'));
            filteredFlows = flows.filter(flow => 
                flow.src_ip.startsWith(networkPrefix) || flow.dest_ip.startsWith(networkPrefix)
            );
        }
        
        // Group flows by time and calculate traffic volumes
        const timeGroups = {};
        
        filteredFlows.forEach(flow => {
            // Parse the timestamp - it comes as GMT format like "Wed, 12 Nov 2025 19:15:29 GMT"
            const time = new Date(flow.start_time);
            
            // Convert to Montreal time (EST/EDT) and format for display
            const timeKey = time.toLocaleTimeString('en-US', { 
                hour12: false, 
                timeZone: 'America/Montreal',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit'
            });
            
            if (!timeGroups[timeKey]) {
                timeGroups[timeKey] = { inbound: 0, outbound: 0 };
            }
            
            // Convert bytes to KB
            timeGroups[timeKey].inbound += (flow.bytes_to_client || 0) / 1024;
            timeGroups[timeKey].outbound += (flow.bytes_to_server || 0) / 1024;
        });
        
        // Sort by time and prepare chart data - get last 20 data points
        const sortedTimes = Object.keys(timeGroups).sort().slice(-20);
        const timestamps = sortedTimes;
        const inbound = sortedTimes.map(time => Number(timeGroups[time].inbound.toFixed(2)));
        const outbound = sortedTimes.map(time => Number(timeGroups[time].outbound.toFixed(2)));
        
        console.log('Latest timestamps:', sortedTimes.slice(-3));
        console.log('Sample data - Inbound:', inbound.slice(-3), 'Outbound:', outbound.slice(-3));
        
        return { timestamps, inbound, outbound };
    }

    createTrafficChart(data) {
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