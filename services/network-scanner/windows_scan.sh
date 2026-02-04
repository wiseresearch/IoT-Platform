#!/bin/sh
# Windows-Compatible Network Scanner
# Uses host.docker.internal to discover network information

NETWORK_RANGE="${1:-172.20.10.0/24}"
OUTPUT_DIR="/scripts/results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="$OUTPUT_DIR/windows_scan_$TIMESTAMP.json"

mkdir -p "$OUTPUT_DIR"

echo "=== Windows Docker Desktop Network Discovery ==="
echo "Target: $NETWORK_RANGE"
echo "Host Gateway: $HOST_IP"
echo "Time: $(date)"
echo ""

# Create results structure
echo "{" > "$OUTPUT_FILE"
echo "  \"scan_time\": \"$(date -Iseconds)\"," >> "$OUTPUT_FILE"
echo "  \"network_range\": \"$NETWORK_RANGE\"," >> "$OUTPUT_FILE"
echo "  \"scanner\": \"nmap-windows-docker\"," >> "$OUTPUT_FILE"
echo "  \"host_gateway\": \"$HOST_IP\"," >> "$OUTPUT_FILE"

DISCOVERED_HOSTS=()

# Method 1: Scan host.docker.internal network range
echo "Method 1: Scanning Docker Host Gateway Network"
nmap -sn -T4 host.docker.internal > /tmp/host_scan.txt 2>&1
HOST_GATEWAY_IP=$(grep -oP '(\d+\.\d+\.\d+\.\d+)' /tmp/host_scan.txt | head -1)

if [ -n "$HOST_GATEWAY_IP" ]; then
    echo "Docker host gateway found at: $HOST_GATEWAY_IP"
    DISCOVERED_HOSTS+=("$HOST_GATEWAY_IP")
    
    # Try to scan the host gateway's network
    GATEWAY_NETWORK=$(echo "$HOST_GATEWAY_IP" | sed 's/\.[0-9]*$/.0\/24/')
    echo "Attempting to scan gateway network: $GATEWAY_NETWORK"
    
    nmap -sn -T4 "$GATEWAY_NETWORK" > /tmp/gateway_scan.txt 2>&1
    GATEWAY_HOSTS=$(grep -oP '(\d+\.\d+\.\d+\.\d+)' /tmp/gateway_scan.txt | sort -u)
    
    for host in $GATEWAY_HOSTS; do
        if [[ ! " ${DISCOVERED_HOSTS[@]} " =~ " $host " ]]; then
            DISCOVERED_HOSTS+=("$host")
            echo "Gateway network scan found: $host"
        fi
    done
fi

# Method 2: TCP connect to known common router/gateway IPs in target range
echo ""
echo "Method 2: TCP probing common device IPs"
COMMON_IPS=("172.20.10.1" "172.20.10.2" "172.20.10.15" "172.20.10.10" "172.20.10.100" "172.20.10.254")

for ip in "${COMMON_IPS[@]}"; do
    # Test if IP responds to common ports
    for port in 80 443 135 139 445 22 23 53 8080; do
        timeout 2 bash -c "</dev/tcp/$ip/$port" 2>/dev/null
        if [ $? -eq 0 ]; then
            if [[ ! " ${DISCOVERED_HOSTS[@]} " =~ " $ip " ]]; then
                DISCOVERED_HOSTS+=("$ip")
                echo "TCP probe found: $ip:$port"
            fi
            break
        fi
    done
done

# Method 3: Ping sweep with aggressive timing (Windows-friendly)
echo ""
echo "Method 3: Windows-optimized ping sweep"
nmap -sn -PE -PA80,443,135 -T4 --max-retries 1 --host-timeout 3s "$NETWORK_RANGE" > /tmp/ping_sweep.txt 2>&1
PING_HOSTS=$(grep -oP '(\d+\.\d+\.\d+\.\d+)' /tmp/ping_sweep.txt | sort -u)

for host in $PING_HOSTS; do
    if [[ ! " ${DISCOVERED_HOSTS[@]} " =~ " $host " ]]; then
        DISCOVERED_HOSTS+=("$host")
        echo "Ping sweep found: $host"
    fi
done

# Build JSON output
echo "  \"methods_used\": [\"host_gateway\", \"tcp_probe\", \"ping_sweep\"]," >> "$OUTPUT_FILE"
echo "  \"total_hosts_found\": ${#DISCOVERED_HOSTS[@]}," >> "$OUTPUT_FILE"

if [ ${#DISCOVERED_HOSTS[@]} -gt 0 ]; then
    echo "  \"hosts\": [" >> "$OUTPUT_FILE"
    
    for i in "${!DISCOVERED_HOSTS[@]}"; do
        host="${DISCOVERED_HOSTS[$i]}"
        
        if [ $i -gt 0 ]; then
            echo "," >> "$OUTPUT_FILE"
        fi
        
        echo -n "    {" >> "$OUTPUT_FILE"
        echo -n "\"ip\": \"$host\", " >> "$OUTPUT_FILE"
        echo -n "\"status\": \"up\", " >> "$OUTPUT_FILE"
        
        # Quick service scan
        echo -n "\"services\": [" >> "$OUTPUT_FILE"
        
        OPEN_PORTS=()
        for port in 22 23 53 80 135 139 443 445 993 995 8080; do
            timeout 1 bash -c "</dev/tcp/$host/$port" 2>/dev/null
            if [ $? -eq 0 ]; then
                OPEN_PORTS+=("$port")
            fi
        done
        
        for j in "${!OPEN_PORTS[@]}"; do
            port="${OPEN_PORTS[$j]}"
            if [ $j -gt 0 ]; then
                echo -n "," >> "$OUTPUT_FILE"
            fi
            echo -n "{\"port\": $port, \"state\": \"open\"}" >> "$OUTPUT_FILE"
        done
        
        echo -n "]," >> "$OUTPUT_FILE"
        
        # Device type inference
        DEVICE_TYPE="Unknown Device"
        if [[ " ${OPEN_PORTS[@]} " =~ " 80 " ]] || [[ " ${OPEN_PORTS[@]} " =~ " 443 " ]]; then
            DEVICE_TYPE="Web Server/Router"
        elif [[ " ${OPEN_PORTS[@]} " =~ " 135 " ]] || [[ " ${OPEN_PORTS[@]} " =~ " 139 " ]] || [[ " ${OPEN_PORTS[@]} " =~ " 445 " ]]; then
            DEVICE_TYPE="Windows Device"
        elif [[ " ${OPEN_PORTS[@]} " =~ " 22 " ]]; then
            DEVICE_TYPE="Linux/Unix Device"
        elif [[ " ${OPEN_PORTS[@]} " =~ " 23 " ]]; then
            DEVICE_TYPE="Network Device"
        fi
        
        echo -n "\"device_type\": \"$DEVICE_TYPE\"" >> "$OUTPUT_FILE"
        echo -n "}" >> "$OUTPUT_FILE"
    done
    
    echo "" >> "$OUTPUT_FILE"
    echo "  ]" >> "$OUTPUT_FILE"
else
    echo "  \"hosts\": []" >> "$OUTPUT_FILE"
fi

echo "}" >> "$OUTPUT_FILE"

echo ""
echo "=== Scan Summary ==="
echo "Total hosts discovered: ${#DISCOVERED_HOSTS[@]}"
for host in "${DISCOVERED_HOSTS[@]}"; do
    echo "  - $host"
done

echo ""
echo "Full results:"
cat "$OUTPUT_FILE"

echo ""
echo "Results saved to: $OUTPUT_FILE"