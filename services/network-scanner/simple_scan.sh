#!/bin/sh
# Windows-Compatible Network Scanner (POSIX sh)

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

DISCOVERED_HOSTS=""

# Method 1: Scan host.docker.internal
echo "Method 1: Scanning Docker Host Gateway"
nmap -sn -T4 host.docker.internal > /tmp/host_scan.txt 2>&1
HOST_GATEWAY_IP=$(grep -oP '(\d+\.\d+\.\d+\.\d+)' /tmp/host_scan.txt 2>/dev/null | head -1)

if [ -n "$HOST_GATEWAY_IP" ]; then
    echo "Docker host gateway found at: $HOST_GATEWAY_IP"
    DISCOVERED_HOSTS="$HOST_GATEWAY_IP"
fi

# Method 2: TCP connect to known IPs
echo ""
echo "Method 2: TCP probing common device IPs"

test_tcp_port() {
    ip="$1"
    port="$2"
    nc -z -w1 "$ip" "$port" 2>/dev/null
    return $?
}

# Test common IPs
for ip in 172.20.10.1 172.20.10.2 172.20.10.15 172.20.10.10; do
    found=0
    for port in 80 443 135 139 445 22 23 53; do
        if test_tcp_port "$ip" "$port"; then
            echo "TCP probe found: $ip:$port"
            
            # Check if IP already in list
            echo "$DISCOVERED_HOSTS" | grep -q "$ip" || {
                if [ -n "$DISCOVERED_HOSTS" ]; then
                    DISCOVERED_HOSTS="$DISCOVERED_HOSTS $ip"
                else
                    DISCOVERED_HOSTS="$ip"
                fi
            }
            found=1
            break
        fi
    done
done

# Method 3: Basic nmap scan
echo ""
echo "Method 3: Direct nmap scan"
nmap -sn -T4 --max-retries 1 "$NETWORK_RANGE" > /tmp/nmap_scan.txt 2>&1
NMAP_HOSTS=$(grep -oP '(\d+\.\d+\.\d+\.\d+)' /tmp/nmap_scan.txt 2>/dev/null)

for host in $NMAP_HOSTS; do
    echo "$DISCOVERED_HOSTS" | grep -q "$host" || {
        if [ -n "$DISCOVERED_HOSTS" ]; then
            DISCOVERED_HOSTS="$DISCOVERED_HOSTS $host"
        else
            DISCOVERED_HOSTS="$host"
        fi
        echo "Nmap scan found: $host"
    }
done

# Count hosts
HOST_COUNT=0
if [ -n "$DISCOVERED_HOSTS" ]; then
    for h in $DISCOVERED_HOSTS; do
        HOST_COUNT=$((HOST_COUNT + 1))
    done
fi

# Build JSON output
echo "  \"methods_used\": [\"host_gateway\", \"tcp_probe\", \"nmap_direct\"]," >> "$OUTPUT_FILE"
echo "  \"total_hosts_found\": $HOST_COUNT," >> "$OUTPUT_FILE"

if [ $HOST_COUNT -gt 0 ]; then
    echo "  \"hosts\": [" >> "$OUTPUT_FILE"
    
    first=1
    for host in $DISCOVERED_HOSTS; do
        if [ $first -eq 0 ]; then
            echo "," >> "$OUTPUT_FILE"
        fi
        first=0
        
        echo -n "    {" >> "$OUTPUT_FILE"
        echo -n "\"ip\": \"$host\", " >> "$OUTPUT_FILE"
        echo -n "\"status\": \"up\", " >> "$OUTPUT_FILE"
        
        # Quick service scan
        echo -n "\"services\": [" >> "$OUTPUT_FILE"
        
        open_ports=""
        for port in 22 23 53 80 135 139 443 445 8080; do
            if test_tcp_port "$host" "$port"; then
                if [ -n "$open_ports" ]; then
                    open_ports="$open_ports $port"
                else
                    open_ports="$port"
                fi
            fi
        done
        
        first_port=1
        for port in $open_ports; do
            if [ $first_port -eq 0 ]; then
                echo -n "," >> "$OUTPUT_FILE"
            fi
            first_port=0
            echo -n "{\"port\": $port, \"state\": \"open\"}" >> "$OUTPUT_FILE"
        done
        
        echo -n "]," >> "$OUTPUT_FILE"
        
        # Device type inference
        device_type="Unknown Device"
        echo "$open_ports" | grep -q "80\|443" && device_type="Web Server/Router"
        echo "$open_ports" | grep -q "135\|139\|445" && device_type="Windows Device"  
        echo "$open_ports" | grep -q "22" && device_type="Linux/Unix Device"
        echo "$open_ports" | grep -q "23" && device_type="Network Device"
        
        echo -n "\"device_type\": \"$device_type\"" >> "$OUTPUT_FILE"
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
echo "Total hosts discovered: $HOST_COUNT"
if [ -n "$DISCOVERED_HOSTS" ]; then
    for host in $DISCOVERED_HOSTS; do
        echo "  - $host"
    done
fi

echo ""
echo "Full results:"
cat "$OUTPUT_FILE"

echo ""
echo "Results saved to: $OUTPUT_FILE"