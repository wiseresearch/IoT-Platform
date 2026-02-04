#!/bin/sh
# WSL2 Network Scanner - Optimized for Docker Desktop with WSL2 backend

NETWORK_RANGE="${1:-172.20.10.0/24}"
OUTPUT_DIR="/scripts/results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="$OUTPUT_DIR/wsl2_scan_$TIMESTAMP.json"

mkdir -p "$OUTPUT_DIR"

echo "=== WSL2-Optimized Network Discovery ==="
echo "Target: $NETWORK_RANGE"
echo "Time: $(date)"
echo ""

# Initialize results
echo "{" > "$OUTPUT_FILE"
echo "  \"scan_time\": \"$(date -Iseconds)\"," >> "$OUTPUT_FILE"
echo "  \"network_range\": \"$NETWORK_RANGE\"," >> "$OUTPUT_FILE"
echo "  \"scanner\": \"nmap-wsl2\"," >> "$OUTPUT_FILE"

DISCOVERED_HOSTS=""

# Method 1: Check available network interfaces
echo "Method 1: Examining network interfaces"
echo "Available interfaces:"
ip route show 2>/dev/null | grep -E "172\.20\.10\." || echo "No direct 172.20.10.x routes found"

# Method 2: WSL2 host network access
echo ""
echo "Method 2: WSL2 Host Network Bridge"

# Try scanning common gateway addresses
for gateway in "172.20.10.1" "192.168.1.1" "10.0.0.1"; do
    echo "Testing gateway: $gateway"
    if nmap -sn -T5 --max-retries 1 --host-timeout 2s "$gateway" 2>/dev/null | grep -q "Host is up"; then
        echo "Gateway $gateway is reachable"
        
        # Extract network and scan it
        GATEWAY_NET=$(echo "$gateway" | sed 's/\.[0-9]*$/.0\/24/')
        echo "Scanning gateway network: $GATEWAY_NET"
        
        SCAN_RESULT=$(nmap -sn -T4 --max-retries 2 "$GATEWAY_NET" 2>/dev/null | grep -oP 'Nmap scan report for \K[0-9.]+' | head -10)
        
        if [ -n "$SCAN_RESULT" ]; then
            echo "Found hosts via gateway scan:"
            echo "$SCAN_RESULT"
            DISCOVERED_HOSTS="$DISCOVERED_HOSTS $SCAN_RESULT"
        fi
        break
    fi
done

# Method 3: Direct target network scan with aggressive settings
echo ""
echo "Method 3: Direct aggressive scan of target network"
DIRECT_SCAN=$(nmap -sn -PE -PA21,22,23,25,53,80,110,135,139,143,443,993,995 -T5 --min-parallelism 100 --max-retries 1 "$NETWORK_RANGE" 2>/dev/null | grep -oP 'Nmap scan report for \K[0-9.]+')

if [ -n "$DIRECT_SCAN" ]; then
    echo "Direct scan found:"
    echo "$DIRECT_SCAN"
    DISCOVERED_HOSTS="$DISCOVERED_HOSTS $DIRECT_SCAN"
fi

# Method 4: ARP-based discovery (most reliable on local networks)
echo ""
echo "Method 4: ARP discovery"
ARP_SCAN=$(nmap -PR -sn "$NETWORK_RANGE" 2>/dev/null | grep -oP 'Nmap scan report for \K[0-9.]+')

if [ -n "$ARP_SCAN" ]; then
    echo "ARP scan found:"
    echo "$ARP_SCAN"
    DISCOVERED_HOSTS="$DISCOVERED_HOSTS $ARP_SCAN"
fi

# Method 5: TCP Connect scan on specific known IPs
echo ""
echo "Method 5: TCP Connect to known device IPs"
KNOWN_IPS="172.20.10.1 172.20.10.2 172.20.10.15 172.20.10.10 172.20.10.100"

for ip in $KNOWN_IPS; do
    # Test multiple ports quickly
    if nmap -sT -p80,443,22,135,139,445,23,53,8080 -T5 --max-retries 1 "$ip" 2>/dev/null | grep -q "open"; then
        echo "TCP connect found active device: $ip"
        DISCOVERED_HOSTS="$DISCOVERED_HOSTS $ip"
    fi
done

# Remove duplicates and sort
UNIQUE_HOSTS=$(echo "$DISCOVERED_HOSTS" | tr ' ' '\n' | sort -u | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | tr '\n' ' ')

HOST_COUNT=$(echo "$UNIQUE_HOSTS" | wc -w)

echo ""
echo "=== Results Summary ==="
echo "Total unique hosts discovered: $HOST_COUNT"
echo "Hosts: $UNIQUE_HOSTS"

# Build JSON
echo "  \"methods_used\": [\"interface_check\", \"gateway_bridge\", \"direct_aggressive\", \"arp_discovery\", \"tcp_connect\"]," >> "$OUTPUT_FILE"
echo "  \"total_hosts_found\": $HOST_COUNT," >> "$OUTPUT_FILE"

if [ "$HOST_COUNT" -gt 0 ]; then
    echo "  \"hosts\": [" >> "$OUTPUT_FILE"
    
    FIRST=true
    for host in $UNIQUE_HOSTS; do
        if [ -n "$host" ]; then
            if [ "$FIRST" = false ]; then
                echo "," >> "$OUTPUT_FILE"
            fi
            FIRST=false
            
            echo -n "    {" >> "$OUTPUT_FILE"
            echo -n "\"ip\": \"$host\", " >> "$OUTPUT_FILE"
            echo -n "\"status\": \"up\", " >> "$OUTPUT_FILE"
            
            # Quick service detection
            SERVICES=$(nmap -sT -p22,23,53,80,135,139,443,445,993,995,8080 -T5 --max-retries 1 "$host" 2>/dev/null | grep -E "^\d+/tcp.*open" | head -5)
            
            echo -n "\"open_ports\": [" >> "$OUTPUT_FILE"
            
            FIRST_PORT=true
            echo "$SERVICES" | while read -r line; do
                if [ -n "$line" ]; then
                    PORT=$(echo "$line" | grep -oP '^\d+')
                    if [ "$FIRST_PORT" = false ]; then
                        echo -n ","
                    fi
                    FIRST_PORT=false
                    echo -n "$PORT"
                fi
            done >> "$OUTPUT_FILE"
            
            echo -n "]}" >> "$OUTPUT_FILE"
        fi
    done
    
    echo "" >> "$OUTPUT_FILE"
    echo "  ]" >> "$OUTPUT_FILE"
else
    echo "  \"hosts\": []" >> "$OUTPUT_FILE"
fi

echo "}" >> "$OUTPUT_FILE"

echo ""
echo "Complete scan results:"
cat "$OUTPUT_FILE"

echo ""
echo "Results saved to: $OUTPUT_FILE"