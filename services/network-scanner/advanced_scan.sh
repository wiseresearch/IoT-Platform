#!/bin/bash
# Advanced Network Discovery Script
# Combines multiple scanning techniques for better Windows compatibility

NETWORK_RANGE="${1:-172.20.10.0/24}"
OUTPUT_DIR="/scripts/results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="$OUTPUT_DIR/advanced_scan_$TIMESTAMP.json"

mkdir -p "$OUTPUT_DIR"

echo "=== Advanced Network Discovery ==="
echo "Target: $NETWORK_RANGE"
echo "Time: $(date)"
echo ""

# Method 1: ICMP Ping Sweep
echo "Method 1: ICMP Ping Sweep"
nmap -sn -PE -PP -PM "$NETWORK_RANGE" > /tmp/icmp_scan.txt 2>&1
ICMP_HOSTS=$(grep -oP '(\d+\.\d+\.\d+\.\d+)' /tmp/icmp_scan.txt | sort -u)
echo "ICMP discovered: $(echo "$ICMP_HOSTS" | wc -w) hosts"

# Method 2: ARP Scan (most effective on local network)
echo "Method 2: ARP Scan"
nmap -PR "$NETWORK_RANGE" > /tmp/arp_scan.txt 2>&1
ARP_HOSTS=$(grep -oP '(\d+\.\d+\.\d+\.\d+)' /tmp/arp_scan.txt | sort -u)
echo "ARP discovered: $(echo "$ARP_HOSTS" | wc -w) hosts"

# Method 3: TCP SYN Scan on common ports
echo "Method 3: TCP SYN Scan"
nmap -PS80,443,135,139,445,22,23 "$NETWORK_RANGE" > /tmp/tcp_scan.txt 2>&1
TCP_HOSTS=$(grep -oP '(\d+\.\d+\.\d+\.\d+)' /tmp/tcp_scan.txt | sort -u)
echo "TCP discovered: $(echo "$TCP_HOSTS" | wc -w) hosts"

# Method 4: UDP Scan on common ports
echo "Method 4: UDP Scan"
nmap -PU53,67,68,161,500 "$NETWORK_RANGE" > /tmp/udp_scan.txt 2>&1
UDP_HOSTS=$(grep -oP '(\d+\.\d+\.\d+\.\d+)' /tmp/udp_scan.txt | sort -u)
echo "UDP discovered: $(echo "$UDP_HOSTS" | wc -w) hosts"

# Combine all discovered hosts
ALL_HOSTS=$(echo -e "$ICMP_HOSTS\n$ARP_HOSTS\n$TCP_HOSTS\n$UDP_HOSTS" | sort -u | grep -v '^$')

echo ""
echo "=== Combined Results ==="
echo "Total unique hosts found: $(echo "$ALL_HOSTS" | wc -w)"

# Generate detailed JSON report
echo "{" > "$OUTPUT_FILE"
echo "  \"scan_time\": \"$(date -Iseconds)\"," >> "$OUTPUT_FILE"
echo "  \"network_range\": \"$NETWORK_RANGE\"," >> "$OUTPUT_FILE"
echo "  \"scanner\": \"nmap-advanced\"," >> "$OUTPUT_FILE"
echo "  \"methods_used\": [\"icmp\", \"arp\", \"tcp_syn\", \"udp\"]," >> "$OUTPUT_FILE"
echo "  \"total_hosts_found\": $(echo "$ALL_HOSTS" | wc -w)," >> "$OUTPUT_FILE"

if [ -n "$ALL_HOSTS" ] && [ "$(echo "$ALL_HOSTS" | wc -w)" -gt 0 ]; then
    echo "  \"hosts\": [" >> "$OUTPUT_FILE"
    
    FIRST=true
    for host in $ALL_HOSTS; do
        if [ "$FIRST" = true ]; then
            FIRST=false
        else
            echo "," >> "$OUTPUT_FILE"
        fi
        
        echo -n "    {" >> "$OUTPUT_FILE"
        echo -n "\"ip\": \"$host\", " >> "$OUTPUT_FILE"
        
        # Determine discovery method
        METHODS=""
        echo "$ICMP_HOSTS" | grep -q "$host" && METHODS="${METHODS}icmp,"
        echo "$ARP_HOSTS" | grep -q "$host" && METHODS="${METHODS}arp,"
        echo "$TCP_HOSTS" | grep -q "$host" && METHODS="${METHODS}tcp,"
        echo "$UDP_HOSTS" | grep -q "$host" && METHODS="${METHODS}udp,"
        METHODS=$(echo "$METHODS" | sed 's/,$//')
        
        echo -n "\"discovery_methods\": \"$METHODS\", " >> "$OUTPUT_FILE"
        echo -n "\"status\": \"up\", " >> "$OUTPUT_FILE"
        
        # Quick service detection
        echo -n "\"services\": [" >> "$OUTPUT_FILE"
        SERVICE_SCAN=$(nmap -sV -p 22,23,80,135,139,443,445,993,995,8080 --version-intensity 0 "$host" 2>/dev/null | grep -E "^\d+/tcp.*open" | head -5)
        
        FIRST_SVC=true
        while IFS= read -r line; do
            if [ -n "$line" ]; then
                if [ "$FIRST_SVC" = true ]; then
                    FIRST_SVC=false
                else
                    echo -n "," >> "$OUTPUT_FILE"
                fi
                
                PORT=$(echo "$line" | grep -oP '^\d+')
                SERVICE=$(echo "$line" | grep -oP 'open\s+\K\S+' | head -1)
                echo -n "{\"port\": $PORT, \"service\": \"$SERVICE\"}" >> "$OUTPUT_FILE"
            fi
        done <<< "$SERVICE_SCAN"
        
        echo -n "]}" >> "$OUTPUT_FILE"
    done
    
    echo "" >> "$OUTPUT_FILE"
    echo "  ]" >> "$OUTPUT_FILE"
else
    echo "  \"hosts\": []" >> "$OUTPUT_FILE"
fi

echo "}" >> "$OUTPUT_FILE"

# Output summary
echo ""
echo "=== Scan Summary ==="
cat "$OUTPUT_FILE" | jq . 2>/dev/null || cat "$OUTPUT_FILE"

echo ""
echo "Results saved to: $OUTPUT_FILE"