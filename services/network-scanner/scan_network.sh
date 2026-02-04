#!/bin/bash
# Network Scanner Script for Docker Container
# Usage: ./scan_network.sh [network_range]

NETWORK_RANGE="${1:-172.20.10.0/24}"
OUTPUT_DIR="/scripts/results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="$OUTPUT_DIR/scan_$TIMESTAMP.json"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

echo "Starting network scan of $NETWORK_RANGE..."

# Perform comprehensive nmap scan
nmap -sn -T4 "$NETWORK_RANGE" > /tmp/ping_scan.txt 2>&1

# Extract live hosts
LIVE_HOSTS=$(grep -oP '(\d+\.\d+\.\d+\.\d+)' /tmp/ping_scan.txt | sort -u)

# Create JSON output
echo "{" > "$OUTPUT_FILE"
echo "  \"scan_time\": \"$(date -Iseconds)\"," >> "$OUTPUT_FILE"
echo "  \"network_range\": \"$NETWORK_RANGE\"," >> "$OUTPUT_FILE"
echo "  \"scanner\": \"nmap\"," >> "$OUTPUT_FILE"
echo "  \"method\": \"ping_sweep\"," >> "$OUTPUT_FILE"

if [ -n "$LIVE_HOSTS" ]; then
    echo "  \"hosts_found\": [" >> "$OUTPUT_FILE"
    
    FIRST=true
    for host in $LIVE_HOSTS; do
        if [ "$FIRST" = true ]; then
            FIRST=false
        else
            echo "," >> "$OUTPUT_FILE"
        fi
        
        echo -n "    {" >> "$OUTPUT_FILE"
        echo -n "\"ip\": \"$host\", " >> "$OUTPUT_FILE"
        echo -n "\"status\": \"up\"" >> "$OUTPUT_FILE"
        
        # Quick port scan on discovered host
        echo ", \"ports\": [" >> "$OUTPUT_FILE"
        PORT_SCAN=$(nmap -p 22,23,80,135,139,443,445,8080 --open -T4 "$host" 2>/dev/null | grep -oP '\d+/tcp')
        
        FIRST_PORT=true
        for port in $PORT_SCAN; do
            if [ "$FIRST_PORT" = true ]; then
                FIRST_PORT=false
            else
                echo -n "," >> "$OUTPUT_FILE"
            fi
            echo -n "\"${port%/*}\"" >> "$OUTPUT_FILE"
        done
        
        echo -n "]}" >> "$OUTPUT_FILE"
    done
    
    echo "" >> "$OUTPUT_FILE"
    echo "  ]" >> "$OUTPUT_FILE"
else
    echo "  \"hosts_found\": []" >> "$OUTPUT_FILE"
fi

echo "}" >> "$OUTPUT_FILE"

# Output results to stdout as well
cat "$OUTPUT_FILE"

echo "Scan completed. Results saved to $OUTPUT_FILE"