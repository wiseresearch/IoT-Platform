FROM ubuntu:22.04

# Install network tools and dependencies
RUN apt-get update && apt-get install -y \
    iptables \
    nftables \
    iproute2 \
    suricata \
    python3 \
    python3-pip \
    curl \
    net-tools \
    procps \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Copy application files
COPY nat_router.py /app/nat_router.py
COPY start_nat_router.sh /app/start_nat_router.sh
COPY requirements.txt /app/requirements.txt

WORKDIR /app

# Install Python dependencies
RUN pip3 install -r requirements.txt

# Create directories
RUN mkdir -p /var/log/suricata
RUN mkdir -p /etc/suricata
RUN chmod +x /app/start_nat_router.sh

# Expose port
EXPOSE 5050

# Run the NAT router
CMD ["/app/start_nat_router.sh"]
