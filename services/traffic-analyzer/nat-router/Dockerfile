FROM ubuntu:22.04

# Install network tools and dependencies
RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    python3 \
    python3-pip \
    curl \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy application files
COPY nat_router.py /app/nat_router.py
COPY requirements.txt /app/requirements.txt

WORKDIR /app

# Install Python dependencies
RUN pip3 install -r requirements.txt

# Create directories
RUN mkdir -p /var/log/suricata
RUN mkdir -p /etc/suricata

# Expose port
EXPOSE 5050

# Run the NAT router
CMD ["python3", "nat_router.py"]