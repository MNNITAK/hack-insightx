# Vulnerable Firewall Component for Security Testing
FROM alpine:latest

# Install firewall and networking tools
RUN apk add --no-cache \
    iptables \
    netcat-openbsd \
    tcpdump \
    nmap \
    curl \
    bash \
    python3 \
    py3-pip

# Install Python packages for firewall management
RUN pip3 install flask requests

# Create directories
RUN mkdir -p /etc/firewall/rules \
             /var/log/firewall \
             /opt/firewall

# Copy firewall configuration and scripts
COPY rules/ /etc/firewall/rules/
COPY scripts/ /opt/firewall/
COPY firewall-manager.py /opt/firewall/

# Copy vulnerable firewall rules
COPY iptables-vulnerable.sh /opt/firewall/
COPY iptables-secure.sh /opt/firewall/

# Make scripts executable
RUN chmod +x /opt/firewall/*.sh
RUN chmod +x /opt/firewall/*.py

# Expose management port
EXPOSE 8080

# Set working directory
WORKDIR /opt/firewall

# Start firewall manager
CMD ["python3", "firewall-manager.py"]