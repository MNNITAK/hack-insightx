# Vulnerable User Workstation for Security Testing
FROM ubuntu:20.04

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install vulnerable services and tools
RUN apt-get update && apt-get install -y \
    openssh-server \
    vsftpd \
    apache2 \
    mysql-client \
    telnet \
    netcat \
    nmap \
    curl \
    wget \
    vim \
    python3 \
    python3-pip \
    rdp \
    xrdp \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip3 install flask requests paramiko

# Create vulnerable user accounts
RUN useradd -m -s /bin/bash -p $(openssl passwd -1 password123) user1
RUN useradd -m -s /bin/bash -p $(openssl passwd -1 admin123) admin
RUN useradd -m -s /bin/bash -p $(openssl passwd -1 "") guest

# Configure SSH with vulnerabilities
COPY ssh_config /etc/ssh/sshd_config

# Configure FTP with vulnerabilities
COPY vsftpd.conf /etc/vsftpd.conf

# Create vulnerable web application
COPY webapp/ /var/www/html/
RUN chown -R www-data:www-data /var/www/html/

# Copy vulnerable scripts and tools
COPY scripts/ /opt/workstation/
COPY user-behavior.py /opt/workstation/

# Create directories for logs and data
RUN mkdir -p /var/log/workstation \
             /home/shared \
             /opt/workstation

# Set vulnerable permissions
RUN chmod 777 /home/shared
RUN chmod +x /opt/workstation/*.py
RUN chmod +x /opt/workstation/*.sh

# Copy supervisor configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose vulnerable services
EXPOSE 22 21 80 3389 23

# Start services via supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]