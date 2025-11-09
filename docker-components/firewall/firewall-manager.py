#!/usr/bin/env python3
"""
🔥 Vulnerable Firewall Manager
Simulates a network firewall with configurable security levels
"""

from flask import Flask, request, jsonify
import subprocess
import logging
import os
import time
from datetime import datetime

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/firewall/firewall.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class VirtualFirewall:
    def __init__(self):
        self.current_profile = "vulnerable"  # Default to vulnerable
        self.blocked_ips = set()
        self.allowed_ports = {80, 443, 22}  # Default open ports
        self.rules = []
        self.traffic_logs = []
        
    def set_security_profile(self, profile):
        """Set firewall security profile"""
        if profile == "vulnerable":
            self._apply_vulnerable_rules()
        elif profile == "secure":
            self._apply_secure_rules()
        elif profile == "disabled":
            self._disable_firewall()
        
        self.current_profile = profile
        logger.info(f"🔥 Firewall profile changed to: {profile}")
        
    def _apply_vulnerable_rules(self):
        """Apply vulnerable firewall configuration"""
        self.rules = [
            "# Vulnerable Firewall Rules",
            "# Allow all incoming traffic (DANGEROUS)",
            "iptables -P INPUT ACCEPT",
            "iptables -P FORWARD ACCEPT", 
            "iptables -P OUTPUT ACCEPT",
            "# Clear all existing rules",
            "iptables -F",
            "iptables -X",
            "iptables -t nat -F",
            "iptables -t nat -X",
            "# Log everything for testing",
            "iptables -A INPUT -j LOG --log-prefix='FIREWALL_IN: '",
            "iptables -A OUTPUT -j LOG --log-prefix='FIREWALL_OUT: '",
        ]
        self._execute_rules()
        
    def _apply_secure_rules(self):
        """Apply secure firewall configuration"""
        self.rules = [
            "# Secure Firewall Rules",
            "# Default deny all",
            "iptables -P INPUT DROP",
            "iptables -P FORWARD DROP",
            "iptables -P OUTPUT ACCEPT",
            "# Clear existing rules",
            "iptables -F",
            "iptables -X",
            "# Allow loopback",
            "iptables -A INPUT -i lo -j ACCEPT",
            "# Allow established connections",
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            "# Allow specific ports only",
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 443 -j ACCEPT",
            "# Block known bad IPs",
            *[f"iptables -A INPUT -s {ip} -j DROP" for ip in self.blocked_ips],
            "# Log dropped packets",
            "iptables -A INPUT -j LOG --log-prefix='FIREWALL_BLOCK: '",
            "iptables -A INPUT -j DROP"
        ]
        self._execute_rules()
        
    def _disable_firewall(self):
        """Completely disable firewall (VERY DANGEROUS)"""
        self.rules = [
            "# Firewall Disabled - DANGER!",
            "iptables -P INPUT ACCEPT",
            "iptables -P FORWARD ACCEPT",
            "iptables -P OUTPUT ACCEPT", 
            "iptables -F",
            "iptables -X",
            "iptables -t nat -F",
            "iptables -t nat -X"
        ]
        self._execute_rules()
        
    def _execute_rules(self):
        """Execute iptables rules"""
        for rule in self.rules:
            if rule.startswith('#') or not rule.strip():
                continue
            try:
                subprocess.run(rule.split(), check=True, capture_output=True)
                logger.info(f"✅ Executed: {rule}")
            except subprocess.CalledProcessError as e:
                logger.error(f"❌ Failed to execute: {rule} - {e}")
                
    def block_ip(self, ip_address):
        """Block specific IP address"""
        self.blocked_ips.add(ip_address)
        if self.current_profile == "secure":
            rule = f"iptables -A INPUT -s {ip_address} -j DROP"
            try:
                subprocess.run(rule.split(), check=True)
                logger.warning(f"🚫 Blocked IP: {ip_address}")
                return True
            except subprocess.CalledProcessError as e:
                logger.error(f"❌ Failed to block IP {ip_address}: {e}")
                return False
        return True
        
    def unblock_ip(self, ip_address):
        """Unblock specific IP address"""
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
            # Reapply rules to remove the block
            self.set_security_profile(self.current_profile)
            logger.info(f"✅ Unblocked IP: {ip_address}")
            return True
        return False
        
    def log_traffic(self, source_ip, dest_port, protocol, action):
        """Log network traffic"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': source_ip,
            'dest_port': dest_port,
            'protocol': protocol,
            'action': action,
            'firewall_profile': self.current_profile
        }
        self.traffic_logs.append(log_entry)
        
        # Keep only last 1000 entries
        if len(self.traffic_logs) > 1000:
            self.traffic_logs = self.traffic_logs[-1000:]
            
        logger.info(f"📊 Traffic: {source_ip}:{dest_port} {protocol} {action}")
        
    def get_status(self):
        """Get current firewall status"""
        return {
            'profile': self.current_profile,
            'blocked_ips': list(self.blocked_ips),
            'allowed_ports': list(self.allowed_ports),
            'rules_count': len(self.rules),
            'traffic_logs_count': len(self.traffic_logs)
        }

# Initialize firewall
firewall = VirtualFirewall()

@app.route('/status', methods=['GET'])
def get_status():
    """Get firewall status"""
    return jsonify(firewall.get_status())

@app.route('/profile', methods=['POST'])
def set_profile():
    """Change firewall security profile"""
    data = request.get_json()
    profile = data.get('profile', 'vulnerable')
    
    if profile not in ['vulnerable', 'secure', 'disabled']:
        return jsonify({'error': 'Invalid profile'}), 400
        
    firewall.set_security_profile(profile)
    return jsonify({'status': 'success', 'profile': profile})

@app.route('/block', methods=['POST'])
def block_ip():
    """Block IP address"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({'error': 'IP address required'}), 400
        
    success = firewall.block_ip(ip_address)
    return jsonify({'status': 'success' if success else 'error'})

@app.route('/unblock', methods=['POST']) 
def unblock_ip():
    """Unblock IP address"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({'error': 'IP address required'}), 400
        
    success = firewall.unblock_ip(ip_address)
    return jsonify({'status': 'success' if success else 'error'})

@app.route('/logs', methods=['GET'])
def get_logs():
    """Get traffic logs"""
    limit = request.args.get('limit', 100, type=int)
    return jsonify({
        'logs': firewall.traffic_logs[-limit:],
        'total_count': len(firewall.traffic_logs)
    })

@app.route('/simulate_traffic', methods=['POST'])
def simulate_traffic():
    """Simulate network traffic for testing"""
    data = request.get_json()
    source_ip = data.get('source_ip', '192.168.1.100')
    dest_port = data.get('dest_port', 80)
    protocol = data.get('protocol', 'TCP')
    
    # Determine action based on firewall rules
    if firewall.current_profile == 'disabled':
        action = 'ALLOWED'
    elif firewall.current_profile == 'vulnerable':
        action = 'ALLOWED'  # Vulnerable allows everything
    elif source_ip in firewall.blocked_ips:
        action = 'BLOCKED'
    elif dest_port in firewall.allowed_ports:
        action = 'ALLOWED'
    else:
        action = 'BLOCKED'
        
    firewall.log_traffic(source_ip, dest_port, protocol, action)
    
    return jsonify({
        'source_ip': source_ip,
        'dest_port': dest_port,
        'protocol': protocol,
        'action': action,
        'firewall_profile': firewall.current_profile
    })

@app.route('/rules', methods=['GET'])
def get_rules():
    """Get current firewall rules"""
    return jsonify({
        'profile': firewall.current_profile,
        'rules': firewall.rules
    })

@app.route('/attack_simulation', methods=['POST'])
def attack_simulation():
    """Simulate various network attacks"""
    data = request.get_json()
    attack_type = data.get('attack_type', 'port_scan')
    source_ip = data.get('source_ip', '10.0.0.100')
    
    results = []
    
    if attack_type == 'port_scan':
        # Simulate port scanning
        for port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 6379]:
            action = 'ALLOWED' if firewall.current_profile != 'secure' or port in firewall.allowed_ports else 'BLOCKED'
            firewall.log_traffic(source_ip, port, 'TCP', action)
            results.append({'port': port, 'action': action})
            
    elif attack_type == 'brute_force':
        # Simulate brute force attack
        for attempt in range(1, 11):
            action = 'ALLOWED' if firewall.current_profile != 'secure' else 'BLOCKED'
            firewall.log_traffic(source_ip, 22, 'TCP', action)
            results.append({'attempt': attempt, 'action': action})
            
    elif attack_type == 'ddos':
        # Simulate DDoS attack
        for i in range(50):
            fake_ip = f"10.0.{i//10}.{i%10}"
            action = 'ALLOWED' if firewall.current_profile != 'secure' else 'BLOCKED'
            firewall.log_traffic(fake_ip, 80, 'TCP', action)
            results.append({'source_ip': fake_ip, 'action': action})
            
    return jsonify({
        'attack_type': attack_type,
        'source_ip': source_ip,
        'results': results,
        'firewall_effectiveness': 'LOW' if firewall.current_profile == 'vulnerable' else 'HIGH'
    })

if __name__ == '__main__':
    # Initialize with vulnerable profile
    firewall.set_security_profile('vulnerable')
    logger.info("🔥 Virtual Firewall Manager started")
    
    # Run Flask app
    app.run(host='0.0.0.0', port=8080, debug=False)