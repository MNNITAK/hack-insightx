#!/usr/bin/env python3
"""
👤 User Behavior Simulator
Simulates realistic user behavior on a workstation for security testing
"""

import time
import random
import logging
import subprocess
import requests
import os
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/workstation/user_behavior.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class UserSimulator:
    def __init__(self):
        self.is_running = True
        self.vulnerability_level = "high"  # high, medium, low
        self.user_profiles = self._init_user_profiles()
        self.current_user = "user1"
        
    def _init_user_profiles(self):
        """Initialize different user behavior profiles"""
        return {
            "user1": {
                "name": "Regular Employee",
                "risk_level": "high",
                "behaviors": ["web_browsing", "email_checking", "file_downloads", "weak_passwords"],
                "vulnerability_factors": ["clicks_suspicious_links", "downloads_attachments", "uses_weak_passwords"]
            },
            "admin": {
                "name": "System Administrator", 
                "risk_level": "medium",
                "behaviors": ["system_administration", "database_access", "remote_connections"],
                "vulnerability_factors": ["elevated_privileges", "multiple_system_access", "shared_accounts"]
            },
            "guest": {
                "name": "Guest User",
                "risk_level": "low",
                "behaviors": ["basic_web_browsing", "limited_access"],
                "vulnerability_factors": ["limited_permissions", "temporary_access"]
            }
        }
    
    def simulate_web_browsing(self):
        """Simulate web browsing behavior"""
        websites = [
            "http://web_server/",
            "http://web_server/admin/",
            "http://malicious-site.example.com",  # Simulated malicious site
            "http://web_server/uploads/",
            "http://web_server/?search=<script>alert('xss')</script>",  # XSS attempt
        ]
        
        site = random.choice(websites)
        try:
            logger.info(f"🌐 User browsing: {site}")
            # Simulate clicking on suspicious links
            if "malicious" in site or "script" in site:
                logger.warning(f"⚠️ User clicked suspicious link: {site}")
                self._log_security_event("suspicious_link_clicked", site)
                
        except Exception as e:
            logger.error(f"❌ Browse error: {e}")
    
    def simulate_file_operations(self):
        """Simulate file operations that might be vulnerable"""
        operations = [
            self._download_suspicious_file,
            self._create_shared_file,
            self._access_sensitive_data,
            self._execute_unknown_binary
        ]
        
        operation = random.choice(operations)
        operation()
    
    def _download_suspicious_file(self):
        """Simulate downloading potentially malicious files"""
        suspicious_files = [
            "document.pdf.exe",
            "invoice.doc",
            "update.exe",
            "photo.jpg.scr"
        ]
        
        filename = random.choice(suspicious_files)
        logger.warning(f"⬇️ User downloaded suspicious file: {filename}")
        
        # Create the file to simulate download
        with open(f"/home/shared/{filename}", 'w') as f:
            f.write("# Simulated suspicious file content\n")
            f.write("# This would be malware in a real attack\n")
        
        self._log_security_event("suspicious_download", filename)
    
    def _create_shared_file(self):
        """Create files in shared directories"""
        filenames = ["passwords.txt", "customer_data.xlsx", "financial_report.pdf"]
        filename = random.choice(filenames)
        
        filepath = f"/home/shared/{filename}"
        with open(filepath, 'w') as f:
            f.write("# Sensitive data simulation\n")
            f.write(f"# Created by {self.current_user}\n")
            f.write("# This file contains sensitive information\n")
        
        # Set vulnerable permissions
        os.chmod(filepath, 0o777)
        logger.info(f"📁 Created shared file: {filename}")
    
    def _access_sensitive_data(self):
        """Simulate accessing sensitive data"""
        sensitive_paths = [
            "/etc/passwd",
            "/etc/shadow", 
            "/var/log/auth.log",
            "/home/admin/.ssh/id_rsa"
        ]
        
        path = random.choice(sensitive_paths)
        try:
            subprocess.run(['ls', '-la', path], capture_output=True)
            logger.warning(f"🔍 User accessed sensitive path: {path}")
            self._log_security_event("sensitive_access", path)
        except:
            pass
    
    def _execute_unknown_binary(self):
        """Simulate executing unknown/suspicious binaries"""
        logger.warning("⚡ User attempted to execute unknown binary")
        self._log_security_event("suspicious_execution", "unknown_binary.exe")
    
    def simulate_network_activity(self):
        """Simulate network activities"""
        activities = [
            self._ssh_connection,
            self._ftp_transfer,
            self._database_query,
            self._suspicious_network_scan
        ]
        
        activity = random.choice(activities)
        activity()
    
    def _ssh_connection(self):
        """Simulate SSH connections"""
        targets = ["database_server", "admin@web_server", "192.168.1.100"]
        target = random.choice(targets)
        
        logger.info(f"🔗 SSH connection attempt to: {target}")
        
        # Simulate weak password usage
        weak_passwords = ["password", "123456", "admin", "root"]
        password = random.choice(weak_passwords)
        
        logger.warning(f"🔑 Using weak password for SSH: {password}")
        self._log_security_event("weak_ssh_password", f"{target}:{password}")
    
    def _ftp_transfer(self):
        """Simulate FTP file transfers"""
        logger.info("📤 FTP file transfer simulation")
        self._log_security_event("ftp_transfer", "unencrypted_ftp")
    
    def _database_query(self):
        """Simulate database queries"""
        queries = [
            "SELECT * FROM users",
            "SELECT * FROM users WHERE username='admin' AND password='admin123'",
            "SELECT * FROM users WHERE username='' OR '1'='1'--",  # SQL injection
        ]
        
        query = random.choice(queries)
        logger.info(f"🗄️ Database query: {query}")
        
        if "OR '1'='1'" in query:
            logger.warning("🚨 SQL injection attempt detected")
            self._log_security_event("sql_injection_attempt", query)
    
    def _suspicious_network_scan(self):
        """Simulate network scanning (might indicate compromise)"""
        logger.warning("🔍 Network scanning detected from user workstation")
        self._log_security_event("network_scan", "internal_network")
    
    def simulate_credential_behavior(self):
        """Simulate various credential-related behaviors"""
        behaviors = [
            self._save_password_plaintext,
            self._share_credentials,
            self._use_default_passwords,
            self._password_reuse
        ]
        
        behavior = random.choice(behaviors)
        behavior()
    
    def _save_password_plaintext(self):
        """Simulate saving passwords in plain text"""
        with open("/home/shared/passwords.txt", "a") as f:
            f.write(f"Website: bank.com, Password: mypassword123\n")
            f.write(f"Email: user@company.com, Password: password123\n")
        
        logger.warning("🔑 User saved passwords in plain text file")
        self._log_security_event("plaintext_passwords", "passwords.txt")
    
    def _share_credentials(self):
        """Simulate sharing credentials inappropriately"""
        logger.warning("👥 User shared credentials via insecure channel")
        self._log_security_event("credential_sharing", "insecure_channel")
    
    def _use_default_passwords(self):
        """Simulate using default passwords"""
        default_creds = ["admin:admin", "root:root", "user:password"]
        cred = random.choice(default_creds)
        
        logger.warning(f"🔐 User using default credentials: {cred}")
        self._log_security_event("default_credentials", cred)
    
    def _password_reuse(self):
        """Simulate password reuse across systems"""
        logger.warning("♻️ Password reuse detected across multiple systems")
        self._log_security_event("password_reuse", "multiple_systems")
    
    def simulate_phishing_susceptibility(self):
        """Simulate user falling for phishing attacks"""
        scenarios = [
            "Clicked suspicious email link",
            "Downloaded email attachment",
            "Entered credentials on fake website",
            "Responded to fake IT support request"
        ]
        
        scenario = random.choice(scenarios)
        logger.warning(f"🎣 Phishing simulation: {scenario}")
        self._log_security_event("phishing_susceptible", scenario)
    
    def _log_security_event(self, event_type, details):
        """Log security-relevant events"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'user': self.current_user,
            'event_type': event_type,
            'details': details,
            'severity': self._get_event_severity(event_type)
        }
        
        # Write to security log
        with open("/var/log/workstation/security_events.log", "a") as f:
            f.write(f"{event}\n")
    
    def _get_event_severity(self, event_type):
        """Determine severity of security event"""
        high_severity = [
            "suspicious_link_clicked",
            "suspicious_download", 
            "sql_injection_attempt",
            "phishing_susceptible"
        ]
        
        medium_severity = [
            "sensitive_access",
            "weak_ssh_password",
            "plaintext_passwords"
        ]
        
        if event_type in high_severity:
            return "HIGH"
        elif event_type in medium_severity:
            return "MEDIUM"
        else:
            return "LOW"
    
    def run_simulation(self):
        """Main simulation loop"""
        logger.info("👤 Starting user behavior simulation")
        
        while self.is_running:
            try:
                # Randomly select user profile
                self.current_user = random.choice(list(self.user_profiles.keys()))
                profile = self.user_profiles[self.current_user]
                
                logger.info(f"🎭 Simulating user: {profile['name']}")
                
                # Simulate different types of activities
                activities = [
                    self.simulate_web_browsing,
                    self.simulate_file_operations,
                    self.simulate_network_activity,
                    self.simulate_credential_behavior,
                    self.simulate_phishing_susceptibility
                ]
                
                # Higher risk users perform more dangerous activities
                if profile['risk_level'] == 'high':
                    activity_count = random.randint(2, 4)
                elif profile['risk_level'] == 'medium':
                    activity_count = random.randint(1, 2)
                else:
                    activity_count = 1
                
                for _ in range(activity_count):
                    activity = random.choice(activities)
                    activity()
                    time.sleep(random.uniform(1, 5))
                
                # Sleep between user sessions
                sleep_time = random.uniform(30, 120)
                logger.info(f"😴 User session complete, sleeping for {sleep_time:.1f} seconds")
                time.sleep(sleep_time)
                
            except KeyboardInterrupt:
                logger.info("🛑 User simulation stopped")
                self.is_running = False
                break
            except Exception as e:
                logger.error(f"❌ Simulation error: {e}")
                time.sleep(10)

if __name__ == "__main__":
    simulator = UserSimulator()
    simulator.run_simulation()