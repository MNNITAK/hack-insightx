"""
VIRTUAL MACHINE COMPONENT DEFINITIONS
====================================

Each component represents a virtual machine with specific vulnerabilities,
data assets, and security characteristics for attack simulation.
"""

# =============================================================================
# COMPONENT DEFINITIONS
# =============================================================================

VM_COMPONENTS = {
    
    # WEB SERVER COMPONENTS
    "web_server": {
        "name": "Web Server",
        "type": "web_server",
        "os": "Ubuntu 20.04",
        "services": ["nginx", "php-fpm", "mysql-client"],
        "ports": [80, 443, 22],
        "vulnerabilities": [
            {
                "type": "SQL_INJECTION",
                "severity": "HIGH",
                "location": "login form, search functionality",
                "description": "User input not sanitized in database queries",
                "cve": "N/A - Application Logic Flaw"
            },
            {
                "type": "XSS",
                "severity": "MEDIUM", 
                "location": "comment sections, user profiles",
                "description": "User input displayed without proper encoding",
                "cve": "N/A - Application Logic Flaw"
            },
            {
                "type": "FILE_UPLOAD",
                "severity": "CRITICAL",
                "location": "upload directory /var/www/uploads/",
                "description": "No file type restrictions on uploads",
                "cve": "N/A - Configuration Issue"
            },
            {
                "type": "WEAK_SSH",
                "severity": "HIGH",
                "location": "SSH service",
                "description": "Weak passwords and root login enabled",
                "cve": "N/A - Configuration Issue"
            }
        ],
        "data_assets": [
            {
                "name": "Web Application Code",
                "type": "source_code",
                "sensitivity": "MEDIUM",
                "location": "/var/www/html/",
                "size": "50MB"
            },
            {
                "name": "Application Logs",
                "type": "logs",
                "sensitivity": "LOW",
                "location": "/var/log/nginx/",
                "size": "100MB"
            },
            {
                "name": "Configuration Files",
                "type": "config",
                "sensitivity": "HIGH",
                "location": "/etc/nginx/, /etc/php/",
                "size": "10MB"
            },
            {
                "name": "SSL Certificates",
                "type": "certificates",
                "sensitivity": "CRITICAL",
                "location": "/etc/ssl/certs/",
                "size": "5MB"
            }
        ],
        "user_accounts": [
            {"username": "www-data", "password": "N/A", "privileges": "service", "home": "/var/www/"},
            {"username": "nginx", "password": "N/A", "privileges": "service", "home": "/var/cache/nginx/"},
            {"username": "admin", "password": "admin123", "privileges": "sudo", "home": "/home/admin/"},
            {"username": "developer", "password": "dev2023", "privileges": "user", "home": "/home/developer/"}
        ],
        "network_config": {
            "interfaces": ["eth0"],
            "ip_address": "192.168.1.10",
            "gateway": "192.168.1.1",
            "dns": ["8.8.8.8", "1.1.1.1"]
        },
        "security_tools": ["fail2ban", "ufw"],
        "backup_schedule": "daily",
        "monitoring": ["nginx-status", "system-metrics"]
    },

    # DATABASE SERVER COMPONENTS  
    "database_server": {
        "name": "Database Server",
        "type": "database_server", 
        "os": "Ubuntu 20.04",
        "services": ["mysql", "ssh"],
        "ports": [3306, 22],
        "vulnerabilities": [
            {
                "type": "WEAK_DATABASE_CREDENTIALS",
                "severity": "CRITICAL",
                "location": "MySQL root account",
                "description": "Default and weak passwords for database accounts",
                "cve": "N/A - Configuration Issue"
            },
            {
                "type": "PRIVILEGE_ESCALATION",
                "severity": "HIGH",
                "location": "MySQL user permissions",
                "description": "Excessive privileges granted to application users",
                "cve": "N/A - Configuration Issue"
            },
            {
                "type": "UNENCRYPTED_CONNECTIONS",
                "severity": "MEDIUM",
                "location": "MySQL network traffic",
                "description": "Database connections not encrypted",
                "cve": "N/A - Configuration Issue"
            },
            {
                "type": "BACKUP_EXPOSURE",
                "severity": "HIGH",
                "location": "/var/backups/",
                "description": "Database backups stored without encryption",
                "cve": "N/A - Configuration Issue"
            }
        ],
        "data_assets": [
            {
                "name": "Customer Database",
                "type": "customer_data",
                "sensitivity": "CRITICAL",
                "location": "ecommerce.customers table",
                "size": "500MB",
                "records": 50000,
                "contains": ["PII", "payment_methods", "addresses", "purchase_history"]
            },
            {
                "name": "Product Catalog",
                "type": "business_data",
                "sensitivity": "MEDIUM", 
                "location": "ecommerce.products table",
                "size": "100MB",
                "records": 10000,
                "contains": ["product_info", "pricing", "inventory"]
            },
            {
                "name": "Financial Transactions",
                "type": "financial_data",
                "sensitivity": "CRITICAL",
                "location": "ecommerce.transactions table", 
                "size": "2GB",
                "records": 200000,
                "contains": ["payment_data", "order_amounts", "transaction_ids"]
            },
            {
                "name": "User Credentials",
                "type": "authentication_data",
                "sensitivity": "CRITICAL",
                "location": "ecommerce.users table",
                "size": "50MB",
                "records": 25000,
                "contains": ["usernames", "hashed_passwords", "email_addresses"]
            },
            {
                "name": "Database Backups",
                "type": "backup_data",
                "sensitivity": "CRITICAL",
                "location": "/var/backups/mysql/",
                "size": "3GB",
                "contains": ["complete_database_dumps", "binary_logs"]
            }
        ],
        "user_accounts": [
            {"username": "root", "password": "root123", "privileges": "DBA", "home": "/root/"},
            {"username": "mysql", "password": "N/A", "privileges": "service", "home": "/var/lib/mysql/"},
            {"username": "webapp", "password": "webapp2023", "privileges": "application", "home": "/home/webapp/"},
            {"username": "backup", "password": "backup456", "privileges": "backup", "home": "/home/backup/"},
            {"username": "dbadmin", "password": "admin789", "privileges": "sudo", "home": "/home/dbadmin/"}
        ],
        "network_config": {
            "interfaces": ["eth0"],
            "ip_address": "192.168.1.20", 
            "gateway": "192.168.1.1",
            "dns": ["8.8.8.8"]
        },
        "security_tools": ["mysql-audit"],
        "backup_schedule": "hourly",
        "monitoring": ["mysql-status", "replication-lag", "query-performance"]
    },

    # FIREWALL COMPONENTS
    "firewall": {
        "name": "Network Firewall",
        "type": "firewall",
        "os": "pfSense 2.6",
        "services": ["pf", "dhcp", "dns"],
        "ports": [53, 67, 443, 80],
        "vulnerabilities": [
            {
                "type": "DEFAULT_CREDENTIALS",
                "severity": "CRITICAL",
                "location": "Web management interface",
                "description": "Default admin credentials not changed",
                "cve": "N/A - Configuration Issue"
            },
            {
                "type": "PERMISSIVE_RULES",
                "severity": "HIGH",
                "location": "Firewall rule set",
                "description": "Overly permissive allow-all rules",
                "cve": "N/A - Configuration Issue"
            },
            {
                "type": "UNPATCHED_FIRMWARE",
                "severity": "MEDIUM",
                "location": "System firmware",
                "description": "Outdated firmware with known vulnerabilities",
                "cve": "CVE-2023-XXXX"
            }
        ],
        "data_assets": [
            {
                "name": "Firewall Rules",
                "type": "network_config",
                "sensitivity": "HIGH",
                "location": "/etc/pf.conf",
                "size": "1MB",
                "contains": ["network_topology", "access_rules", "port_mappings"]
            },
            {
                "name": "Network Logs",
                "type": "security_logs", 
                "sensitivity": "MEDIUM",
                "location": "/var/log/pflog/",
                "size": "500MB",
                "contains": ["connection_logs", "blocked_attempts", "traffic_patterns"]
            },
            {
                "name": "DHCP Leases",
                "type": "network_data",
                "sensitivity": "LOW",
                "location": "/var/dhcpd/dhcpd.leases",
                "size": "10MB",
                "contains": ["ip_assignments", "mac_addresses", "lease_times"]
            }
        ],
        "user_accounts": [
            {"username": "admin", "password": "pfsense", "privileges": "administrator", "home": "/home/admin/"},
            {"username": "operator", "password": "operator123", "privileges": "operator", "home": "/home/operator/"}
        ],
        "network_config": {
            "interfaces": ["em0", "em1", "em2"],
            "wan_ip": "203.0.113.10",
            "lan_ip": "192.168.1.1",
            "dmz_ip": "192.168.100.1"
        },
        "security_tools": ["pfBlockerNG", "Suricata", "ntopng"],
        "backup_schedule": "weekly",
        "monitoring": ["interface-status", "rule-performance", "threat-detection"]
    },

    # USER WORKSTATION COMPONENTS
    "user_workstation": {
        "name": "User Workstation", 
        "type": "workstation",
        "os": "Windows 10 Pro",
        "services": ["RDP", "SMB", "WinRM"],
        "ports": [3389, 445, 5985],
        "vulnerabilities": [
            {
                "type": "OUTDATED_OS",
                "severity": "HIGH",
                "location": "Windows Update",
                "description": "Missing critical security updates",
                "cve": "CVE-2023-XXXX, CVE-2023-YYYY"
            },
            {
                "type": "WEAK_RDP_CONFIG",
                "severity": "CRITICAL",
                "location": "Remote Desktop Service",
                "description": "RDP enabled without NLA, weak passwords",
                "cve": "N/A - Configuration Issue"
            },
            {
                "type": "ADMIN_SHARES",
                "severity": "MEDIUM",
                "location": "Administrative shares",
                "description": "Default administrative shares enabled",
                "cve": "N/A - Configuration Issue"
            },
            {
                "type": "BROWSER_VULNS",
                "severity": "MEDIUM",
                "location": "Internet Explorer, Chrome",
                "description": "Outdated browsers with known vulnerabilities",
                "cve": "CVE-2023-ZZZZ"
            }
        ],
        "data_assets": [
            {
                "name": "User Documents",
                "type": "business_documents",
                "sensitivity": "MEDIUM",
                "location": "C:\\Users\\*\\Documents\\",
                "size": "2GB",
                "contains": ["financial_reports", "contracts", "proposals", "presentations"]
            },
            {
                "name": "Browser Data",
                "type": "browsing_data",
                "sensitivity": "HIGH",
                "location": "C:\\Users\\*\\AppData\\Local\\",
                "size": "500MB",
                "contains": ["saved_passwords", "cookies", "browsing_history", "cached_credentials"]
            },
            {
                "name": "Email Cache",
                "type": "email_data",
                "sensitivity": "HIGH",
                "location": "C:\\Users\\*\\AppData\\Local\\Microsoft\\Outlook\\",
                "size": "1GB",
                "contains": ["email_messages", "contacts", "calendar_data", "attachments"]
            },
            {
                "name": "Registry Database",
                "type": "system_config",
                "sensitivity": "MEDIUM",
                "location": "C:\\Windows\\System32\\config\\",
                "size": "100MB",
                "contains": ["system_settings", "installed_software", "user_preferences"]
            },
            {
                "name": "Temporary Files",
                "type": "temp_data",
                "sensitivity": "LOW",
                "location": "C:\\Windows\\Temp\\, C:\\Users\\*\\AppData\\Local\\Temp\\",
                "size": "1GB",
                "contains": ["cached_files", "installation_files", "temporary_documents"]
            }
        ],
        "user_accounts": [
            {"username": "Administrator", "password": "Admin@123", "privileges": "administrator", "home": "C:\\Users\\Administrator\\"},
            {"username": "john.doe", "password": "Password123", "privileges": "user", "home": "C:\\Users\\john.doe\\"},
            {"username": "jane.smith", "password": "Welcome2023", "privileges": "user", "home": "C:\\Users\\jane.smith\\"},
            {"username": "it.support", "password": "Support456", "privileges": "power_user", "home": "C:\\Users\\it.support\\"}
        ],
        "network_config": {
            "interfaces": ["Ethernet"],
            "ip_address": "192.168.1.50",
            "gateway": "192.168.1.1", 
            "dns": ["192.168.1.1", "8.8.8.8"]
        },
        "security_tools": ["Windows Defender", "Event Viewer"],
        "backup_schedule": "none",
        "monitoring": ["event-logs", "performance-counters"]
    },

    # DOMAIN CONTROLLER COMPONENTS
    "domain_controller": {
        "name": "Active Directory Domain Controller",
        "type": "domain_controller",
        "os": "Windows Server 2019",
        "services": ["AD DS", "DNS", "LDAP", "Kerberos"],
        "ports": [389, 636, 88, 53, 445],
        "vulnerabilities": [
            {
                "type": "WEAK_DOMAIN_POLICY",
                "severity": "HIGH",
                "location": "Group Policy",
                "description": "Weak password policies and account lockout settings",
                "cve": "N/A - Configuration Issue"
            },
            {
                "type": "KERBEROS_ATTACKS",
                "severity": "CRITICAL",
                "location": "Kerberos Service",
                "description": "Vulnerable to Kerberoasting and ASREPRoast attacks",
                "cve": "N/A - Protocol Weakness"
            },
            {
                "type": "PRIVILEGED_ACCOUNTS",
                "severity": "HIGH",
                "location": "Domain Admin Group",
                "description": "Excessive privileged accounts and weak delegation",
                "cve": "N/A - Configuration Issue"
            }
        ],
        "data_assets": [
            {
                "name": "Active Directory Database",
                "type": "identity_data",
                "sensitivity": "CRITICAL",
                "location": "C:\\Windows\\NTDS\\ntds.dit",
                "size": "500MB",
                "contains": ["user_accounts", "password_hashes", "group_memberships", "computer_accounts"]
            },
            {
                "name": "SYSVOL Share",
                "type": "policy_data",
                "sensitivity": "HIGH",
                "location": "C:\\Windows\\SYSVOL\\",
                "size": "100MB",
                "contains": ["group_policies", "login_scripts", "administrative_templates"]
            },
            {
                "name": "Security Logs",
                "type": "audit_logs",
                "sensitivity": "HIGH",
                "location": "Windows Event Logs",
                "size": "200MB",
                "contains": ["authentication_events", "privilege_usage", "policy_changes"]
            }
        ],
        "user_accounts": [
            {"username": "Administrator", "password": "DomainAdmin2023!", "privileges": "domain_admin", "home": "C:\\Users\\Administrator\\"},
            {"username": "krbtgt", "password": "N/A", "privileges": "service", "home": "N/A"},
            {"username": "dc_service", "password": "ServicePass789", "privileges": "service", "home": "C:\\Users\\dc_service\\"}
        ],
        "network_config": {
            "interfaces": ["Ethernet"],
            "ip_address": "192.168.1.5",
            "gateway": "192.168.1.1",
            "dns": ["127.0.0.1"]
        },
        "security_tools": ["Windows Defender ATP", "SIEM Integration"],
        "backup_schedule": "daily",
        "monitoring": ["ad-health", "replication-status", "authentication-metrics"]
    },

    # LOAD BALANCER COMPONENTS
    "load_balancer": {
        "name": "Load Balancer",
        "type": "load_balancer", 
        "os": "HAProxy on CentOS 8",
        "services": ["haproxy", "ssh", "stats"],
        "ports": [80, 443, 22, 8404],
        "vulnerabilities": [
            {
                "type": "UNPROTECTED_STATS",
                "severity": "MEDIUM",
                "location": "Stats interface",
                "description": "Statistics interface accessible without authentication",
                "cve": "N/A - Configuration Issue"
            },
            {
                "type": "SSL_CONFIG",
                "severity": "HIGH",
                "location": "SSL/TLS configuration",
                "description": "Weak SSL ciphers and protocols enabled",
                "cve": "N/A - Configuration Issue"
            }
        ],
        "data_assets": [
            {
                "name": "HAProxy Configuration",
                "type": "network_config",
                "sensitivity": "HIGH",
                "location": "/etc/haproxy/haproxy.cfg",
                "size": "1MB",
                "contains": ["backend_servers", "load_balancing_rules", "ssl_certificates"]
            },
            {
                "name": "Access Logs",
                "type": "access_logs",
                "sensitivity": "MEDIUM",
                "location": "/var/log/haproxy/",
                "size": "1GB",
                "contains": ["http_requests", "response_times", "client_ips", "user_agents"]
            }
        ],
        "user_accounts": [
            {"username": "haproxy", "password": "N/A", "privileges": "service", "home": "/var/lib/haproxy/"},
            {"username": "admin", "password": "lb_admin123", "privileges": "sudo", "home": "/home/admin/"}
        ],
        "network_config": {
            "interfaces": ["eth0"],
            "ip_address": "192.168.1.30",
            "gateway": "192.168.1.1"
        },
        "security_tools": ["fail2ban"],
        "backup_schedule": "weekly",
        "monitoring": ["backend-health", "response-times", "connection-counts"]
    }
}

# =============================================================================
# COMPONENT RELATIONSHIPS AND DEPENDENCIES
# =============================================================================

COMPONENT_DEPENDENCIES = {
    "web_server": {
        "depends_on": ["database_server", "load_balancer"],
        "provides_to": ["user_workstation"],
        "network_access": ["database_server:3306", "load_balancer:80"]
    },
    "database_server": {
        "depends_on": [],
        "provides_to": ["web_server"],
        "network_access": ["backup_server:22"]
    },
    "firewall": {
        "depends_on": [],
        "provides_to": ["all_components"],
        "network_access": ["*:*"]
    },
    "user_workstation": {
        "depends_on": ["domain_controller", "web_server"],
        "provides_to": [],
        "network_access": ["domain_controller:389", "web_server:80"]
    },
    "domain_controller": {
        "depends_on": [],
        "provides_to": ["user_workstation"],
        "network_access": []
    },
    "load_balancer": {
        "depends_on": ["web_server"],
        "provides_to": ["external_users"],
        "network_access": ["web_server:80"]
    }
}

# =============================================================================
# ATTACK IMPACT CALCULATIONS
# =============================================================================

def get_component_by_type(component_type):
    """Get component definition by type"""
    return VM_COMPONENTS.get(component_type, {})

def calculate_attack_impact(component_type, attack_type):
    """Calculate what gets compromised when a specific attack hits a component"""
    component = get_component_by_type(component_type)
    if not component:
        return {"error": f"Unknown component type: {component_type}"}
    
    impact = {
        "component": component["name"],
        "attack_type": attack_type,
        "compromised_assets": [],
        "exposed_data": [],
        "credential_exposure": [],
        "lateral_movement_opportunities": [],
        "business_impact": "",
        "severity": "LOW"
    }
    
    # Analyze based on attack type and component vulnerabilities
    for vuln in component["vulnerabilities"]:
        if attack_matches_vulnerability(attack_type, vuln["type"]):
            impact = calculate_vulnerability_impact(component, vuln, impact)
    
    return impact

def attack_matches_vulnerability(attack_type, vuln_type):
    """Check if attack type exploits vulnerability type"""
    attack_vuln_mapping = {
        "sql_injection": ["SQL_INJECTION", "WEAK_DATABASE_CREDENTIALS"],
        "xss": ["XSS"],
        "brute_force": ["WEAK_SSH", "WEAK_DATABASE_CREDENTIALS", "DEFAULT_CREDENTIALS", "WEAK_RDP_CONFIG"],
        "file_upload": ["FILE_UPLOAD"],
        "privilege_escalation": ["PRIVILEGE_ESCALATION", "WEAK_DOMAIN_POLICY"],
        "lateral_movement": ["ADMIN_SHARES", "KERBEROS_ATTACKS", "PRIVILEGED_ACCOUNTS"],
        "data_exfiltration": ["BACKUP_EXPOSURE", "UNENCRYPTED_CONNECTIONS"]
    }
    
    return vuln_type in attack_vuln_mapping.get(attack_type, [])

def calculate_vulnerability_impact(component, vulnerability, impact):
    """Calculate impact when vulnerability is exploited"""
    
    vuln_type = vulnerability["type"]
    severity = vulnerability["severity"]
    
    # Update overall severity
    severity_levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    current_severity = severity_levels.get(impact["severity"], 1)
    new_severity = severity_levels.get(severity, 1)
    
    if new_severity > current_severity:
        impact["severity"] = severity
    
    # Add compromised assets based on vulnerability
    if vuln_type == "SQL_INJECTION":
        for asset in component["data_assets"]:
            if "customer_data" in asset["type"] or "authentication_data" in asset["type"]:
                impact["compromised_assets"].append(asset)
                impact["exposed_data"].extend(asset.get("contains", []))
        
        impact["business_impact"] = "Customer data breach, financial loss, regulatory fines"
        
    elif vuln_type == "WEAK_DATABASE_CREDENTIALS":
        for asset in component["data_assets"]:
            impact["compromised_assets"].append(asset)
            impact["exposed_data"].extend(asset.get("contains", []))
        
        for account in component["user_accounts"]:
            if account["privileges"] in ["DBA", "application"]:
                impact["credential_exposure"].append(account)
        
        impact["business_impact"] = "Complete database compromise, data theft, service disruption"
        
    elif vuln_type == "DEFAULT_CREDENTIALS":
        for account in component["user_accounts"]:
            if "admin" in account["username"]:
                impact["credential_exposure"].append(account)
        
        impact["lateral_movement_opportunities"].append("Administrative access to component")
        impact["business_impact"] = "Administrative access, potential for further compromise"
        
    elif vuln_type == "KERBEROS_ATTACKS":
        for account in component["user_accounts"]:
            impact["credential_exposure"].append(account)
        
        for asset in component["data_assets"]:
            if "identity_data" in asset["type"]:
                impact["compromised_assets"].append(asset)
                impact["exposed_data"].extend(asset.get("contains", []))
        
        impact["lateral_movement_opportunities"].extend([
            "Domain-wide credential access",
            "Golden ticket attacks",
            "Lateral movement to any domain system"
        ])
        impact["business_impact"] = "Domain compromise, complete network access, data breach"
        
    elif vuln_type == "FILE_UPLOAD":
        impact["lateral_movement_opportunities"].append("Web shell upload for remote code execution")
        impact["business_impact"] = "Server compromise, potential data access"
        
    elif vuln_type == "WEAK_RDP_CONFIG":
        for account in component["user_accounts"]:
            impact["credential_exposure"].append(account)
        
        for asset in component["data_assets"]:
            if asset["sensitivity"] in ["HIGH", "CRITICAL"]:
                impact["compromised_assets"].append(asset)
        
        impact["lateral_movement_opportunities"].append("Remote desktop access to workstation")
        impact["business_impact"] = "Workstation compromise, data theft, credential harvesting"
    
    return impact

def get_component_by_type(component_type):
    """Get VM component configuration by type"""
    
    # Normalize component type
    component_type = component_type.lower().strip()
    
    # Handle common type variations
    type_mapping = {
        "database": "database_server",
        "db": "database_server", 
        "mysql": "database_server",
        "postgres": "database_server",
        "web": "web_server",
        "webserver": "web_server",
        "nginx": "web_server",
        "apache": "web_server",
        "user": "user_workstation",
        "workstation": "user_workstation", 
        "laptop": "user_workstation",
        "desktop": "user_workstation",
        "fw": "firewall",
        "pfsense": "firewall",
        "router": "firewall"
    }
    
    # Map to standard type
    standard_type = type_mapping.get(component_type, component_type)
    
    return VM_COMPONENTS.get(standard_type)