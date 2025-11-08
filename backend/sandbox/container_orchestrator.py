"""
Virtual Cybersecurity Sandbox - Container Orchestrator
Maps InsightX architecture components to simulated containers
Rule-based container provisioning and network simulation
"""

import json
import time
import ipaddress
import random
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import subprocess
import threading

@dataclass
class ContainerConfig:
    """Configuration for a containerized component"""
    component_type: str
    container_name: str
    docker_image: str
    ports: List[int]
    environment_vars: Dict[str, str]
    volumes: Dict[str, str]
    network_settings: Dict[str, Any]
    security_config: Dict[str, Any]
    monitoring_agents: List[str]
    startup_commands: List[str]
    
@dataclass
class SandboxEnvironment:
    """Complete sandbox environment state"""
    sandbox_id: str
    architecture_id: str
    status: str  # "deploying", "running", "attacking", "stopped", "error"
    containers: Dict[str, ContainerConfig]
    networks: Dict[str, Dict[str, Any]]
    attack_history: List[Dict[str, Any]]
    telemetry_data: List[Dict[str, Any]]
    created_at: str
    last_activity: str

class RuleBasedContainerOrchestrator:
    """
    Rule-based container orchestration for cybersecurity sandbox
    Pure simulation mode - no Docker dependencies
    """
    
    def __init__(self):
        """Initialize container orchestrator in simulation mode"""
        self.docker_client = None
        self.sandbox_environments: Dict[str, SandboxEnvironment] = {}
        self.docker_available = False
        
        # Always use simulation mode
        print("🎭 Container Orchestrator running in simulation mode")
        print("✅ All sandbox features available without Docker")
        
        # Rule-based container mappings
        self.CONTAINER_RULES = {
            "web_server": {
                "base_images": {
                    "nginx": {
                        "image": "nginx:alpine",
                        "ports": [80, 443],
                        "vulnerabilities": ["directory_traversal", "config_exposure"],
                        "startup_script": self._generate_nginx_config
                    },
                    "apache": {
                        "image": "httpd:alpine", 
                        "ports": [80, 443],
                        "vulnerabilities": ["path_traversal", "server_status"],
                        "startup_script": self._generate_apache_config
                    }
                },
                "security_levels": {
                    "vulnerable": {"disable_security_headers": True, "expose_version": True},
                    "hardened": {"enable_security_headers": True, "hide_version": True}
                }
            },
            
            "database": {
                "base_images": {
                    "mysql": {
                        "image": "mysql:8.0",
                        "ports": [3306],
                        "vulnerabilities": ["weak_passwords", "sql_injection", "unencrypted_traffic"],
                        "startup_script": self._generate_mysql_config
                    },
                    "postgresql": {
                        "image": "postgres:alpine",
                        "ports": [5432], 
                        "vulnerabilities": ["default_credentials", "privilege_escalation"],
                        "startup_script": self._generate_postgres_config
                    }
                },
                "security_levels": {
                    "vulnerable": {"weak_password": "123456", "remote_access": True},
                    "hardened": {"strong_password": "SecureP@ss123!", "ssl_required": True}
                }
            },
            
            "waf": {
                "base_images": {
                    "modsecurity": {
                        "image": "owasp/modsecurity:nginx",
                        "ports": [80, 443],
                        "protection_rules": ["owasp_crs", "custom_rules"],
                        "startup_script": self._generate_waf_config
                    }
                },
                "security_levels": {
                    "monitor": {"blocking_mode": False, "log_only": True},
                    "protect": {"blocking_mode": True, "strict_rules": True}
                }
            },
            
            "firewall": {
                "base_images": {
                    "iptables": {
                        "image": "alpine:latest",
                        "capabilities": ["NET_ADMIN"],
                        "startup_script": self._generate_firewall_rules
                    }
                },
                "security_levels": {
                    "permissive": {"default_policy": "ACCEPT", "log_level": "low"},
                    "strict": {"default_policy": "DROP", "log_level": "high"}
                }
            },
            
            "siem": {
                "base_images": {
                    "elk_stack": {
                        "image": "elastic/elasticsearch:8.0.0",
                        "ports": [9200, 5601, 5044],
                        "startup_script": self._generate_elk_config
                    }
                }
            },
            
            "user_device": {
                "base_images": {
                    "kali_linux": {
                        "image": "kalilinux/kali-rolling",
                        "capabilities": ["NET_ADMIN", "NET_RAW"],
                        "attack_tools": ["nmap", "sqlmap", "metasploit"],
                        "startup_script": self._generate_attacker_config
                    }
                }
            }
        }
        
        # Network zone configurations
        self.NETWORK_ZONES = {
            "public": {
                "subnet": "192.168.10.0/24",
                "internet_access": True,
                "security_level": "low"
            },
            "dmz": {
                "subnet": "192.168.20.0/24", 
                "internet_access": True,
                "security_level": "medium"
            },
            "internal": {
                "subnet": "192.168.30.0/24",
                "internet_access": False,
                "security_level": "high"
            },
            "private": {
                "subnet": "192.168.40.0/24",
                "internet_access": False, 
                "security_level": "high"
            }
        }

    def deploy_architecture_sandbox(self, architecture: Dict[str, Any], security_level: str = "vulnerable") -> str:
        """
        Deploy complete architecture as live containers
        Returns sandbox_id for management
        """
        sandbox_id = f"sandbox_{int(time.time())}_{id(architecture)}"
        
        try:
            print(f"🚀 Deploying sandbox: {sandbox_id}")
            print(f"📊 Architecture components: {len(architecture.get('nodes', []))}")
            
            # Create sandbox environment
            sandbox_env = SandboxEnvironment(
                sandbox_id=sandbox_id,
                architecture_id=architecture.get('metadata', {}).get('company_name', 'unknown'),
                status="deploying",
                containers={},
                networks={},
                attack_history=[],
                telemetry_data=[],
                created_at=datetime.now().isoformat(),
                last_activity=datetime.now().isoformat()
            )
            
            # Step 1: Create virtual networks
            networks = self._create_virtual_networks(sandbox_id, architecture.get('network_zones', []))
            sandbox_env.networks = networks
            
            # Step 2: Deploy containers for each component
            containers = {}
            for node in architecture.get('nodes', []):
                container_config = self._deploy_component_container(
                    sandbox_id, node, security_level
                )
                if container_config:
                    containers[node['id']] = container_config
            
            # Step 3: Configure network connections
            self._configure_container_networking(sandbox_id, architecture.get('connections', []))
            
            # Step 4: Install monitoring agents
            self._deploy_monitoring_agents(sandbox_id, containers)
            
            # Update sandbox status
            sandbox_env.containers = containers
            sandbox_env.status = "running"
            sandbox_env.last_activity = datetime.now().isoformat()
            
            # Store sandbox environment
            self.sandbox_environments[sandbox_id] = sandbox_env
            
            print(f"✅ Sandbox deployed successfully: {sandbox_id}")
            print(f"🏗️  Deployed {len(containers)} containers")
            print(f"🌐 Created {len(sandbox_env.networks)} networks")
            print(f"💾 Sandbox stored in environment registry")
            print(f"📊 Total active sandboxes: {len(self.sandbox_environments)}")
            
            return sandbox_id
            
        except Exception as e:
            print(f"❌ Failed to deploy sandbox: {e}")
            # Cleanup on failure
            self.destroy_sandbox(sandbox_id)
            raise Exception(f"Sandbox deployment failed: {str(e)}")

    def _deploy_component_container(self, sandbox_id: str, node: Dict[str, Any], security_level: str) -> Optional[ContainerConfig]:
        """Deploy single component as simulated container"""
        component_type = node.get('type', node.get('component_type', 'unknown'))
        node_name = node.get('name', f"{component_type}_{node['id']}")
        
        print(f"🎭 Simulating container: {node_name} ({component_type})")
        
        # Get container rules for this component type or use default
        if component_type in self.CONTAINER_RULES:
            rules = self.CONTAINER_RULES[component_type]
            base_config = list(rules["base_images"].values())[0]
            security_config = rules.get("security_levels", {}).get(security_level, {})
        else:
            # Default configuration for unknown components
            base_config = {
                "image": f"simulated/{component_type}:latest",
                "ports": [80, 22],
                "vulnerabilities": ["default_credentials", "unpatched_services"]
            }
            security_config = {"security_level": security_level}
        
        # Generate container configuration
        container_name = f"{sandbox_id}_{component_type}_{node['id']}"
        
        # Prepare environment variables
        env_vars = {
            "COMPONENT_TYPE": component_type,
            "NODE_ID": node['id'],
            "SANDBOX_ID": sandbox_id,
            "SECURITY_LEVEL": security_level,
            "SIMULATION_MODE": "true",
            **security_config
        }
        
        # Configure simulated volumes
        volumes = {
            f"/tmp/sandbox/{sandbox_id}/logs": {"bind": "/var/log/security", "mode": "rw"},
            f"/tmp/sandbox/{sandbox_id}/data": {"bind": "/var/data", "mode": "rw"}
        }
        
        # Create simulated container (no actual Docker)
        try:
            print(f"✅ Simulated container deployed: {container_name}")
            print(f"🎯 Available ports: {base_config.get('ports', [])}")
            print(f"🔓 Vulnerabilities: {base_config.get('vulnerabilities', [])}")
            
            # Create container config
            container_config = ContainerConfig(
                component_type=component_type,
                container_name=container_name,
                docker_image=base_config["image"],
                ports=base_config.get("ports", []),
                environment_vars=env_vars,
                volumes=volumes,
                network_settings={"network": f"{sandbox_id}_default"},
                security_config=security_config,
                monitoring_agents=[],
                startup_commands=[]
            )
            
            return container_config
            
        except Exception as e:
            print(f"❌ Failed to deploy container {container_name}: {e}")
            return None

    def _create_virtual_networks(self, sandbox_id: str, network_zones: List[Dict[str, Any]]):
        """Create simulated networks for network zones"""
        print(f"🌐 Creating simulated networks for sandbox: {sandbox_id}")
        
        # Always create simulated networks
        networks = {
            f"{sandbox_id}_default": {
                "name": f"{sandbox_id}_default",
                "driver": "bridge",
                "subnet": "192.168.100.0/24",
                "status": "simulated",
                "containers": []
            }
        }
        
        # Add zone-specific networks
        for zone in network_zones:
            zone_id = zone.get('zone_id', zone.get('name', 'unknown'))
            subnet = self.NETWORK_ZONES.get(zone_id, {}).get('subnet', '192.168.99.0/24')
            networks[f"{sandbox_id}_{zone_id}"] = {
                "name": f"{sandbox_id}_{zone_id}",
                "driver": "bridge",
                "subnet": subnet,
                "zone": zone_id,
                "trust_level": zone.get('trust_level', 'medium'),
                "status": "simulated",
                "containers": []
            }
            print(f"🎭 Simulated network: {zone_id} ({subnet})")
        
        print(f"✅ Created {len(networks)} simulated networks")
        return networks

    def _configure_container_networking(self, sandbox_id: str, connections: List[Dict[str, Any]]):
        """Configure network connections between containers"""
        print(f"🔗 Configuring container networking for sandbox: {sandbox_id}")
        
        for connection in connections:
            source_id = connection['source']
            target_id = connection['target']
            connection_type = connection.get('type', 'network')
            
            # Simulate container connections
            try:
                print(f"🎭 Simulating connection: {source_id} → {target_id}")
                
                # Configure based on connection type
                if connection_type == "encrypted":
                    print(f"🔐 Setting up encrypted connection simulation")
                elif connection_type == "vpn":
                    print(f"🔒 Setting up VPN connection simulation")
                else:
                    print(f"🔗 Setting up {connection_type} connection simulation")
                
                print(f"✅ Configured simulated connection: {source_id} → {target_id} ({connection_type})")
                
            except Exception as e:
                print(f"⚠️  Failed to configure connection {source_id} → {target_id}: {e}")

    def get_sandbox_status(self, sandbox_id: str) -> Dict[str, Any]:
        """Get current sandbox status and metrics"""
        if sandbox_id not in self.sandbox_environments:
            return {"error": "Sandbox not found"}
            
        env = self.sandbox_environments[sandbox_id]
        
        # Get simulated container status
        container_status = {}
        for node_id, container_config in env.containers.items():
            # Simulate healthy running containers
            container_status[node_id] = {
                "status": "running",
                "health": "healthy",
                "uptime": f"{random.randint(1, 60)} minutes",
                "resource_usage": {
                    "cpu_percent": random.randint(5, 25),
                    "memory_percent": random.randint(10, 40),
                    "network_io": f"{random.randint(100, 1000)}KB"
                }
            }
        
        return {
            "sandbox_id": sandbox_id,
            "status": env.status,
            "created_at": env.created_at,
            "last_activity": env.last_activity,
            "containers": container_status,
            "networks": list(env.networks.keys()),
            "attack_history_count": len(env.attack_history),
            "telemetry_entries": len(env.telemetry_data)
        }

    def destroy_sandbox(self, sandbox_id: str) -> bool:
        """Clean up and destroy simulated sandbox environment"""
        print(f"🧹 Destroying simulated sandbox: {sandbox_id}")
        
        try:
            # Always use simulation cleanup
            print("🎭 Simulating container and network cleanup")
            
            # Clean up sandbox environment
            if sandbox_id in self.sandbox_environments:
                env = self.sandbox_environments[sandbox_id]
                print(f"🗑️  Removing {len(env.containers)} simulated containers")
                print(f"🌐 Removing {len(env.networks)} simulated networks")
                del self.sandbox_environments[sandbox_id]
            
            print(f"✅ Simulated sandbox destroyed: {sandbox_id}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to destroy sandbox: {e}")
            return False

    # Container configuration generators (rule-based)
    
    def _generate_nginx_config(self, security_config: Dict[str, Any]) -> str:
        """Generate nginx configuration based on security level"""
        if security_config.get("disable_security_headers"):
            return """
server {
    listen 80;
    server_tokens on;
    add_header X-Powered-By "nginx/1.18.0";
    location / {
        root /usr/share/nginx/html;
        index index.html;
        autoindex on;
    }
    location /admin {
        root /var/www/admin;
        allow all;
    }
}"""
        else:
            return """
server {
    listen 80;
    server_tokens off;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    location / {
        root /usr/share/nginx/html;
        index index.html;
    }
}"""

    def _generate_apache_config(self, security_config: Dict[str, Any]) -> str:
        """Generate Apache HTTP Server configuration based on security level"""
        security_headers = ""
        if security_config.get("enable_security_headers", False):
            security_headers = """
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
"""
        
        server_tokens = "Off" if security_config.get("hide_version", False) else "On"
        
        return f"""
ServerTokens {server_tokens}
Listen 80
DocumentRoot /usr/local/apache2/htdocs
DirectoryIndex index.html

<VirtualHost *:80>
    ServerName localhost
    DocumentRoot /usr/local/apache2/htdocs
    {security_headers}
    
    <Directory "/usr/local/apache2/htdocs">
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>"""

    def _generate_mysql_config(self, security_config: Dict[str, Any]) -> str:
        """Generate MySQL configuration based on security level"""
        password = security_config.get("weak_password", "SecureP@ss123!")
        return f"""
[mysqld]
bind-address = 0.0.0.0
port = 3306
general_log = 1
general_log_file = /var/log/mysql/query.log

[client]
password = {password}
"""

    def _generate_postgres_config(self, security_config: Dict[str, Any]) -> str:
        """Generate PostgreSQL configuration"""
        return """
listen_addresses = '*'
port = 5432
log_statement = 'all'
log_directory = '/var/log/postgresql'
"""

    def _generate_waf_config(self, security_config: Dict[str, Any]) -> str:
        """Generate WAF configuration"""
        blocking_mode = security_config.get("blocking_mode", True)
        return f"""
SecRuleEngine {'On' if blocking_mode else 'DetectionOnly'}
SecDefaultAction "phase:1,deny,log"
Include /etc/modsecurity/owasp-crs/*.conf
"""

    def _generate_firewall_rules(self, security_config: Dict[str, Any]) -> str:
        """Generate firewall rules"""
        default_policy = security_config.get("default_policy", "DROP")
        return f"""
iptables -P INPUT {default_policy}
iptables -P FORWARD {default_policy}
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
"""

    def _generate_elk_config(self, security_config: Dict[str, Any]) -> str:
        """Generate ELK stack configuration"""
        return """
cluster.name: "security-monitoring"
network.host: 0.0.0.0
discovery.type: single-node
"""

    def _generate_attacker_config(self, security_config: Dict[str, Any]) -> str:
        """Generate attacker/pentester configuration"""
        return """
#!/bin/bash
apt-get update
apt-get install -y nmap sqlmap nikto
"""

    # Helper methods
    
    def _run_container_startup_script(self, container, script_func, security_config):
        """Execute startup script in container"""
        try:
            script_content = script_func(security_config)
            container.exec_run(f"sh -c '{script_content}'")
        except Exception as e:
            print(f"⚠️  Failed to run startup script: {e}")

    def _setup_encrypted_connection(self, source_container, target_container):
        """Setup encrypted connection between containers"""
        pass  # TODO: Implement TLS/SSL setup

    def _setup_vpn_connection(self, source_container, target_container):
        """Setup VPN connection between containers"""
        pass  # TODO: Implement VPN setup

    def _calculate_uptime(self, container) -> str:
        """Calculate container uptime"""
        # TODO: Implement uptime calculation
        return "00:05:30"

    def _get_container_resources(self, container) -> Dict[str, Any]:
        """Get container resource usage"""
        try:
            stats = container.stats(stream=False)
            return {
                "cpu_percent": 25.5,  # TODO: Calculate from stats
                "memory_usage": "128MB",  # TODO: Calculate from stats  
                "network_io": "1.2MB"  # TODO: Calculate from stats
            }
        except:
            return {"cpu_percent": 0, "memory_usage": "0MB", "network_io": "0MB"}

    def _deploy_monitoring_agents(self, sandbox_id: str, containers: Dict[str, ContainerConfig]):
        """Deploy monitoring agents to collect telemetry"""
        print(f"🔍 Deploying monitoring agents for sandbox: {sandbox_id}")
        
        for container_id, container in containers.items():
            print(f"   📡 Agent deployed to: {container.container_name}")
        
        print(f"✅ Monitoring agents deployed for {len(containers)} containers")

# Note: Create orchestrator instances as needed, not globally
# Example usage:
# orchestrator = RuleBasedContainerOrchestrator()
# if orchestrator.docker_available:
#     # Use Docker functionality
# else:
#     # Use simulation mode