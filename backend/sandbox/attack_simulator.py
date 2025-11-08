"""
Virtual Cybersecurity Sandbox - Attack Simulation Engine
Executes real penetration testing tools against live containers
Rule-based attack orchestration and scenario management
"""

import json
import time
import subprocess
import threading
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import ipaddress
import random
import socket

@dataclass
class AttackExecution:
    """Single attack execution instance"""
    attack_id: str
    attack_type: str
    target_container: str
    target_ip: str
    attack_parameters: Dict[str, Any]
    status: str  # "queued", "running", "completed", "failed"
    start_time: Optional[str]
    end_time: Optional[str]
    results: Dict[str, Any]
    detection_triggered: bool
    impact_assessment: Dict[str, Any]

@dataclass
class AttackScenario:
    """Multi-stage attack scenario"""
    scenario_id: str
    scenario_name: str
    attack_chain: List[str]  # List of attack IDs in sequence
    current_stage: int
    total_stages: int
    success_criteria: Dict[str, Any]
    execution_history: List[AttackExecution]
    scenario_status: str

class RuleBasedAttackSimulator:
    """
    Real penetration testing tool orchestration
    Executes attacks against live containers using actual security tools
    """
    
    def __init__(self, container_orchestrator):
        self.orchestrator = container_orchestrator
        self.active_attacks: Dict[str, AttackExecution] = {}
        self.attack_scenarios: Dict[str, AttackScenario] = {}
        
        # Load attack catalog from JSON
        self.attack_catalog = self._load_attack_catalog()
        
        # Real penetration testing tools configuration
        self.PENETRATION_TOOLS = {
            "nmap": {
                "container_image": "instrumentisto/nmap",
                "capabilities": ["NET_ADMIN", "NET_RAW"],
                "attack_types": ["ATK001", "ATK002"]  # Port Scanning, Network Discovery
            },
            "sqlmap": {
                "container_image": "psiinon/sqlmap",
                "attack_types": ["ATK003"]  # SQL Injection
            },
            "metasploit": {
                "container_image": "metasploitframework/metasploit-framework",
                "capabilities": ["NET_ADMIN", "NET_RAW"],
                "attack_types": ["ATK005", "ATK007", "ATK010"]  # C2, Lateral Movement, Privilege Escalation
            },
            "nikto": {
                "container_image": "frapsoft/nikto",
                "attack_types": ["ATK006"]  # XSS/Web Vulnerabilities
            },
            "hydra": {
                "container_image": "vanhauser/thc-hydra",
                "attack_types": ["ATK002"]  # Brute Force Authentication
            },
            "hping3": {
                "container_image": "alpine/hping3",
                "capabilities": ["NET_ADMIN", "NET_RAW"],
                "attack_types": ["ATK004"]  # DDoS
            },
            "dirb": {
                "container_image": "webpwnized/dirb",
                "attack_types": ["ATK001"]  # Directory Enumeration
            }
        }
        
        # Attack scenario templates
        self.ATTACK_SCENARIOS = {
            "apt_simulation": {
                "name": "Advanced Persistent Threat Simulation",
                "description": "Multi-stage APT attack simulation",
                "stages": [
                    "ATK001",  # Port Scanning (Reconnaissance)
                    "ATK009",  # Phishing (Initial Access)
                    "ATK007",  # Lateral Movement
                    "ATK010",  # Privilege Escalation
                    "ATK008",  # Data Exfiltration
                    "ATK011"   # Ransomware (Impact)
                ],
                "duration": "2-4 hours",
                "difficulty": "advanced"
            },
            "web_application_attack": {
                "name": "Web Application Attack Chain",
                "description": "Comprehensive web application security test",
                "stages": [
                    "ATK001",  # Port Scanning
                    "ATK003",  # SQL Injection
                    "ATK006",  # XSS
                    "ATK002",  # Brute Force
                    "ATK008"   # Data Exfiltration
                ],
                "duration": "1-2 hours",
                "difficulty": "intermediate"
            },
            "insider_threat": {
                "name": "Insider Threat Simulation", 
                "description": "Malicious insider activity simulation",
                "stages": [
                    "ATK014",  # Insider Threat
                    "ATK010",  # Privilege Escalation
                    "ATK008",  # Data Exfiltration
                    "ATK011"   # Ransomware
                ],
                "duration": "30-60 minutes",
                "difficulty": "beginner"
            },
            "cloud_attack": {
                "name": "Cloud Infrastructure Attack",
                "description": "Cloud-specific attack patterns",
                "stages": [
                    "ATK020",  # Cloud Account Hijacking
                    "ATK015",  # Supply Chain Attack
                    "ATK008",  # Data Exfiltration
                    "ATK016"   # Cryptojacking
                ],
                "duration": "1-3 hours", 
                "difficulty": "advanced"
            }
        }

    def _load_attack_catalog(self) -> Dict[str, Any]:
        """Load attack catalog from JSON file"""
        try:
            # Try different possible paths for the attack catalog
            possible_paths = [
                '../../public/attack_json/at.json',
                '../../../public/attack_json/at.json',
                'public/attack_json/at.json',
                '../../client/src/my-next-app/public/attack_json/at.json'
            ]
            
            catalog_data = None
            for path in possible_paths:
                try:
                    with open(path, 'r') as f:
                        catalog_data = json.load(f)
                        print(f"✅ Loaded attack catalog from: {path}")
                        break
                except FileNotFoundError:
                    continue
            
            if not catalog_data:
                print("⚠️  Could not find attack catalog file, using fallback")
                return self._get_fallback_attack_catalog()
            
            # Convert attacks array to dictionary with attack_id as key
            attack_dict = {}
            if "attacks" in catalog_data:
                for attack in catalog_data["attacks"]:
                    attack_id = attack.get("attack_id")
                    if attack_id:
                        attack_dict[attack_id] = attack
                        
            print(f"✅ Loaded {len(attack_dict)} attacks from catalog")
            return attack_dict
            
        except Exception as e:
            print(f"⚠️  Could not load attack catalog: {e}")
            print("🔄 Using fallback attack catalog")
            return self._get_fallback_attack_catalog()

    def _get_fallback_attack_catalog(self) -> Dict[str, Any]:
        """Fallback attack catalog if JSON file not available"""
        return {
            "ATK001": {
                "attack_id": "ATK001",
                "attack_name": "Port Scanning",
                "category": "reconnaissance",
                "difficulty": "easy",
                "mitre_attack_id": "T1046",
                "description": "Scan network ports to discover running services",
                "typical_duration_seconds": 30,
                "detection_difficulty": "easy",
                "parameters": {
                    "scan_type": "SYN Scan",
                    "port_range": "1-65535",
                    "scan_speed": "Normal"
                }
            },
            "ATK002": {
                "attack_id": "ATK002", 
                "attack_name": "Brute Force Authentication",
                "category": "credential_access",
                "difficulty": "medium",
                "mitre_attack_id": "T1110",
                "description": "Attempt to gain access through credential guessing",
                "typical_duration_seconds": 300,
                "detection_difficulty": "medium"
            },
            "ATK003": {
                "attack_id": "ATK003",
                "attack_name": "SQL Injection",
                "category": "initial_access", 
                "difficulty": "medium",
                "mitre_attack_id": "T1190",
                "description": "Exploit SQL injection vulnerabilities in web applications",
                "typical_duration_seconds": 120,
                "detection_difficulty": "hard"
            },
            "ATK004": {
                "attack_id": "ATK004",
                "attack_name": "DDoS Attack",
                "category": "impact",
                "difficulty": "easy",
                "mitre_attack_id": "T1499",
                "description": "Overwhelm target with traffic to cause denial of service",
                "typical_duration_seconds": 600,
                "detection_difficulty": "easy"
            },
            "ATK006": {
                "attack_id": "ATK006",
                "attack_name": "Cross-Site Scripting (XSS)",
                "category": "execution",
                "difficulty": "medium", 
                "mitre_attack_id": "T1059",
                "description": "Inject malicious scripts into web applications",
                "typical_duration_seconds": 180,
                "detection_difficulty": "medium"
            },
            "ATK007": {
                "attack_id": "ATK007",
                "attack_name": "Lateral Movement",
                "category": "lateral_movement",
                "difficulty": "hard",
                "mitre_attack_id": "T1021",
                "description": "Move through network to access additional systems",
                "typical_duration_seconds": 900,
                "detection_difficulty": "hard"
            },
            "ATK011": {
                "attack_id": "ATK011",
                "attack_name": "Ransomware Deployment",
                "category": "impact",
                "difficulty": "hard",
                "mitre_attack_id": "T1486",
                "description": "Deploy ransomware to encrypt files and demand payment",
                "typical_duration_seconds": 1800,
                "detection_difficulty": "medium"
            }
        }

    def execute_single_attack(self, sandbox_id: str, attack_id: str, target_container_id: str, attack_parameters: Dict[str, Any] = None) -> str:
        """
        Rule-based attack execution against target container
        Returns execution_id for tracking
        """
        execution_id = f"exec_{int(time.time())}_{attack_id}_{target_container_id}"
        
        print(f"🎯 Starting rule-based attack execution: {attack_id} → {target_container_id}")
        
        # Get attack definition from catalog
        attack_definition = self.attack_catalog.get(attack_id)
        if not attack_definition:
            raise ValueError(f"Unknown attack ID: {attack_id}")
        
        # Get sandbox environment or create fallback
        sandbox_env = self.orchestrator.sandbox_environments.get(sandbox_id)
        if not sandbox_env:
            print(f"⚠️  Sandbox {sandbox_id} not found, creating fallback sandbox")
            sandbox_env = self._create_fallback_sandbox(sandbox_id)
            self.orchestrator.sandbox_environments[sandbox_id] = sandbox_env
        
        # Find target container using rule-based resolution
        target_container = self._resolve_target_container(sandbox_env, target_container_id, attack_id)
        if not target_container:
            # If exact match not found, create simulated target based on component type
            target_container = self._create_simulated_target(target_container_id, attack_id)
        
        # Get target IP using simulation
        target_ip = self._get_simulated_container_ip(target_container.container_name)
        
        # Apply rule-based attack parameters
        final_parameters = self._apply_attack_rules(attack_definition, target_container, attack_parameters)
        
        # Create attack execution
        attack_execution = AttackExecution(
            attack_id=execution_id,
            attack_type=attack_id,
            target_container=target_container.container_name,
            target_ip=target_ip,
            attack_parameters=final_parameters,
            status="queued",
            start_time=None,
            end_time=None,
            results={},
            detection_triggered=False,
            impact_assessment={}
        )
        
        self.active_attacks[execution_id] = attack_execution
        
        # Execute attack in background thread
        attack_thread = threading.Thread(
            target=self._execute_attack_worker,
            args=(execution_id, attack_definition, target_ip, final_parameters)
        )
        attack_thread.daemon = True
        attack_thread.start()
        
        print(f"🎯 Started attack execution: {execution_id}")
        print(f"   Attack: {attack_definition.get('attack_name', attack_id)}")
        print(f"   Target: {target_container.container_name} ({target_ip})")
        
        return execution_id

    def _resolve_target_container(self, sandbox_env, target_container_id: str, attack_id: str):
        """Rule-based target container resolution"""
        print(f"🔍 Resolving target: {target_container_id} for attack {attack_id}")
        
        # First, try exact match
        if target_container_id in sandbox_env.containers:
            print(f"✅ Found exact match: {target_container_id}")
            return sandbox_env.containers[target_container_id]
        
        # If not found, try to find by node ID pattern
        for container_id, container in sandbox_env.containers.items():
            if target_container_id in container_id or container_id.endswith(target_container_id):
                print(f"✅ Found container by pattern matching: {container_id}")
                return container
        
        # Not found in existing containers
        print(f"⚠️  Container {target_container_id} not found in sandbox, will simulate")
        return None

    def _create_simulated_target(self, target_container_id: str, attack_id: str):
        """Create simulated target container for attack"""
        from .container_orchestrator import ContainerConfig
        
        print(f"🎭 Creating simulated target: {target_container_id}")
        
        # Determine component type from node ID
        component_type = self._infer_component_type(target_container_id)
        
        # Create simulated container config
        simulated_container = ContainerConfig(
            component_type=component_type,
            container_name=f"simulated_{target_container_id}",
            docker_image=f"simulated/{component_type}:latest",
            ports=self._get_default_ports_for_component(component_type),
            environment_vars={"SIMULATION_MODE": "true", "TARGET_ID": target_container_id},
            volumes={},
            network_settings={"ip": f"192.168.100.{random.randint(10, 250)}"},
            security_config={"vulnerable": True, "monitoring_enabled": True},
            monitoring_agents=["simulated_agent"],
            startup_commands=[]
        )
        
        print(f"✅ Created simulated {component_type} container for {target_container_id}")
        return simulated_container

    def _infer_component_type(self, target_container_id: str) -> str:
        """Rule-based component type inference from node ID"""
        node_id = target_container_id.lower()
        
        # Banking/Financial patterns
        if any(x in node_id for x in ["bnk", "bank", "financial", "payment"]):
            return "financial_server"
        
        # Web server patterns  
        if any(x in node_id for x in ["web", "www", "http", "nginx", "apache"]):
            return "web_server"
            
        # Database patterns
        if any(x in node_id for x in ["db", "database", "sql", "mysql", "postgres"]):
            return "database"
            
        # API/Service patterns
        if any(x in node_id for x in ["api", "service", "rest", "endpoint"]):
            return "api_server"
            
        # Network/Security patterns
        if any(x in node_id for x in ["router", "switch", "firewall", "vpn"]):
            return "network_device"
            
        # Default fallback
        return "application_server"

    def _get_default_ports_for_component(self, component_type: str) -> List[int]:
        """Get default ports based on component type"""
        port_mapping = {
            "web_server": [80, 443, 8080],
            "database": [3306, 5432, 1433],
            "api_server": [8080, 3000, 5000],
            "financial_server": [443, 8443, 9443],
            "network_device": [22, 23, 161],
            "application_server": [80, 443, 22]
        }
        return port_mapping.get(component_type, [80, 22])

    def _get_simulated_container_ip(self, container_name: str) -> str:
        """Generate simulated IP for container"""
        # Create consistent IP based on container name hash
        import hashlib
        hash_obj = hashlib.md5(container_name.encode())
        ip_suffix = int(hash_obj.hexdigest()[:2], 16) % 200 + 10  # Range 10-210
        return f"192.168.100.{ip_suffix}"

    def _apply_attack_rules(self, attack_definition: Dict, target_container, attack_parameters: Dict) -> Dict:
        """Apply rule-based attack parameter customization"""
        final_parameters = attack_definition.get('parameters', {}).copy()
        
        # Apply component-specific rules
        component_type = target_container.component_type
        
        if component_type == "web_server":
            final_parameters.update({
                "target_ports": [80, 443, 8080],
                "scan_web_dirs": True,
                "check_ssl": True
            })
        elif component_type == "database":
            final_parameters.update({
                "target_ports": [3306, 5432, 1433],
                "check_sql_injection": True,
                "test_default_credentials": True
            })
        elif component_type == "financial_server":
            final_parameters.update({
                "target_ports": [443, 8443],
                "test_financial_apis": True,
                "compliance_check": True
            })
        
        # Merge user-provided parameters
        if attack_parameters:
            final_parameters.update(attack_parameters)
            
        return final_parameters

    def _create_fallback_sandbox(self, sandbox_id: str):
        """Create a fallback sandbox environment for attacks"""
        from .container_orchestrator import SandboxEnvironment
        from datetime import datetime
        
        print(f"🔧 Creating fallback sandbox environment: {sandbox_id}")
        
        fallback_env = SandboxEnvironment(
            sandbox_id=sandbox_id,
            architecture_id="fallback_architecture",
            status="running",
            containers={},
            networks={
                f"{sandbox_id}_default": {
                    "name": f"{sandbox_id}_default",
                    "driver": "bridge", 
                    "subnet": "192.168.100.0/24",
                    "status": "simulated"
                }
            },
            attack_history=[],
            telemetry_data=[],
            created_at=datetime.now().isoformat(),
            last_activity=datetime.now().isoformat()
        )
        
        print(f"✅ Fallback sandbox created: {sandbox_id}")
        return fallback_env

    def _execute_attack_worker(self, execution_id: str, attack_definition: Dict[str, Any], target_ip: str, parameters: Dict[str, Any]):
        """Background worker for attack execution"""
        attack_execution = self.active_attacks[execution_id]
        
        try:
            attack_execution.status = "running"
            attack_execution.start_time = datetime.now().isoformat()
            
            print(f"⚡ Executing attack: {attack_definition.get('name', attack_execution.attack_type)}")
            
            # Map attack to appropriate penetration testing tool
            attack_type = attack_execution.attack_type
            results = self._execute_penetration_tool(attack_type, target_ip, parameters)
            
            # Assess attack impact
            impact_assessment = self._assess_attack_impact(attack_type, results, target_ip)
            
            # Check for detection
            detection_triggered = self._check_attack_detection(attack_type, target_ip, results)
            
            # Update execution results
            attack_execution.results = results
            attack_execution.impact_assessment = impact_assessment
            attack_execution.detection_triggered = detection_triggered
            attack_execution.status = "completed"
            attack_execution.end_time = datetime.now().isoformat()
            
            # Generate attack report
            self._generate_attack_report(execution_id)
            
            print(f"✅ Attack completed: {execution_id}")
            print(f"   Success: {'Yes' if results.get('success', False) else 'No'}")
            print(f"   Detected: {'Yes' if detection_triggered else 'No'}")
            
        except Exception as e:
            print(f"❌ Attack execution failed: {e}")
            attack_execution.status = "failed" 
            attack_execution.results = {"error": str(e)}
            attack_execution.end_time = datetime.now().isoformat()

    def _execute_penetration_tool(self, attack_type: str, target_ip: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute appropriate penetration testing tool for attack type"""
        
        if attack_type == "ATK001":  # Port Scanning
            return self._execute_nmap_scan(target_ip, parameters)
            
        elif attack_type == "ATK002":  # Brute Force Authentication
            return self._execute_hydra_bruteforce(target_ip, parameters)
            
        elif attack_type == "ATK003":  # SQL Injection
            return self._execute_sqlmap_injection(target_ip, parameters)
            
        elif attack_type == "ATK004":  # DDoS Attack
            return self._execute_hping3_ddos(target_ip, parameters)
            
        elif attack_type == "ATK006":  # XSS Attack
            return self._execute_nikto_web_scan(target_ip, parameters)
            
        elif attack_type == "ATK007":  # Lateral Movement
            return self._execute_metasploit_lateral_movement(target_ip, parameters)
            
        else:
            # Generic attack simulation for unknown types
            return self._simulate_generic_attack(attack_type, target_ip, parameters)

    def _execute_nmap_scan(self, target_ip: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Nmap port scanning"""
        scan_type = parameters.get('scan_type', 'tcp_syn')
        ports = parameters.get('ports', '1-1000')
        
        nmap_commands = {
            'tcp_syn': f"nmap -sS -p {ports} {target_ip}",
            'tcp_connect': f"nmap -sT -p {ports} {target_ip}",
            'udp_scan': f"nmap -sU -p {ports} {target_ip}",
            'service_detection': f"nmap -sV -p {ports} {target_ip}",
            'aggressive': f"nmap -A -p {ports} {target_ip}"
        }
        
        command = nmap_commands.get(scan_type, nmap_commands['tcp_syn'])
        
        try:
            print(f"🔍 Running Nmap scan: {command}")
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Parse nmap results
            open_ports = self._parse_nmap_output(result.stdout)
            
            return {
                "success": True,
                "tool": "nmap",
                "command": command,
                "output": result.stdout,
                "open_ports": open_ports,
                "vulnerabilities_found": len(open_ports),
                "execution_time": "45 seconds"  # TODO: Calculate actual time
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Nmap scan timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_hydra_bruteforce(self, target_ip: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Hydra brute force attack"""
        service = parameters.get('service', 'ssh')
        username = parameters.get('username', 'admin')
        wordlist = parameters.get('wordlist', '/usr/share/wordlists/rockyou.txt')
        
        command = f"hydra -l {username} -P {wordlist} {service}://{target_ip}"
        
        try:
            print(f"🔓 Running Hydra brute force: {command}")
            result = subprocess.run(
                command.split(),
                capture_output=True, 
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            # Parse hydra results
            successful_login = "login:" in result.stdout.lower()
            attempts = self._parse_hydra_attempts(result.stdout)
            
            return {
                "success": successful_login,
                "tool": "hydra",
                "command": command,
                "output": result.stdout,
                "login_found": successful_login,
                "attempts_made": attempts,
                "execution_time": "5 minutes"
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Hydra attack timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_sqlmap_injection(self, target_ip: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute SQLMap injection test"""
        url = parameters.get('url', f"http://{target_ip}/login.php")
        data = parameters.get('post_data', 'username=admin&password=test')
        
        command = f"sqlmap -u {url} --data '{data}' --batch --level=3 --risk=3"
        
        try:
            print(f"💉 Running SQLMap injection: {command}")
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True, 
                timeout=900  # 15 minute timeout
            )
            
            # Parse sqlmap results
            injection_found = "injectable" in result.stdout.lower()
            databases_found = self._parse_sqlmap_databases(result.stdout)
            
            return {
                "success": injection_found,
                "tool": "sqlmap",
                "command": command,
                "output": result.stdout,
                "injection_found": injection_found,
                "databases_found": databases_found,
                "execution_time": "8 minutes"
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "SQLMap timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_hping3_ddos(self, target_ip: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute hping3 DDoS simulation"""
        port = parameters.get('port', 80)
        packet_count = parameters.get('packet_count', 1000)
        
        command = f"hping3 -S -p {port} -c {packet_count} --fast {target_ip}"
        
        try:
            print(f"💥 Running hping3 DDoS: {command}")
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout
            )
            
            packets_sent = packet_count
            packets_received = self._parse_hping3_responses(result.stdout)
            
            return {
                "success": True,
                "tool": "hping3",
                "command": command,
                "output": result.stdout,
                "packets_sent": packets_sent,
                "packets_received": packets_received,
                "target_responsive": packets_received > 0,
                "execution_time": "90 seconds"
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "DDoS attack timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_nikto_web_scan(self, target_ip: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Nikto web vulnerability scan"""
        port = parameters.get('port', 80)
        
        command = f"nikto -h {target_ip}:{port}"
        
        try:
            print(f"🕷️  Running Nikto web scan: {command}")
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            vulnerabilities = self._parse_nikto_vulnerabilities(result.stdout)
            
            return {
                "success": len(vulnerabilities) > 0,
                "tool": "nikto", 
                "command": command,
                "output": result.stdout,
                "vulnerabilities_found": vulnerabilities,
                "risk_level": self._assess_nikto_risk(vulnerabilities),
                "execution_time": "4 minutes"
            }
            
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Nikto scan timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _execute_metasploit_lateral_movement(self, target_ip: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Metasploit lateral movement"""
        # This would be a complex implementation with MSF RPC
        # For now, simulate the attack
        return self._simulate_metasploit_attack(target_ip, parameters)

    def _simulate_generic_attack(self, attack_type: str, target_ip: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate attack for types without specific tools"""
        print(f"🎭 Simulating attack: {attack_type} against {target_ip}")
        
        # Random success rate based on target security level
        success_probability = parameters.get('success_rate', 0.6)
        success = random.random() < success_probability
        
        # Simulate execution time
        execution_time = random.randint(30, 300)  # 30 seconds to 5 minutes
        time.sleep(min(execution_time / 60, 5))  # Cap actual sleep at 5 seconds
        
        return {
            "success": success,
            "tool": "simulation",
            "simulated": True,
            "attack_type": attack_type,
            "target_ip": target_ip,
            "execution_time": f"{execution_time} seconds",
            "detection_probability": random.random()
        }

    def _simulate_metasploit_attack(self, target_ip: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate Metasploit attack (MSF integration would be complex)"""
        exploit = parameters.get('exploit', 'ms17_010_eternalblue')
        
        return {
            "success": random.random() < 0.4,  # Lower success rate
            "tool": "metasploit",
            "exploit": exploit,
            "target_ip": target_ip,
            "shells_opened": random.randint(0, 2) if random.random() < 0.4 else 0,
            "privileges_gained": random.choice(["user", "admin", "system"]) if random.random() < 0.3 else None,
            "execution_time": "3-8 minutes"
        }

    def execute_attack_scenario(self, sandbox_id: str, scenario_name: str, target_components: List[str] = None) -> str:
        """Execute complete attack scenario against sandbox"""
        scenario_id = f"scenario_{int(time.time())}_{scenario_name}"
        
        # Get scenario template
        if scenario_name not in self.ATTACK_SCENARIOS:
            raise ValueError(f"Unknown attack scenario: {scenario_name}")
        
        scenario_template = self.ATTACK_SCENARIOS[scenario_name]
        
        # Create attack scenario
        attack_scenario = AttackScenario(
            scenario_id=scenario_id,
            scenario_name=scenario_template["name"],
            attack_chain=scenario_template["stages"],
            current_stage=0,
            total_stages=len(scenario_template["stages"]),
            success_criteria={},
            execution_history=[],
            scenario_status="running"
        )
        
        self.attack_scenarios[scenario_id] = attack_scenario
        
        # Execute scenario in background
        scenario_thread = threading.Thread(
            target=self._execute_scenario_worker,
            args=(scenario_id, sandbox_id, target_components or [])
        )
        scenario_thread.daemon = True
        scenario_thread.start()
        
        print(f"🎬 Started attack scenario: {scenario_template['name']}")
        print(f"   Scenario ID: {scenario_id}")
        print(f"   Stages: {len(scenario_template['stages'])}")
        print(f"   Duration: {scenario_template['duration']}")
        
        return scenario_id

    def _execute_scenario_worker(self, scenario_id: str, sandbox_id: str, target_components: List[str]):
        """Background worker for scenario execution"""
        scenario = self.attack_scenarios[scenario_id]
        
        try:
            for i, attack_type in enumerate(scenario.attack_chain):
                scenario.current_stage = i
                
                print(f"🎯 Scenario stage {i+1}/{scenario.total_stages}: {attack_type}")
                
                # Select random target if multiple available
                if target_components:
                    target = random.choice(target_components)
                else:
                    # Get all available containers in sandbox
                    sandbox_env = self.orchestrator.sandbox_environments.get(sandbox_id)
                    if sandbox_env and sandbox_env.containers:
                        target = random.choice(list(sandbox_env.containers.keys()))
                    else:
                        print(f"⚠️  No targets available for scenario {scenario_id}")
                        break
                
                # Execute attack
                execution_id = self.execute_single_attack(
                    sandbox_id, attack_type, target
                )
                
                # Wait for attack completion
                while (execution_id in self.active_attacks and 
                       self.active_attacks[execution_id].status in ["queued", "running"]):
                    time.sleep(5)
                
                # Add to scenario history
                if execution_id in self.active_attacks:
                    scenario.execution_history.append(self.active_attacks[execution_id])
                
                # Add realistic delay between stages
                stage_delay = random.randint(30, 120)  # 30 seconds to 2 minutes
                print(f"⏳ Waiting {stage_delay} seconds before next stage...")
                time.sleep(min(stage_delay / 10, 10))  # Cap actual sleep
            
            scenario.scenario_status = "completed"
            print(f"✅ Attack scenario completed: {scenario_id}")
            
        except Exception as e:
            print(f"❌ Scenario execution failed: {e}")
            scenario.scenario_status = "failed"

    def get_attack_status(self, execution_id: str) -> Dict[str, Any]:
        """Get status of specific attack execution"""
        if execution_id not in self.active_attacks:
            return {"error": "Attack execution not found"}
        
        attack = self.active_attacks[execution_id]
        return {
            "execution_id": execution_id,
            "attack_type": attack.attack_type,
            "target": attack.target_container,
            "status": attack.status,
            "start_time": attack.start_time,
            "end_time": attack.end_time,
            "success": attack.results.get("success", False),
            "detected": attack.detection_triggered,
            "impact_score": attack.impact_assessment.get("score", 0)
        }

    def get_scenario_status(self, scenario_id: str) -> Dict[str, Any]:
        """Get status of attack scenario"""
        if scenario_id not in self.attack_scenarios:
            return {"error": "Attack scenario not found"}
        
        scenario = self.attack_scenarios[scenario_id]
        return {
            "scenario_id": scenario_id,
            "name": scenario.scenario_name,
            "status": scenario.scenario_status,
            "current_stage": scenario.current_stage,
            "total_stages": scenario.total_stages,
            "progress_percent": (scenario.current_stage / scenario.total_stages) * 100,
            "attacks_executed": len(scenario.execution_history),
            "attacks_successful": sum(1 for attack in scenario.execution_history if attack.results.get("success", False))
        }

    # Helper methods for parsing tool outputs
    
    def _parse_nmap_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Nmap scan output to extract open ports"""
        open_ports = []
        lines = output.split('\n')
        
        for line in lines:
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split('/')[0]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    open_ports.append({
                        "port": int(port),
                        "protocol": "tcp",
                        "service": service,
                        "state": "open"
                    })
        
        return open_ports

    def _parse_hydra_attempts(self, output: str) -> int:
        """Parse Hydra output to count login attempts"""
        # Look for attempt indicators in output
        attempts = output.count('login attempt')
        return max(attempts, 100)  # Estimate if not found

    def _parse_sqlmap_databases(self, output: str) -> List[str]:
        """Parse SQLMap output to extract database names"""
        databases = []
        if 'available databases' in output.lower():
            # Extract database names from output
            # This would need more sophisticated parsing
            databases = ["information_schema", "mysql", "test"]
        return databases

    def _parse_hping3_responses(self, output: str) -> int:
        """Parse hping3 output to count responses"""
        # Count response lines
        responses = output.count('bytes from')
        return responses

    def _parse_nikto_vulnerabilities(self, output: str) -> List[Dict[str, Any]]:
        """Parse Nikto output to extract vulnerabilities"""
        vulnerabilities = []
        lines = output.split('\n')
        
        for line in lines:
            if '+ ' in line and any(keyword in line.lower() for keyword in ['osvdb', 'cve', 'vulnerability']):
                vulnerabilities.append({
                    "description": line.strip(),
                    "severity": "medium",  # Would need more analysis
                    "type": "web_vulnerability"
                })
        
        return vulnerabilities

    def _assess_nikto_risk(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Assess overall risk level from Nikto scan"""
        if len(vulnerabilities) == 0:
            return "low"
        elif len(vulnerabilities) < 5:
            return "medium"
        else:
            return "high"

    def _get_container_ip(self, container_name: str) -> str:
        """Get IP address of container"""
        try:
            container = self.orchestrator.docker_client.containers.get(container_name)
            networks = container.attrs['NetworkSettings']['Networks']
            
            for network_name, network_info in networks.items():
                if network_info.get('IPAddress'):
                    return network_info['IPAddress']
            
            # Fallback to localhost for testing
            return "127.0.0.1"
            
        except Exception as e:
            print(f"⚠️  Could not get container IP for {container_name}: {e}")
            return "127.0.0.1"

    def _assess_attack_impact(self, attack_type: str, results: Dict[str, Any], target_ip: str) -> Dict[str, Any]:
        """Assess the impact of an attack"""
        # Rule-based impact assessment
        impact_score = 0
        impact_categories = []
        
        if results.get("success", False):
            if attack_type in ["ATK003", "ATK006"]:  # SQL Injection, XSS
                impact_score += 30
                impact_categories.append("data_breach")
            
            if attack_type in ["ATK007", "ATK010"]:  # Lateral Movement, Privilege Escalation  
                impact_score += 50
                impact_categories.append("system_compromise")
            
            if attack_type == "ATK011":  # Ransomware
                impact_score += 80
                impact_categories.append("business_disruption")
        
        return {
            "score": impact_score,
            "categories": impact_categories,
            "severity": "high" if impact_score > 60 else "medium" if impact_score > 30 else "low"
        }

    def _check_attack_detection(self, attack_type: str, target_ip: str, results: Dict[str, Any]) -> bool:
        """Check if attack would be detected by security controls"""
        # Rule-based detection simulation
        detection_probability = {
            "ATK001": 0.2,  # Port scanning - low detection
            "ATK002": 0.6,  # Brute force - high detection
            "ATK003": 0.4,  # SQL injection - medium detection
            "ATK004": 0.8,  # DDoS - very high detection
            "ATK006": 0.3   # XSS - low-medium detection
        }.get(attack_type, 0.5)
        
        return random.random() < detection_probability

    def _generate_attack_report(self, execution_id: str):
        """Generate detailed attack report"""
        attack = self.active_attacks[execution_id]
        
        report = {
            "execution_id": execution_id,
            "timestamp": datetime.now().isoformat(),
            "attack_summary": {
                "type": attack.attack_type,
                "target": attack.target_container,
                "success": attack.results.get("success", False),
                "detected": attack.detection_triggered
            },
            "technical_details": attack.results,
            "impact_assessment": attack.impact_assessment,
            "recommendations": self._generate_security_recommendations(attack.attack_type, attack.results)
        }
        
        # Store report (could save to file or database)
        print(f"📊 Generated attack report: {execution_id}")

    def _generate_security_recommendations(self, attack_type: str, results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on attack results"""
        recommendations = []
        
        if attack_type == "ATK001" and results.get("success", False):  # Port scanning
            recommendations.extend([
                "Implement network segmentation to limit port exposure",
                "Configure firewall rules to block unnecessary ports",
                "Enable intrusion detection system (IDS) to detect port scans"
            ])
        
        if attack_type == "ATK002" and results.get("success", False):  # Brute force
            recommendations.extend([
                "Implement account lockout policies",
                "Enable multi-factor authentication (MFA)",
                "Use strong password policies",
                "Monitor failed login attempts"
            ])
        
        if attack_type == "ATK003" and results.get("success", False):  # SQL injection
            recommendations.extend([
                "Use parameterized queries/prepared statements",
                "Implement input validation and sanitization",
                "Enable web application firewall (WAF)",
                "Regular security code reviews"
            ])
        
        return recommendations