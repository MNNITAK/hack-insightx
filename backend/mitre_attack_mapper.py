"""
MITRE ATT&CK Framework Mapping
Maps architecture vulnerabilities to MITRE ATT&CK tactics and techniques
"""

from typing import List, Dict, Any, Set
from dataclasses import dataclass
from enum import Enum

class AttackTactic(Enum):
    """MITRE ATT&CK Tactics"""
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"

@dataclass
class AttackTechnique:
    """Represents a MITRE ATT&CK technique with comprehensive attributes"""
    technique_id: str
    name: str
    tactic: AttackTactic
    description: str
    possible: bool
    affected_components: List[str]
    attack_path: str
    detection_methods: List[str]
    mitigations: List[str]
    # Extended attributes for future use
    severity: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW
    likelihood: str = "MEDIUM"  # HIGH, MEDIUM, LOW
    impact: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW
    complexity: str = "MEDIUM"  # HIGH, MEDIUM, LOW (attacker skill needed)
    prerequisites: List[str] = None  # What attacker needs before executing
    data_sources: List[str] = None  # Where to look for evidence
    platforms: List[str] = None  # Affected platforms (Windows, Linux, Cloud, etc.)
    permissions_required: List[str] = None  # Required permissions
    defense_bypassed: List[str] = None  # What defenses this bypasses
    sub_techniques: List[str] = None  # Related sub-techniques
    related_techniques: List[str] = None  # Related MITRE techniques
    kill_chain_phases: List[str] = None  # Cyber kill chain phases
    cvss_score: float = 5.0  # Estimated CVSS score
    cwe_mapping: List[str] = None  # Related CWE IDs
    nist_controls: List[str] = None  # NIST 800-53 controls
    compliance_impact: Dict[str, str] = None  # Impact on compliance frameworks
    remediation_effort: str = "MEDIUM"  # Time/cost to fix
    business_impact: str = "MEDIUM"  # Impact on business operations
    
    def __post_init__(self):
        """Initialize list fields if None"""
        if self.prerequisites is None:
            self.prerequisites = []
        if self.data_sources is None:
            self.data_sources = []
        if self.platforms is None:
            self.platforms = []
        if self.permissions_required is None:
            self.permissions_required = []
        if self.defense_bypassed is None:
            self.defense_bypassed = []
        if self.sub_techniques is None:
            self.sub_techniques = []
        if self.related_techniques is None:
            self.related_techniques = []
        if self.kill_chain_phases is None:
            self.kill_chain_phases = []
        if self.cwe_mapping is None:
            self.cwe_mapping = []
        if self.nist_controls is None:
            self.nist_controls = []
        if self.compliance_impact is None:
            self.compliance_impact = {}

class MITREAttackMapper:
    """
    Maps architecture to MITRE ATT&CK framework
    Identifies which ATT&CK techniques are possible based on architecture
    """
    
    def __init__(self):
        self.techniques: List[AttackTechnique] = []
    
    def analyze_architecture(self, architecture: Dict[str, Any]) -> List[AttackTechnique]:
        """
        Analyze architecture and map to MITRE ATT&CK techniques
        """
        self.techniques = []
        nodes = architecture.get('nodes', [])
        connections = architecture.get('connections', [])
        
        # Check each tactic's techniques
        self._check_reconnaissance(nodes, connections)
        self._check_initial_access(nodes, connections)
        self._check_execution(nodes, connections)
        self._check_persistence(nodes, connections)
        self._check_privilege_escalation(nodes, connections)
        self._check_defense_evasion(nodes, connections)
        self._check_credential_access(nodes, connections)
        self._check_discovery(nodes, connections)
        self._check_lateral_movement(nodes, connections)
        self._check_collection(nodes, connections)
        self._check_command_and_control(nodes, connections)
        self._check_exfiltration(nodes, connections)
        self._check_impact(nodes, connections)
        
        return self.techniques
    
    def _check_reconnaissance(self, nodes: List[Dict], connections: List[Dict]):
        """TA0043: Reconnaissance"""
        
        # T1595: Active Scanning
        web_servers = [n for n in nodes if self._is_web_server(n)]
        firewalls = [n for n in nodes if self._is_firewall(n)]
        
        if web_servers and not firewalls:
            self.techniques.append(AttackTechnique(
                technique_id="T1595",
                name="Active Scanning",
                tactic=AttackTactic.RECONNAISSANCE,
                description="Attacker can scan exposed services to identify vulnerabilities",
                possible=True,
                affected_components=[ws.get('id') for ws in web_servers],
                attack_path="Port scan → Service enumeration → Vulnerability identification",
                detection_methods=[
                    "Monitor for unusual scan patterns",
                    "Deploy honeypots",
                    "Use IDS signatures for scanning tools"
                ],
                mitigations=[
                    "Deploy firewall with rate limiting",
                    "Hide service version information",
                    "Use fail2ban for repeated scans"
                ]
            ))
        
        # T1590: Gather Victim Network Information
        if not self._has_network_segmentation(nodes):
            self.techniques.append(AttackTechnique(
                technique_id="T1590",
                name="Gather Victim Network Information",
                tactic=AttackTactic.RECONNAISSANCE,
                description="Flat network allows attacker to map entire infrastructure once inside",
                possible=True,
                affected_components=["architecture"],
                attack_path="Initial access → Network scan → Full topology mapping",
                detection_methods=[
                    "Monitor internal network scanning",
                    "Detect unusual ARP requests",
                    "Track internal DNS queries"
                ],
                mitigations=[
                    "Implement network segmentation",
                    "Use micro-segmentation",
                    "Deploy network access control (NAC)"
                ]
            ))
    
    def _check_initial_access(self, nodes: List[Dict], connections: List[Dict]):
        """TA0001: Initial Access"""
        
        # T1190: Exploit Public-Facing Application
        public_apps = [n for n in nodes if self._is_public_facing(n)]
        waf_components = [n for n in nodes if self._is_waf(n)]
        
        if public_apps and not waf_components:
            self.techniques.append(AttackTechnique(
                technique_id="T1190",
                name="Exploit Public-Facing Application",
                tactic=AttackTactic.INITIAL_ACCESS,
                description="Public applications without WAF protection vulnerable to exploitation",
                possible=True,
                affected_components=[app.get('id') for app in public_apps],
                attack_path="Find vulnerability → Craft exploit → Gain initial foothold",
                detection_methods=[
                    "Monitor for exploitation attempts",
                    "Deploy WAF with OWASP rules",
                    "Track abnormal request patterns"
                ],
                mitigations=[
                    "Deploy Web Application Firewall",
                    "Regular security patching",
                    "Implement virtual patching",
                    "Use vulnerability scanning"
                ]
            ))
        
        # T1133: External Remote Services
        vpn_components = [n for n in nodes if self._is_vpn(n)]
        mfa_components = [n for n in nodes if self._is_mfa(n)]
        
        if vpn_components and not mfa_components:
            self.techniques.append(AttackTechnique(
                technique_id="T1133",
                name="External Remote Services",
                tactic=AttackTactic.INITIAL_ACCESS,
                description="VPN access without MFA vulnerable to credential compromise",
                possible=True,
                affected_components=[vpn.get('id') for vpn in vpn_components],
                attack_path="Steal/guess credentials → VPN login → Internal network access",
                detection_methods=[
                    "Monitor failed VPN login attempts",
                    "Track VPN logins from unusual locations",
                    "Detect concurrent logins from different IPs"
                ],
                mitigations=[
                    "Implement MFA for VPN access",
                    "Use certificate-based authentication",
                    "Implement geo-blocking",
                    "Deploy conditional access policies"
                ]
            ))
        
        # T1078: Valid Accounts
        auth_services = [n for n in nodes if self._is_auth_component(n)]
        
        if auth_services:
            self.techniques.append(AttackTechnique(
                technique_id="T1078",
                name="Valid Accounts",
                tactic=AttackTactic.INITIAL_ACCESS,
                description="Attacker can use stolen credentials to access systems",
                possible=True,
                affected_components=[auth.get('id') for auth in auth_services],
                attack_path="Phishing/credential stuffing → Valid credentials → Legitimate access",
                detection_methods=[
                    "Monitor for logins from unusual locations/times",
                    "Track failed login attempts",
                    "Implement user behavior analytics (UBA)"
                ],
                mitigations=[
                    "Enforce strong password policies",
                    "Implement MFA",
                    "Use password manager",
                    "Deploy credential monitoring services"
                ]
            ))
    
    def _check_execution(self, nodes: List[Dict], connections: List[Dict]):
        """TA0002: Execution"""
        
        # T1059: Command and Scripting Interpreter
        app_servers = [n for n in nodes if self._is_app_server(n)]
        
        if app_servers:
            self.techniques.append(AttackTechnique(
                technique_id="T1059",
                name="Command and Scripting Interpreter",
                tactic=AttackTactic.EXECUTION,
                description="Application servers vulnerable to command injection attacks",
                possible=True,
                affected_components=[app.get('id') for app in app_servers],
                attack_path="Find injection point → Execute system commands → Gain shell access",
                detection_methods=[
                    "Monitor process execution",
                    "Detect unusual command-line arguments",
                    "Track child processes from web servers"
                ],
                mitigations=[
                    "Input validation and sanitization",
                    "Use parameterized queries",
                    "Implement application whitelisting",
                    "Disable unnecessary interpreters"
                ]
            ))
        
        # T1203: Exploitation for Client Execution
        web_servers = [n for n in nodes if self._is_web_server(n)]
        
        if web_servers:
            self.techniques.append(AttackTechnique(
                technique_id="T1203",
                name="Exploitation for Client Execution",
                tactic=AttackTactic.EXECUTION,
                description="Web servers can serve malicious content for client-side exploitation",
                possible=True,
                affected_components=[ws.get('id') for ws in web_servers],
                attack_path="Compromise website → Inject malicious code → Client execution",
                detection_methods=[
                    "Monitor for XSS attempts",
                    "Use Content Security Policy (CSP)",
                    "Deploy client-side security controls"
                ],
                mitigations=[
                    "Implement CSP headers",
                    "Output encoding",
                    "Deploy XSS protection",
                    "Use Subresource Integrity (SRI)"
                ]
            ))
    
    def _check_persistence(self, nodes: List[Dict], connections: List[Dict]):
        """TA0003: Persistence"""
        
        # T1136: Create Account
        auth_services = [n for n in nodes if self._is_auth_component(n)]
        
        if auth_services:
            self.techniques.append(AttackTechnique(
                technique_id="T1136",
                name="Create Account",
                tactic=AttackTactic.PERSISTENCE,
                description="Attacker can create rogue accounts for persistent access",
                possible=True,
                affected_components=[auth.get('id') for auth in auth_services],
                attack_path="Compromise admin account → Create backdoor user → Maintain access",
                detection_methods=[
                    "Monitor account creation events",
                    "Track privileged account usage",
                    "Audit user provisioning logs"
                ],
                mitigations=[
                    "Implement account creation approval workflow",
                    "Regular account audits",
                    "Use privileged access management (PAM)",
                    "Enable account creation alerts"
                ]
            ))
        
        # T1505: Server Software Component
        web_servers = [n for n in nodes if self._is_web_server(n)]
        
        if web_servers:
            self.techniques.append(AttackTechnique(
                technique_id="T1505",
                name="Server Software Component",
                tactic=AttackTactic.PERSISTENCE,
                description="Attacker can install webshell or modify server components for persistence",
                possible=True,
                affected_components=[ws.get('id') for ws in web_servers],
                attack_path="Gain access → Upload webshell → Persistent backdoor access",
                detection_methods=[
                    "File integrity monitoring (FIM)",
                    "Monitor for unusual file uploads",
                    "Scan for webshell signatures"
                ],
                mitigations=[
                    "Implement file integrity monitoring",
                    "Use read-only file systems",
                    "Restrict file upload capabilities",
                    "Regular system baseline checks"
                ]
            ))
    
    def _check_privilege_escalation(self, nodes: List[Dict], connections: List[Dict]):
        """TA0004: Privilege Escalation"""
        
        # T1068: Exploitation for Privilege Escalation
        containers = [n for n in nodes if self._is_container(n)]
        
        if containers:
            self.techniques.append(AttackTechnique(
                technique_id="T1068",
                name="Exploitation for Privilege Escalation",
                tactic=AttackTactic.PRIVILEGE_ESCALATION,
                description="Container vulnerabilities allow escalation to host root access",
                possible=True,
                affected_components=[c.get('id') for c in containers],
                attack_path="Container access → Exploit escape vulnerability → Host root access",
                detection_methods=[
                    "Monitor container syscalls",
                    "Detect privilege escalation attempts",
                    "Use runtime security tools (Falco)"
                ],
                mitigations=[
                    "Run containers as non-root",
                    "Use security profiles (AppArmor, SELinux)",
                    "Drop unnecessary capabilities",
                    "Keep container runtime updated"
                ]
            ))
        
        # T1078.003: Valid Accounts - Cloud Accounts
        cloud_services = [n for n in nodes if self._is_cloud_service(n)]
        
        if cloud_services:
            self.techniques.append(AttackTechnique(
                technique_id="T1078.003",
                name="Valid Accounts: Cloud Accounts",
                tactic=AttackTactic.PRIVILEGE_ESCALATION,
                description="Compromised cloud service account can escalate privileges",
                possible=True,
                affected_components=[cs.get('id') for cs in cloud_services],
                attack_path="Steal cloud credentials → Access cloud console → Escalate IAM privileges",
                detection_methods=[
                    "Monitor IAM policy changes",
                    "Track privilege escalation attempts",
                    "Use CloudTrail/Activity logs"
                ],
                mitigations=[
                    "Implement least privilege IAM policies",
                    "Use service accounts with minimal permissions",
                    "Enable MFA for cloud access",
                    "Regular IAM policy audits"
                ]
            ))
    
    def _check_defense_evasion(self, nodes: List[Dict], connections: List[Dict]):
        """TA0005: Defense Evasion"""
        
        # T1070: Indicator Removal on Host
        logging_services = [n for n in nodes if self._is_logging(n)]
        
        if not logging_services:
            self.techniques.append(AttackTechnique(
                technique_id="T1070",
                name="Indicator Removal on Host",
                tactic=AttackTactic.DEFENSE_EVASION,
                description="Without centralized logging, attacker can delete local logs",
                possible=True,
                affected_components=["architecture"],
                attack_path="Compromise system → Delete local logs → Hide attack traces",
                detection_methods=[
                    "Centralized log collection",
                    "Monitor for log deletion events",
                    "Use write-once log storage"
                ],
                mitigations=[
                    "Implement centralized SIEM",
                    "Forward logs in real-time",
                    "Use immutable log storage",
                    "Enable log file protection"
                ]
            ))
        
        # T1562.001: Disable or Modify Tools
        ids_ips = [n for n in nodes if self._is_ids_ips(n)]
        
        if not ids_ips:
            self.techniques.append(AttackTechnique(
                technique_id="T1562.001",
                name="Impair Defenses: Disable or Modify Tools",
                tactic=AttackTactic.DEFENSE_EVASION,
                description="Without IDS/IPS, attacker actions go undetected",
                possible=True,
                affected_components=["architecture"],
                attack_path="Gain access → Perform malicious actions undetected",
                detection_methods=[
                    "Deploy IDS/IPS",
                    "Monitor security tool status",
                    "Use network traffic analysis"
                ],
                mitigations=[
                    "Deploy IDS/IPS solutions",
                    "Use network behavior analysis",
                    "Implement EDR on endpoints",
                    "Enable tamper protection"
                ]
            ))
    
    def _check_credential_access(self, nodes: List[Dict], connections: List[Dict]):
        """TA0006: Credential Access"""
        
        # T1110: Brute Force
        auth_services = [n for n in nodes if self._is_auth_component(n)]
        rate_limiters = [n for n in nodes if self._is_rate_limiter(n)]
        
        if auth_services and not rate_limiters:
            self.techniques.append(AttackTechnique(
                technique_id="T1110",
                name="Brute Force",
                tactic=AttackTactic.CREDENTIAL_ACCESS,
                description="Authentication services without rate limiting vulnerable to brute force",
                possible=True,
                affected_components=[auth.get('id') for auth in auth_services],
                attack_path="Enumerate users → Brute force passwords → Gain access",
                detection_methods=[
                    "Monitor failed login attempts",
                    "Implement account lockout",
                    "Use anomaly detection"
                ],
                mitigations=[
                    "Implement rate limiting",
                    "Use CAPTCHA after failures",
                    "Deploy account lockout policy",
                    "Enforce strong passwords"
                ]
            ))
        
        # T1557: Man-in-the-Middle
        unencrypted_conns = [c for c in connections if not self._connection_encrypted(c)]
        
        if unencrypted_conns:
            affected = list(set([c.get('source') for c in unencrypted_conns] + [c.get('target') for c in unencrypted_conns]))
            self.techniques.append(AttackTechnique(
                technique_id="T1557",
                name="Man-in-the-Middle",
                tactic=AttackTactic.CREDENTIAL_ACCESS,
                description="Unencrypted connections allow credential interception",
                possible=True,
                affected_components=affected,
                attack_path="Position on network → Intercept traffic → Steal credentials",
                detection_methods=[
                    "Monitor for ARP spoofing",
                    "Detect SSL stripping attempts",
                    "Use certificate pinning"
                ],
                mitigations=[
                    "Enforce TLS/SSL everywhere",
                    "Use HSTS headers",
                    "Implement certificate pinning",
                    "Deploy 802.1X authentication"
                ]
            ))
    
    def _check_discovery(self, nodes: List[Dict], connections: List[Dict]):
        """TA0007: Discovery"""
        
        # T1046: Network Service Scanning
        if not self._has_network_segmentation(nodes):
            self.techniques.append(AttackTechnique(
                technique_id="T1046",
                name="Network Service Scanning",
                tactic=AttackTactic.DISCOVERY,
                description="Flat network allows comprehensive service discovery after initial access",
                possible=True,
                affected_components=["architecture"],
                attack_path="Gain foothold → Scan internal network → Map all services",
                detection_methods=[
                    "Monitor internal port scans",
                    "Deploy network IDS",
                    "Track unusual network connections"
                ],
                mitigations=[
                    "Implement network segmentation",
                    "Use micro-segmentation",
                    "Deploy host-based firewalls",
                    "Limit service exposure"
                ]
            ))
    
    def _check_lateral_movement(self, nodes: List[Dict], connections: List[Dict]):
        """TA0008: Lateral Movement"""
        
        # T1021: Remote Services
        if not self._has_network_segmentation(nodes):
            self.techniques.append(AttackTechnique(
                technique_id="T1021",
                name="Remote Services",
                tactic=AttackTactic.LATERAL_MOVEMENT,
                description="Flat network enables easy lateral movement between systems",
                possible=True,
                affected_components=["architecture"],
                attack_path="Compromise one system → Use remote services → Move laterally",
                detection_methods=[
                    "Monitor remote desktop connections",
                    "Track SSH/RDP usage patterns",
                    "Use network segmentation logs"
                ],
                mitigations=[
                    "Implement network segmentation",
                    "Use jump servers/bastions",
                    "Enforce MFA for remote access",
                    "Limit lateral movement paths"
                ]
            ))
        
        # T1550: Use Alternate Authentication Material
        databases = [n for n in nodes if self._is_database(n)]
        
        if databases:
            self.techniques.append(AttackTechnique(
                technique_id="T1550",
                name="Use Alternate Authentication Material",
                tactic=AttackTactic.LATERAL_MOVEMENT,
                description="Stolen database credentials can be reused across systems",
                possible=True,
                affected_components=[db.get('id') for db in databases],
                attack_path="Extract credentials from DB → Reuse on other systems → Lateral movement",
                detection_methods=[
                    "Monitor for credential reuse",
                    "Track authentication across systems",
                    "Use behavior analytics"
                ],
                mitigations=[
                    "Use unique credentials per system",
                    "Implement credential vault",
                    "Rotate credentials regularly",
                    "Use certificate-based auth"
                ]
            ))
    
    def _check_collection(self, nodes: List[Dict], connections: List[Dict]):
        """TA0009: Collection"""
        
        # T1530: Data from Cloud Storage Object
        cloud_storage = [n for n in nodes if self._is_cloud_storage(n)]
        
        if cloud_storage:
            self.techniques.append(AttackTechnique(
                technique_id="T1530",
                name="Data from Cloud Storage Object",
                tactic=AttackTactic.COLLECTION,
                description="Misconfigured cloud storage allows unauthorized data access",
                possible=True,
                affected_components=[cs.get('id') for cs in cloud_storage],
                attack_path="Find public/misconfigured storage → Download sensitive data",
                detection_methods=[
                    "Monitor storage access patterns",
                    "Track unusual download volumes",
                    "Use cloud security posture management"
                ],
                mitigations=[
                    "Configure private storage buckets",
                    "Use IAM policies for access control",
                    "Enable access logging",
                    "Regular permission audits"
                ]
            ))
        
        # T1119: Automated Collection
        databases = [n for n in nodes if self._is_database(n)]
        
        if databases:
            self.techniques.append(AttackTechnique(
                technique_id="T1119",
                name="Automated Collection",
                tactic=AttackTactic.COLLECTION,
                description="Attacker can automate data collection from databases",
                possible=True,
                affected_components=[db.get('id') for db in databases],
                attack_path="Gain DB access → Run automated queries → Collect bulk data",
                detection_methods=[
                    "Monitor query patterns",
                    "Detect unusual data access volumes",
                    "Track long-running queries"
                ],
                mitigations=[
                    "Implement query rate limiting",
                    "Use database activity monitoring",
                    "Deploy data loss prevention",
                    "Encrypt sensitive data columns"
                ]
            ))
    
    def _check_command_and_control(self, nodes: List[Dict], connections: List[Dict]):
        """TA0011: Command and Control"""
        
        # T1071: Application Layer Protocol
        proxy_services = [n for n in nodes if self._is_proxy(n)]
        
        if not proxy_services:
            self.techniques.append(AttackTechnique(
                technique_id="T1071",
                name="Application Layer Protocol",
                tactic=AttackTactic.COMMAND_AND_CONTROL,
                description="Without egress filtering, malware can use HTTP/HTTPS for C2",
                possible=True,
                affected_components=["architecture"],
                attack_path="Install malware → Connect to C2 server → Receive commands",
                detection_methods=[
                    "Monitor egress traffic",
                    "Use DNS filtering",
                    "Deploy network traffic analysis",
                    "Track unusual outbound connections"
                ],
                mitigations=[
                    "Deploy egress filtering",
                    "Use proxy for outbound traffic",
                    "Implement DNS security",
                    "Deploy SSL inspection"
                ]
            ))
    
    def _check_exfiltration(self, nodes: List[Dict], connections: List[Dict]):
        """TA0010: Exfiltration"""
        
        # T1048: Exfiltration Over Alternative Protocol
        monitoring_services = [n for n in nodes if self._is_network_monitoring(n)]
        
        if not monitoring_services:
            self.techniques.append(AttackTechnique(
                technique_id="T1048",
                name="Exfiltration Over Alternative Protocol",
                tactic=AttackTactic.EXFILTRATION,
                description="Without network monitoring, data can be exfiltrated via alternative protocols",
                possible=True,
                affected_components=["architecture"],
                attack_path="Collect data → Use DNS/ICMP for exfiltration → Bypass controls",
                detection_methods=[
                    "Monitor DNS query sizes",
                    "Track ICMP traffic patterns",
                    "Use network behavior analysis"
                ],
                mitigations=[
                    "Deploy data loss prevention",
                    "Monitor all protocols",
                    "Use egress filtering",
                    "Deploy network traffic analysis"
                ]
            ))
        
        # T1041: Exfiltration Over C2 Channel
        self.techniques.append(AttackTechnique(
            technique_id="T1041",
            name="Exfiltration Over C2 Channel",
            tactic=AttackTactic.EXFILTRATION,
            description="Attacker can exfiltrate data through established C2 channel",
            possible=True,
            affected_components=["architecture"],
            attack_path="Establish C2 → Collect data → Exfiltrate via C2 channel",
            detection_methods=[
                "Monitor for data exfiltration patterns",
                "Track unusual outbound traffic volumes",
                "Use DLP solutions"
            ],
            mitigations=[
                "Deploy data loss prevention",
                "Use egress traffic monitoring",
                "Implement rate limiting on outbound traffic",
                "Encrypt and tag sensitive data"
            ]
        ))
    
    def _check_impact(self, nodes: List[Dict], connections: List[Dict]):
        """TA0040: Impact"""
        
        # T1486: Data Encrypted for Impact (Ransomware)
        backup_systems = [n for n in nodes if self._is_backup_system(n)]
        databases = [n for n in nodes if self._is_database(n)]
        
        if databases and not backup_systems:
            self.techniques.append(AttackTechnique(
                technique_id="T1486",
                name="Data Encrypted for Impact",
                tactic=AttackTactic.IMPACT,
                description="Without backups, ransomware can cause permanent data loss",
                possible=True,
                affected_components=[db.get('id') for db in databases],
                attack_path="Gain access → Deploy ransomware → Encrypt data → Demand ransom",
                detection_methods=[
                    "Monitor for mass file encryption",
                    "Detect ransomware signatures",
                    "Track unusual file modifications"
                ],
                mitigations=[
                    "Implement automated backups",
                    "Use immutable backup storage",
                    "Deploy ransomware protection",
                    "Test backup restoration regularly"
                ]
            ))
        
        # T1498: Network Denial of Service
        load_balancers = [n for n in nodes if self._is_load_balancer(n)]
        
        if not load_balancers:
            self.techniques.append(AttackTechnique(
                technique_id="T1498",
                name="Network Denial of Service",
                tactic=AttackTactic.IMPACT,
                description="Without load balancer and DDoS protection, service vulnerable to DoS",
                possible=True,
                affected_components=["architecture"],
                attack_path="Flood target with traffic → Exhaust resources → Service unavailable",
                detection_methods=[
                    "Monitor traffic volumes",
                    "Detect SYN floods",
                    "Use anomaly detection"
                ],
                mitigations=[
                    "Deploy load balancer with DDoS protection",
                    "Use CDN with DDoS mitigation",
                    "Implement rate limiting",
                    "Use cloud-based DDoS protection services"
                ]
            ))
    
    # ==================== Helper Methods ====================
    
    def _is_web_server(self, node: Dict) -> bool:
        keywords = ['web_server', 'web server', 'apache', 'nginx', 'iis']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_firewall(self, node: Dict) -> bool:
        keywords = ['firewall', 'fw', 'security_group', 'nacl']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_waf(self, node: Dict) -> bool:
        keywords = ['waf', 'web application firewall']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_public_facing(self, node: Dict) -> bool:
        keywords = ['web', 'api', 'public', 'external']
        name = node.get('name', '').lower()
        return any(kw in name for kw in keywords)
    
    def _is_vpn(self, node: Dict) -> bool:
        keywords = ['vpn', 'virtual private network']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_mfa(self, node: Dict) -> bool:
        keywords = ['mfa', 'multi-factor', '2fa', 'totp']
        name = node.get('name', '').lower()
        return any(kw in name for kw in keywords)
    
    def _is_auth_component(self, node: Dict) -> bool:
        keywords = ['auth', 'identity', 'oauth', 'oidc', 'saml']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_app_server(self, node: Dict) -> bool:
        keywords = ['app_server', 'application', 'backend']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_container(self, node: Dict) -> bool:
        keywords = ['container', 'docker', 'pod', 'kubernetes']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_cloud_service(self, node: Dict) -> bool:
        keywords = ['aws', 'azure', 'gcp', 'cloud']
        name = node.get('name', '').lower()
        return any(kw in name for kw in keywords)
    
    def _is_logging(self, node: Dict) -> bool:
        keywords = ['log', 'siem', 'splunk', 'elk']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_ids_ips(self, node: Dict) -> bool:
        keywords = ['ids', 'ips', 'intrusion', 'snort']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_rate_limiter(self, node: Dict) -> bool:
        keywords = ['rate_limit', 'throttle']
        name = node.get('name', '').lower()
        return any(kw in name for kw in keywords)
    
    def _is_database(self, node: Dict) -> bool:
        keywords = ['database', 'db', 'postgres', 'mysql', 'mongo']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_backup_system(self, node: Dict) -> bool:
        keywords = ['backup', 'snapshot', 'recovery']
        name = node.get('name', '').lower()
        return any(kw in name for kw in keywords)
    
    def _is_load_balancer(self, node: Dict) -> bool:
        keywords = ['load_balancer', 'load balancer', 'alb', 'elb']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_proxy(self, node: Dict) -> bool:
        keywords = ['proxy', 'forward_proxy', 'reverse_proxy']
        name = node.get('name', '').lower()
        return any(kw in name for kw in keywords)
    
    def _is_network_monitoring(self, node: Dict) -> bool:
        keywords = ['monitor', 'network_monitor', 'traffic_analysis']
        name = node.get('name', '').lower()
        return any(kw in name for kw in keywords)
    
    def _is_cloud_storage(self, node: Dict) -> bool:
        keywords = ['s3', 'blob', 'bucket', 'cloud_storage']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _has_network_segmentation(self, nodes: List[Dict]) -> bool:
        zones = set()
        for node in nodes:
            zone = node.get('properties', {}).get('zone', 'default')
            zones.add(zone)
        return len(zones) > 1
    
    def _connection_encrypted(self, conn: Dict) -> bool:
        props = conn.get('properties', {})
        encrypted = props.get('encrypted', False)
        protocol = props.get('protocol', '').lower()
        secure_protocols = ['https', 'tls', 'ssl', 'ssh', 'vpn']
        return encrypted or any(sp in protocol for sp in secure_protocols)
