"""
STRIDE Threat Modeling Engine
Implements Microsoft's STRIDE methodology for threat identification
"""

from typing import List, Dict, Any
from dataclasses import dataclass
from enum import Enum

class ThreatCategory(Enum):
    """STRIDE threat categories"""
    SPOOFING = "Spoofing Identity"
    TAMPERING = "Tampering with Data"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"

class AssetType(Enum):
    """Asset classification for threat modeling"""
    PROCESS = "process"
    DATA_STORE = "datastore"
    DATA_FLOW = "dataflow"
    EXTERNAL_ENTITY = "external_entity"
    TRUST_BOUNDARY = "trust_boundary"

@dataclass
class Threat:
    """Represents a comprehensive STRIDE threat with extended attributes"""
    threat_id: str
    category: ThreatCategory
    title: str
    description: str
    affected_asset: str
    asset_type: AssetType
    likelihood: str  # high/medium/low
    impact: str  # critical/high/medium/low
    attack_vector: str
    prerequisites: List[str]
    mitigations: List[str]
    # Extended threat attributes
    severity: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW (overall risk)
    risk_score: float = 5.0  # 0-10 scale
    exploitability: str = "MEDIUM"  # HIGH, MEDIUM, LOW
    discoverability: str = "MEDIUM"  # EASY, MEDIUM, HARD
    reproducibility: str = "ALWAYS"  # ALWAYS, COMMON, UNCOMMON, RARE
    affected_users: str = "SOME"  # ALL, SOME, FEW, ADMIN_ONLY
    # Security properties violated
    confidentiality_breach: bool = False
    integrity_breach: bool = False
    availability_breach: bool = False
    authenticity_breach: bool = False
    authorization_breach: bool = False
    non_repudiation_breach: bool = False
    # Attack characteristics
    attack_complexity: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    attack_surface: str = "NETWORK"  # NETWORK, LOCAL, PHYSICAL, SOCIAL
    required_privileges: str = "USER"  # NONE, USER, ADMIN, ROOT
    user_interaction_required: bool = False
    # Detection and monitoring
    detection_methods: List[str] = None
    monitoring_indicators: List[str] = None  # IoCs or behavioral indicators
    log_sources: List[str] = None  # Where to find evidence
    alert_rules: List[str] = None  # SIEM rules or signatures
    # Business context
    business_process_impact: List[str] = None
    data_classification: str = "INTERNAL"  # PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
    affected_compliance: List[str] = None  # Compliance frameworks affected
    financial_impact: str = "$10K-$100K"
    reputational_impact: str = "MEDIUM"  # HIGH, MEDIUM, LOW
    legal_implications: List[str] = None
    # Remediation
    mitigation_priority: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW
    remediation_effort: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    remediation_cost: str = "$5K-$25K"
    compensating_controls: List[str] = None
    residual_risk: str = "LOW"  # After mitigation
    # Threat intelligence
    known_exploits: List[str] = None
    threat_actors: List[str] = None  # Known threat groups
    attack_patterns: List[str] = None  # CAPEC IDs
    related_cves: List[str] = None
    similar_incidents: List[str] = None
    # Framework mappings
    mitre_techniques: List[str] = None  # MITRE ATT&CK technique IDs
    cwe_ids: List[str] = None
    owasp_categories: List[str] = None
    nist_controls: List[str] = None
    kill_chain_phase: str = "UNKNOWN"  # Cyber kill chain phase
    
    def __post_init__(self):
        """Initialize list fields if None"""
        if self.detection_methods is None:
            self.detection_methods = []
        if self.monitoring_indicators is None:
            self.monitoring_indicators = []
        if self.log_sources is None:
            self.log_sources = []
        if self.alert_rules is None:
            self.alert_rules = []
        if self.business_process_impact is None:
            self.business_process_impact = []
        if self.affected_compliance is None:
            self.affected_compliance = []
        if self.legal_implications is None:
            self.legal_implications = []
        if self.compensating_controls is None:
            self.compensating_controls = []
        if self.known_exploits is None:
            self.known_exploits = []
        if self.threat_actors is None:
            self.threat_actors = []
        if self.attack_patterns is None:
            self.attack_patterns = []
        if self.related_cves is None:
            self.related_cves = []
        if self.similar_incidents is None:
            self.similar_incidents = []
        if self.mitre_techniques is None:
            self.mitre_techniques = []
        if self.cwe_ids is None:
            self.cwe_ids = []
        if self.owasp_categories is None:
            self.owasp_categories = []
        if self.nist_controls is None:
            self.nist_controls = []

class STRIDEThreatEngine:
    """
    STRIDE-based threat modeling engine
    Analyzes architecture for STRIDE threats
    """
    
    def __init__(self):
        self.threats: List[Threat] = []
    
    def analyze_architecture(self, architecture: Dict[str, Any]) -> List[Threat]:
        """
        Perform STRIDE threat modeling on architecture
        """
        self.threats = []
        nodes = architecture.get('nodes', [])
        connections = architecture.get('connections', [])
        
        # Analyze each component type
        for node in nodes:
            self._analyze_spoofing_threats(node, nodes, connections)
            self._analyze_tampering_threats(node, connections)
            self._analyze_repudiation_threats(node, connections)
            self._analyze_information_disclosure_threats(node, connections)
            self._analyze_dos_threats(node, nodes)
            self._analyze_elevation_threats(node, connections)
        
        # Analyze data flows
        for connection in connections:
            self._analyze_connection_threats(connection, nodes)
        
        return self.threats
    
    def _analyze_spoofing_threats(self, node: Dict, all_nodes: List[Dict], connections: List[Dict]):
        """
        S - Spoofing Identity
        Threat: Attacker impersonates another user/system
        """
        node_id = node.get('id')
        node_name = node.get('name', 'Unknown')
        node_type = node.get('properties', {}).get('component_type', '')
        
        # Threat: Unauthenticated API endpoint
        if self._is_api_component(node):
            incoming_conns = [c for c in connections if c.get('target') == node_id]
            auth_present = any(self._connection_has_auth(c) for c in incoming_conns)
            
            if not auth_present:
                self.threats.append(Threat(
                    threat_id=f"STRIDE-S-001-{node_id}",
                    category=ThreatCategory.SPOOFING,
                    title=f"Unauthenticated API Access: {node_name}",
                    description=f"API component '{node_name}' accepts requests without authentication. Attacker can spoof legitimate clients.",
                    affected_asset=node_id,
                    asset_type=AssetType.PROCESS,
                    likelihood="high",
                    impact="high",
                    attack_vector="Send unauthenticated API requests with forged identity",
                    prerequisites=["Network access to API endpoint"],
                    mitigations=[
                        "Implement API key authentication",
                        "Use OAuth 2.0 or OpenID Connect",
                        "Require mutual TLS authentication",
                        "Implement IP whitelisting"
                    ]
                ))
        
        # Threat: Database without authentication
        if self._is_database(node):
            incoming_conns = [c for c in connections if c.get('target') == node_id]
            
            for conn in incoming_conns:
                if not self._connection_has_auth(conn):
                    self.threats.append(Threat(
                        threat_id=f"STRIDE-S-002-{node_id}",
                        category=ThreatCategory.SPOOFING,
                        title=f"Unauthenticated Database Connection: {node_name}",
                        description=f"Database '{node_name}' accepts connections without proper authentication. Attacker can spoof database client.",
                        affected_asset=node_id,
                        asset_type=AssetType.DATA_STORE,
                        likelihood="medium",
                        impact="critical",
                        attack_vector="Direct connection to database port with forged credentials",
                        prerequisites=["Network access to database port"],
                        mitigations=[
                            "Enable database authentication (username/password)",
                            "Use certificate-based authentication",
                            "Implement connection string encryption",
                            "Restrict database access via security groups"
                        ]
                    ))
        
        # Threat: Web server without HTTPS
        if self._is_web_server(node):
            incoming_conns = [c for c in connections if c.get('target') == node_id]
            has_https = any(self._connection_uses_https(c) for c in incoming_conns)
            
            if not has_https:
                self.threats.append(Threat(
                    threat_id=f"STRIDE-S-003-{node_id}",
                    category=ThreatCategory.SPOOFING,
                    title=f"Web Server Without HTTPS: {node_name}",
                    description=f"Web server '{node_name}' accepts HTTP traffic. Vulnerable to session hijacking and credential theft.",
                    affected_asset=node_id,
                    asset_type=AssetType.PROCESS,
                    likelihood="high",
                    impact="high",
                    attack_vector="Man-in-the-middle attack to steal session cookies",
                    prerequisites=["Network position between client and server"],
                    mitigations=[
                        "Enable HTTPS only",
                        "Install TLS certificate",
                        "Implement HSTS headers",
                        "Redirect HTTP to HTTPS"
                    ]
                ))
    
    def _analyze_tampering_threats(self, node: Dict, connections: List[Dict]):
        """
        T - Tampering with Data
        Threat: Attacker modifies data in transit or at rest
        """
        node_id = node.get('id')
        node_name = node.get('name', 'Unknown')
        
        # Threat: Unencrypted data in transit
        outgoing_conns = [c for c in connections if c.get('source') == node_id]
        
        for conn in outgoing_conns:
            if not self._connection_encrypted(conn):
                self.threats.append(Threat(
                    threat_id=f"STRIDE-T-001-{conn.get('id')}",
                    category=ThreatCategory.TAMPERING,
                    title=f"Unencrypted Data Flow from {node_name}",
                    description=f"Data transmitted from '{node_name}' without encryption. Attacker can intercept and modify data.",
                    affected_asset=conn.get('id'),
                    asset_type=AssetType.DATA_FLOW,
                    likelihood="high",
                    impact="high",
                    attack_vector="Man-in-the-middle attack to modify data in transit",
                    prerequisites=["Network access between source and target"],
                    mitigations=[
                        "Enable TLS/SSL encryption",
                        "Implement message signing (HMAC)",
                        "Use VPN tunnel for sensitive data",
                        "Implement end-to-end encryption"
                    ]
                ))
        
        # Threat: Database without integrity checks
        if self._is_database(node):
            self.threats.append(Threat(
                threat_id=f"STRIDE-T-002-{node_id}",
                category=ThreatCategory.TAMPERING,
                title=f"Database Without Integrity Verification: {node_name}",
                description=f"Database '{node_name}' lacks integrity checking mechanisms. Unauthorized modifications may go undetected.",
                affected_asset=node_id,
                asset_type=AssetType.DATA_STORE,
                likelihood="medium",
                impact="high",
                attack_vector="Unauthorized database access to modify records",
                prerequisites=["Database access (legitimate or compromised)"],
                mitigations=[
                    "Enable database audit logging",
                    "Implement row-level checksums",
                    "Use blockchain or ledger database for critical data",
                    "Enable database change tracking"
                ]
            ))
    
    def _analyze_repudiation_threats(self, node: Dict, connections: List[Dict]):
        """
        R - Repudiation
        Threat: Attacker denies performing an action (lack of audit trail)
        """
        node_id = node.get('id')
        node_name = node.get('name', 'Unknown')
        
        # Threat: No logging for critical operations
        if self._is_critical_component(node):
            self.threats.append(Threat(
                threat_id=f"STRIDE-R-001-{node_id}",
                category=ThreatCategory.REPUDIATION,
                title=f"No Audit Logging: {node_name}",
                description=f"Critical component '{node_name}' lacks audit logging. Users can deny performing actions.",
                affected_asset=node_id,
                asset_type=AssetType.PROCESS,
                likelihood="medium",
                impact="medium",
                attack_vector="Perform malicious actions then deny responsibility",
                prerequisites=["Access to system"],
                mitigations=[
                    "Implement comprehensive audit logging",
                    "Log all authentication attempts",
                    "Log all data access and modifications",
                    "Use write-once log storage (WORM)",
                    "Implement log signing for non-repudiation"
                ]
            ))
        
        # Threat: No transaction logging for database
        if self._is_database(node):
            self.threats.append(Threat(
                threat_id=f"STRIDE-R-002-{node_id}",
                category=ThreatCategory.REPUDIATION,
                title=f"No Transaction Audit Trail: {node_name}",
                description=f"Database '{node_name}' may lack transaction audit trail. Cannot prove who made changes.",
                affected_asset=node_id,
                asset_type=AssetType.DATA_STORE,
                likelihood="medium",
                impact="high",
                attack_vector="Modify data then deny making changes",
                prerequisites=["Database access"],
                mitigations=[
                    "Enable database transaction logs",
                    "Log user identity for all queries",
                    "Implement trigger-based audit tables",
                    "Use temporal tables for change history"
                ]
            ))
    
    def _analyze_information_disclosure_threats(self, node: Dict, connections: List[Dict]):
        """
        I - Information Disclosure
        Threat: Attacker gains unauthorized access to confidential data
        """
        node_id = node.get('id')
        node_name = node.get('name', 'Unknown')
        
        # Threat: Database exposed to internet
        if self._is_database(node):
            incoming_conns = [c for c in connections if c.get('target') == node_id]
            
            # Check if any incoming connection is from external/public source
            for conn in incoming_conns:
                if self._connection_from_internet(conn):
                    self.threats.append(Threat(
                        threat_id=f"STRIDE-I-001-{node_id}",
                        category=ThreatCategory.INFORMATION_DISCLOSURE,
                        title=f"Database Exposed to Internet: {node_name}",
                        description=f"Database '{node_name}' accepts connections from internet. Sensitive data at risk of exposure.",
                        affected_asset=node_id,
                        asset_type=AssetType.DATA_STORE,
                        likelihood="high",
                        impact="critical",
                        attack_vector="Direct connection to database port from internet",
                        prerequisites=["Internet connectivity", "Knowledge of database endpoint"],
                        mitigations=[
                            "Place database in private subnet",
                            "Use VPN for database access",
                            "Implement firewall rules (allow only application servers)",
                            "Enable database encryption at rest"
                        ]
                    ))
        
        # Threat: Unencrypted sensitive data storage
        if self._is_database(node) or self._is_storage(node):
            self.threats.append(Threat(
                threat_id=f"STRIDE-I-002-{node_id}",
                category=ThreatCategory.INFORMATION_DISCLOSURE,
                title=f"Unencrypted Data at Rest: {node_name}",
                description=f"Storage '{node_name}' may store sensitive data unencrypted. Data accessible if storage is compromised.",
                affected_asset=node_id,
                asset_type=AssetType.DATA_STORE,
                likelihood="medium",
                impact="critical",
                attack_vector="Physical access to storage or backup media",
                prerequisites=["Physical or admin access to storage"],
                mitigations=[
                    "Enable encryption at rest (AES-256)",
                    "Use Transparent Data Encryption (TDE)",
                    "Encrypt backups",
                    "Use hardware security module (HSM) for key management"
                ]
            ))
        
        # Threat: Verbose error messages
        if self._is_web_server(node) or self._is_api_component(node):
            self.threats.append(Threat(
                threat_id=f"STRIDE-I-003-{node_id}",
                category=ThreatCategory.INFORMATION_DISCLOSURE,
                title=f"Information Leakage via Error Messages: {node_name}",
                description=f"Component '{node_name}' may expose sensitive information in error messages (stack traces, database queries).",
                affected_asset=node_id,
                asset_type=AssetType.PROCESS,
                likelihood="high",
                impact="medium",
                attack_vector="Trigger errors to extract system information",
                prerequisites=["Access to application"],
                mitigations=[
                    "Implement custom error pages",
                    "Log detailed errors server-side only",
                    "Return generic error messages to clients",
                    "Disable debug mode in production"
                ]
            ))
    
    def _analyze_dos_threats(self, node: Dict, all_nodes: List[Dict]):
        """
        D - Denial of Service
        Threat: Attacker makes system unavailable to legitimate users
        """
        node_id = node.get('id')
        node_name = node.get('name', 'Unknown')
        
        # Threat: No rate limiting
        if self._is_api_component(node) or self._is_web_server(node):
            rate_limiters = [n for n in all_nodes if self._is_rate_limiter(n)]
            
            if not rate_limiters:
                self.threats.append(Threat(
                    threat_id=f"STRIDE-D-001-{node_id}",
                    category=ThreatCategory.DENIAL_OF_SERVICE,
                    title=f"No Rate Limiting: {node_name}",
                    description=f"Component '{node_name}' lacks rate limiting. Vulnerable to resource exhaustion attacks.",
                    affected_asset=node_id,
                    asset_type=AssetType.PROCESS,
                    likelihood="high",
                    impact="high",
                    attack_vector="Flood system with requests to exhaust resources",
                    prerequisites=["Network access to endpoint"],
                    mitigations=[
                        "Implement rate limiting (requests per minute/IP)",
                        "Use API Gateway with throttling",
                        "Deploy CDN with DDoS protection",
                        "Implement request queuing with backpressure"
                    ]
                ))
        
        # Threat: Single point of failure
        if self._is_critical_component(node):
            redundant_components = [n for n in all_nodes if n.get('name') == node_name and n.get('id') != node_id]
            
            if not redundant_components:
                self.threats.append(Threat(
                    threat_id=f"STRIDE-D-002-{node_id}",
                    category=ThreatCategory.DENIAL_OF_SERVICE,
                    title=f"Single Point of Failure: {node_name}",
                    description=f"Critical component '{node_name}' has no redundancy. System unavailable if component fails.",
                    affected_asset=node_id,
                    asset_type=AssetType.PROCESS,
                    likelihood="medium",
                    impact="critical",
                    attack_vector="Target single component to bring down entire system",
                    prerequisites=["Knowledge of architecture"],
                    mitigations=[
                        "Deploy multiple instances (cluster)",
                        "Use load balancer for high availability",
                        "Implement auto-scaling",
                        "Configure health checks and automatic failover"
                    ]
                ))
        
        # Threat: Database without connection pooling
        if self._is_database(node):
            self.threats.append(Threat(
                threat_id=f"STRIDE-D-003-{node_id}",
                category=ThreatCategory.DENIAL_OF_SERVICE,
                title=f"Database Resource Exhaustion Risk: {node_name}",
                description=f"Database '{node_name}' may lack connection pooling. Vulnerable to connection exhaustion attacks.",
                affected_asset=node_id,
                asset_type=AssetType.DATA_STORE,
                likelihood="medium",
                impact="high",
                attack_vector="Open maximum number of connections to exhaust database resources",
                prerequisites=["Database access"],
                mitigations=[
                    "Configure connection pooling",
                    "Set maximum connection limits",
                    "Implement query timeouts",
                    "Use read replicas to distribute load"
                ]
            ))
    
    def _analyze_elevation_threats(self, node: Dict, connections: List[Dict]):
        """
        E - Elevation of Privilege
        Threat: Attacker gains higher privileges than authorized
        """
        node_id = node.get('id')
        node_name = node.get('name', 'Unknown')
        
        # Threat: Database with admin privileges
        if self._is_database(node):
            self.threats.append(Threat(
                threat_id=f"STRIDE-E-001-{node_id}",
                category=ThreatCategory.ELEVATION_OF_PRIVILEGE,
                title=f"Database Admin Privilege Risk: {node_name}",
                description=f"Application may connect to database '{node_name}' with admin privileges. Compromised app can perform admin operations.",
                affected_asset=node_id,
                asset_type=AssetType.DATA_STORE,
                likelihood="medium",
                impact="critical",
                attack_vector="Exploit application vulnerability to execute admin database commands",
                prerequisites=["Application vulnerability (SQL injection, etc.)"],
                mitigations=[
                    "Use least-privilege database accounts",
                    "Create separate read-only and read-write accounts",
                    "Restrict admin operations to specific admin tools",
                    "Use database roles and permissions"
                ]
            ))
        
        # Threat: No authorization checks
        if self._is_api_component(node):
            self.threats.append(Threat(
                threat_id=f"STRIDE-E-002-{node_id}",
                category=ThreatCategory.ELEVATION_OF_PRIVILEGE,
                title=f"Missing Authorization Controls: {node_name}",
                description=f"API '{node_name}' may lack proper authorization checks. Users can access resources beyond their privileges.",
                affected_asset=node_id,
                asset_type=AssetType.PROCESS,
                likelihood="high",
                impact="high",
                attack_vector="Manipulate requests to access admin endpoints or other users' data",
                prerequisites=["Valid user account"],
                mitigations=[
                    "Implement role-based access control (RBAC)",
                    "Enforce authorization checks on all endpoints",
                    "Use attribute-based access control (ABAC) for fine-grained control",
                    "Implement principle of least privilege"
                ]
            ))
        
        # Threat: Container running as root
        if self._is_container(node):
            self.threats.append(Threat(
                threat_id=f"STRIDE-E-003-{node_id}",
                category=ThreatCategory.ELEVATION_OF_PRIVILEGE,
                title=f"Container Running as Root: {node_name}",
                description=f"Container '{node_name}' may run processes as root. Container escape grants root access to host.",
                affected_asset=node_id,
                asset_type=AssetType.PROCESS,
                likelihood="medium",
                impact="critical",
                attack_vector="Exploit container vulnerability to escape and gain root access to host",
                prerequisites=["Container vulnerability"],
                mitigations=[
                    "Run containers as non-root user",
                    "Use read-only root filesystem",
                    "Drop unnecessary capabilities",
                    "Use security profiles (AppArmor, SELinux)"
                ]
            ))
    
    def _analyze_connection_threats(self, connection: Dict, nodes: List[Dict]):
        """Analyze threats specific to data flows/connections"""
        
        source_id = connection.get('source')
        target_id = connection.get('target')
        
        source_node = next((n for n in nodes if n.get('id') == source_id), None)
        target_node = next((n for n in nodes if n.get('id') == target_id), None)
        
        if not source_node or not target_node:
            return
        
        # Threat: Cross-trust-boundary without encryption
        if self._crosses_trust_boundary(source_node, target_node):
            if not self._connection_encrypted(connection):
                self.threats.append(Threat(
                    threat_id=f"STRIDE-TB-001-{connection.get('id')}",
                    category=ThreatCategory.TAMPERING,
                    title=f"Unencrypted Cross-Boundary Communication",
                    description=f"Data flows from {source_node.get('name')} to {target_node.get('name')} crosses trust boundary without encryption.",
                    affected_asset=connection.get('id'),
                    asset_type=AssetType.TRUST_BOUNDARY,
                    likelihood="high",
                    impact="high",
                    attack_vector="Intercept cross-boundary traffic to steal or modify data",
                    prerequisites=["Network position at trust boundary"],
                    mitigations=[
                        "Enable TLS/SSL for all cross-boundary connections",
                        "Use VPN tunnels between trust zones",
                        "Implement network segmentation with firewalls"
                    ]
                ))
    
    # ==================== Helper Methods ====================
    
    def _is_api_component(self, node: Dict) -> bool:
        keywords = ['api', 'rest', 'graphql', 'endpoint', 'gateway']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_database(self, node: Dict) -> bool:
        keywords = ['database', 'db', 'postgres', 'mysql', 'mongo', 'redis', 'sql']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_web_server(self, node: Dict) -> bool:
        keywords = ['web_server', 'web server', 'apache', 'nginx', 'iis']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_storage(self, node: Dict) -> bool:
        keywords = ['storage', 's3', 'blob', 'file_storage', 'bucket']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_container(self, node: Dict) -> bool:
        keywords = ['container', 'docker', 'pod', 'kubernetes']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_critical_component(self, node: Dict) -> bool:
        critical_types = ['database', 'authentication', 'api_gateway', 'load_balancer']
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(ct in comp_type for ct in critical_types)
    
    def _is_rate_limiter(self, node: Dict) -> bool:
        keywords = ['rate_limit', 'throttle', 'rate limiter']
        name = node.get('name', '').lower()
        return any(kw in name for kw in keywords)
    
    def _connection_has_auth(self, connection: Dict) -> bool:
        props = connection.get('properties', {})
        return props.get('authenticated', False) or props.get('auth', False)
    
    def _connection_uses_https(self, connection: Dict) -> bool:
        props = connection.get('properties', {})
        protocol = props.get('protocol', '').lower()
        return protocol == 'https' or 'tls' in protocol or 'ssl' in protocol
    
    def _connection_encrypted(self, connection: Dict) -> bool:
        props = connection.get('properties', {})
        encrypted = props.get('encrypted', False)
        protocol = props.get('protocol', '').lower()
        secure_protocols = ['https', 'tls', 'ssl', 'ssh', 'vpn']
        return encrypted or any(sp in protocol for sp in secure_protocols)
    
    def _connection_from_internet(self, connection: Dict) -> bool:
        # Simplified check - would need more context in real implementation
        props = connection.get('properties', {})
        source = props.get('source_zone', '').lower()
        return 'internet' in source or 'public' in source or 'external' in source
    
    def _crosses_trust_boundary(self, source_node: Dict, target_node: Dict) -> bool:
        """Check if connection crosses trust boundary"""
        source_zone = source_node.get('properties', {}).get('zone', 'unknown')
        target_zone = target_node.get('properties', {}).get('zone', 'unknown')
        
        return source_zone != target_zone
