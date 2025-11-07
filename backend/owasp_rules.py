"""
OWASP Top 10 & ASVS Rule-Based Security Evaluation
Implements comprehensive OWASP security checks without LLM dependency
"""

from typing import List, Dict, Any, Set
from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class OWASPCategory(Enum):
    A01_BROKEN_ACCESS_CONTROL = "A01:2021 - Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021 - Cryptographic Failures"
    A03_INJECTION = "A03:2021 - Injection"
    A04_INSECURE_DESIGN = "A04:2021 - Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021 - Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021 - Identification and Authentication Failures"
    A08_DATA_INTEGRITY_FAILURES = "A08:2021 - Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021 - Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021 - Server-Side Request Forgery"

@dataclass
class SecurityFinding:
    """Represents a comprehensive security vulnerability finding"""
    rule_id: str
    title: str
    description: str
    severity: Severity
    owasp_category: OWASPCategory
    affected_components: List[str]
    cvss_score: float
    cwe_id: str
    mitigation: str
    confidence: str  # high/medium/low
    # Extended attributes for comprehensive analysis
    attack_vector: str = "NETWORK"  # NETWORK, ADJACENT, LOCAL, PHYSICAL
    attack_complexity: str = "LOW"  # LOW, HIGH
    privileges_required: str = "NONE"  # NONE, LOW, HIGH
    user_interaction: str = "NONE"  # NONE, REQUIRED
    scope: str = "UNCHANGED"  # UNCHANGED, CHANGED
    confidentiality_impact: str = "HIGH"  # NONE, LOW, HIGH
    integrity_impact: str = "HIGH"  # NONE, LOW, HIGH
    availability_impact: str = "NONE"  # NONE, LOW, HIGH
    exploitability: str = "HIGH"  # HIGH, MEDIUM, LOW
    remediation_level: str = "OFFICIAL_FIX"  # OFFICIAL_FIX, TEMPORARY_FIX, WORKAROUND, UNAVAILABLE
    report_confidence: str = "CONFIRMED"  # CONFIRMED, REASONABLE, UNKNOWN
    # Business and compliance
    business_impact: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW
    data_sensitivity: str = "HIGH"  # HIGH, MEDIUM, LOW
    compliance_violations: List[str] = None  # PCI-DSS, HIPAA, GDPR, SOC2, etc.
    regulatory_risk: str = "HIGH"  # HIGH, MEDIUM, LOW
    # Detection and response
    detection_difficulty: str = "EASY"  # EASY, MEDIUM, HARD
    false_positive_rate: str = "LOW"  # LOW, MEDIUM, HIGH
    automated_fix_available: bool = False
    # Remediation details
    remediation_priority: str = "P1"  # P0, P1, P2, P3, P4
    estimated_fix_time: str = "1-3 days"
    estimated_fix_cost: str = "$5,000-$15,000"
    requires_downtime: bool = False
    # References and evidence
    references: List[str] = None  # URLs to documentation
    evidence: List[str] = None  # Specific evidence found
    related_findings: List[str] = None  # Related rule IDs
    # Threat intelligence
    exploit_available: bool = False
    exploit_maturity: str = "PROOF_OF_CONCEPT"  # UNPROVEN, PROOF_OF_CONCEPT, FUNCTIONAL, HIGH
    actively_exploited: bool = False
    threat_actor_interest: str = "MEDIUM"  # HIGH, MEDIUM, LOW
    
    def __post_init__(self):
        """Initialize list fields if None"""
        if self.compliance_violations is None:
            self.compliance_violations = []
        if self.references is None:
            self.references = []
        if self.evidence is None:
            self.evidence = []
        if self.related_findings is None:
            self.related_findings = []

class OWASPRuleEngine:
    """
    Rule-based OWASP Top 10 vulnerability scanner
    Uses predefined rules and component analysis
    """
    
    def __init__(self):
        self.findings: List[SecurityFinding] = []
    
    def analyze_architecture(self, architecture: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Analyze architecture against all OWASP rules
        """
        self.findings = []
        nodes = architecture.get('nodes', [])
        connections = architecture.get('connections', [])
        metadata = architecture.get('metadata', {})
        
        # Run all rule checks
        self._check_broken_access_control(nodes, connections)
        self._check_cryptographic_failures(nodes, connections)
        self._check_injection_vulnerabilities(nodes, connections)
        self._check_insecure_design(nodes, connections, metadata)
        self._check_security_misconfiguration(nodes, metadata)
        self._check_vulnerable_components(nodes)
        self._check_authentication_failures(nodes, connections)
        self._check_data_integrity_failures(nodes, connections)
        self._check_logging_failures(nodes)
        self._check_ssrf_vulnerabilities(nodes, connections)
        
        return self.findings
    
    def _check_broken_access_control(self, nodes: List[Dict], connections: List[Dict]):
        """A01: Broken Access Control - OWASP #1"""
        
        # Rule 1.1: Missing authentication gateway
        auth_components = [n for n in nodes if self._is_auth_component(n)]
        if not auth_components:
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A01-001",
                title="Missing Authentication Gateway",
                description="No authentication or identity management component detected. All resources may be publicly accessible without access control.",
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                affected_components=["architecture"],
                cvss_score=9.1,
                cwe_id="CWE-284",
                mitigation="Implement authentication service (OAuth2, OIDC, SAML) before all protected resources. Add API Gateway with authentication middleware.",
                confidence="high"
            ))
        
        # Rule 1.2: Direct database access without API gateway
        databases = [n for n in nodes if self._is_database(n)]
        api_gateways = [n for n in nodes if self._is_api_gateway(n)]
        
        if databases and not api_gateways:
            db_ids = [db.get('id') for db in databases]
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A01-002",
                title="Direct Database Access Without API Gateway",
                description="Database components are exposed without an API Gateway layer. This allows potential direct access and bypass of authorization checks.",
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                affected_components=db_ids,
                cvss_score=8.2,
                cwe_id="CWE-425",
                mitigation="Place API Gateway between clients and databases. Implement role-based access control (RBAC) at gateway level.",
                confidence="high"
            ))
        
        # Rule 1.3: No load balancer for session distribution
        web_servers = [n for n in nodes if self._is_web_server(n)]
        load_balancers = [n for n in nodes if self._is_load_balancer(n)]
        
        if len(web_servers) > 1 and not load_balancers:
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A01-003",
                title="Multiple Web Servers Without Load Balancer",
                description="Multiple web servers without load balancer may cause session management issues and inconsistent access control enforcement.",
                severity=Severity.MEDIUM,
                owasp_category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                affected_components=[ws.get('id') for ws in web_servers],
                cvss_score=5.3,
                cwe_id="CWE-384",
                mitigation="Add load balancer with sticky sessions or centralized session store (Redis).",
                confidence="high"
            ))
    
    def _check_cryptographic_failures(self, nodes: List[Dict], connections: List[Dict]):
        """A02: Cryptographic Failures - formerly Sensitive Data Exposure"""
        
        # Rule 2.1: Unencrypted connections to databases
        db_connections = [c for c in connections if self._is_db_connection(c, nodes)]
        
        for conn in db_connections:
            if not self._is_connection_encrypted(conn):
                self.findings.append(SecurityFinding(
                    rule_id="OWASP-A02-001",
                    title="Unencrypted Database Connection",
                    description=f"Connection {conn.get('id')} transmits data to database without encryption. Sensitive data may be intercepted.",
                    severity=Severity.CRITICAL,
                    owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                    affected_components=[conn.get('source'), conn.get('target')],
                    cvss_score=9.4,
                    cwe_id="CWE-319",
                    mitigation="Enable TLS/SSL for database connections. Use encrypted protocols (e.g., PostgreSQL SSL, MySQL over SSL).",
                    confidence="high"
                ))
        
        # Rule 2.2: HTTP instead of HTTPS
        http_connections = [c for c in connections if self._uses_http_protocol(c)]
        
        if http_connections:
            affected = list(set([c.get('source') for c in http_connections] + [c.get('target') for c in http_connections]))
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A02-002",
                title="HTTP Protocol Usage (Unencrypted)",
                description=f"Found {len(http_connections)} connection(s) using HTTP instead of HTTPS. Data transmitted in plaintext.",
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                affected_components=affected,
                cvss_score=7.5,
                cwe_id="CWE-319",
                mitigation="Enforce HTTPS for all web traffic. Redirect HTTP to HTTPS. Implement HSTS headers.",
                confidence="high"
            ))
        
        # Rule 2.3: Missing encryption service
        encryption_components = [n for n in nodes if self._is_encryption_component(n)]
        
        if not encryption_components and len(nodes) > 5:
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A02-003",
                title="No Encryption Gateway or KMS",
                description="No encryption gateway or Key Management Service detected. Secrets and sensitive data may be stored in plaintext.",
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                affected_components=["architecture"],
                cvss_score=7.2,
                cwe_id="CWE-311",
                mitigation="Implement Key Management Service (AWS KMS, Azure Key Vault, HashiCorp Vault). Encrypt data at rest and in transit.",
                confidence="medium"
            ))
    
    def _check_injection_vulnerabilities(self, nodes: List[Dict], connections: List[Dict]):
        """A03: Injection - SQL, NoSQL, Command injection"""
        
        # Rule 3.1: Database without WAF or input validation
        databases = [n for n in nodes if self._is_database(n)]
        waf_components = [n for n in nodes if self._is_waf(n)]
        
        if databases and not waf_components:
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A03-001",
                title="Database Exposed Without WAF Protection",
                description="Database components without Web Application Firewall are vulnerable to SQL/NoSQL injection attacks.",
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.A03_INJECTION,
                affected_components=[db.get('id') for db in databases],
                cvss_score=9.8,
                cwe_id="CWE-89",
                mitigation="Deploy WAF with injection attack rules. Use parameterized queries. Implement input validation at application layer.",
                confidence="high"
            ))
        
        # Rule 3.2: API endpoints without validation layer
        api_servers = [n for n in nodes if self._is_api_server(n)]
        validation_services = [n for n in nodes if self._is_validation_service(n)]
        
        if api_servers and not validation_services and not waf_components:
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A03-002",
                title="API Services Without Input Validation",
                description="API endpoints lack dedicated input validation or WAF protection, making them vulnerable to injection attacks.",
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A03_INJECTION,
                affected_components=[api.get('id') for api in api_servers],
                cvss_score=8.6,
                cwe_id="CWE-20",
                mitigation="Implement API Gateway with request validation. Add JSON schema validation. Deploy WAF with OWASP Core Rule Set.",
                confidence="high"
            ))
    
    def _check_insecure_design(self, nodes: List[Dict], connections: List[Dict], metadata: Dict):
        """A04: Insecure Design - architectural flaws"""
        
        # Rule 4.1: No network segmentation
        network_zones = self._detect_network_zones(nodes, connections)
        
        if len(network_zones) <= 1 and len(nodes) > 5:
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A04-001",
                title="Flat Network Architecture - No Segmentation",
                description="All components appear to be in same network zone. No network segmentation detected. Single breach compromises entire system.",
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                affected_components=["architecture"],
                cvss_score=7.8,
                cwe_id="CWE-1008",
                mitigation="Implement network segmentation: DMZ for web servers, private subnet for application tier, isolated subnet for databases. Use security groups and NACLs.",
                confidence="medium"
            ))
        
        # Rule 4.2: Missing redundancy for critical components
        databases = [n for n in nodes if self._is_database(n)]
        
        if len(databases) == 1:
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A04-002",
                title="Single Point of Failure - No Database Redundancy",
                description="Only one database instance detected. No replication or backup strategy evident. Vulnerable to availability attacks.",
                severity=Severity.MEDIUM,
                owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                affected_components=[databases[0].get('id')],
                cvss_score=5.5,
                cwe_id="CWE-1026",
                mitigation="Implement database replication (master-slave or multi-master). Add automated backup system. Consider database clustering.",
                confidence="high"
            ))
        
        # Rule 4.3: Internet-facing admin interfaces
        admin_components = [n for n in nodes if self._is_admin_interface(n)]
        firewalls = [n for n in nodes if self._is_firewall(n)]
        
        if admin_components and not firewalls:
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A04-003",
                title="Admin Interfaces Without Firewall Protection",
                description="Administrative interfaces exposed without firewall protection. Should be accessible only via VPN or bastion host.",
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.A04_INSECURE_DESIGN,
                affected_components=[a.get('id') for a in admin_components],
                cvss_score=9.1,
                cwe_id="CWE-1188",
                mitigation="Place admin interfaces behind firewall. Require VPN access. Implement IP whitelisting. Use bastion host architecture.",
                confidence="high"
            ))
    
    def _check_security_misconfiguration(self, nodes: List[Dict], metadata: Dict):
        """A05: Security Misconfiguration"""
        
        # Rule 5.1: Default security level
        security_level = metadata.get('security_level', 'low')
        
        if security_level in ['low', 'basic']:
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A05-001",
                title="Low Security Configuration Level",
                description=f"Architecture configured with '{security_level}' security level. Production systems require 'high' or 'hardened' security posture.",
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                affected_components=["architecture"],
                cvss_score=7.5,
                cwe_id="CWE-16",
                mitigation="Upgrade security level to 'high'. Enable security hardening. Review and update all default configurations.",
                confidence="high"
            ))
        
        # Rule 5.2: Exposed internal services
        internal_services = [n for n in nodes if self._is_internal_service(n)]
        dmz_components = [n for n in nodes if self._is_dmz_component(n)]
        
        if internal_services and not dmz_components:
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A05-002",
                title="Internal Services Without DMZ Isolation",
                description="Internal services are not isolated in DMZ. May be directly accessible from internet.",
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                affected_components=[s.get('id') for s in internal_services],
                cvss_score=8.1,
                cwe_id="CWE-668",
                mitigation="Create DMZ zone. Place public-facing services in DMZ. Use reverse proxy to protect internal services.",
                confidence="medium"
            ))
    
    def _check_vulnerable_components(self, nodes: List[Dict]):
        """A06: Vulnerable and Outdated Components"""
        
        # Rule 6.1: Legacy components
        legacy_keywords = ['legacy', 'old', 'deprecated', 'v1', 'classic']
        
        for node in nodes:
            node_name = node.get('name', '').lower()
            node_type = node.get('properties', {}).get('component_type', '').lower()
            
            if any(keyword in node_name or keyword in node_type for keyword in legacy_keywords):
                self.findings.append(SecurityFinding(
                    rule_id="OWASP-A06-001",
                    title=f"Legacy Component Detected: {node.get('name')}",
                    description="Legacy or deprecated component may contain unpatched vulnerabilities. Should be upgraded or replaced.",
                    severity=Severity.HIGH,
                    owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                    affected_components=[node.get('id')],
                    cvss_score=7.3,
                    cwe_id="CWE-1104",
                    mitigation="Upgrade to latest stable version. If upgrade not possible, implement compensating controls (WAF rules, network isolation).",
                    confidence="medium"
                ))
        
        # Rule 6.2: Missing patch management system
        patch_management = [n for n in nodes if 'patch' in n.get('name', '').lower() or 'update' in n.get('name', '').lower()]
        
        if not patch_management and len(nodes) > 5:
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A06-002",
                title="No Patch Management System",
                description="No automated patch management or update system detected. Components may run with known vulnerabilities.",
                severity=Severity.MEDIUM,
                owasp_category=OWASPCategory.A06_VULNERABLE_COMPONENTS,
                affected_components=["architecture"],
                cvss_score=6.5,
                cwe_id="CWE-1357",
                mitigation="Implement automated patch management (AWS Systems Manager, Ansible, WSUS). Schedule regular security updates.",
                confidence="low"
            ))
    
    def _check_authentication_failures(self, nodes: List[Dict], connections: List[Dict]):
        """A07: Identification and Authentication Failures"""
        
        # Rule 7.1: Missing MFA
        auth_services = [n for n in nodes if self._is_auth_component(n)]
        mfa_components = [n for n in nodes if self._is_mfa_component(n)]
        
        if auth_services and not mfa_components:
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A07-001",
                title="Authentication Without Multi-Factor Authentication (MFA)",
                description="Authentication service detected but no MFA implementation found. Accounts vulnerable to credential compromise.",
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                affected_components=[a.get('id') for a in auth_services],
                cvss_score=7.5,
                cwe_id="CWE-308",
                mitigation="Implement MFA (TOTP, SMS, hardware tokens). Require MFA for administrative accounts. Support FIDO2/WebAuthn.",
                confidence="high"
            ))
        
        # Rule 7.2: No rate limiting or anti-brute force
        api_gateways = [n for n in nodes if self._is_api_gateway(n)]
        rate_limiters = [n for n in nodes if self._is_rate_limiter(n)]
        
        if (api_gateways or auth_services) and not rate_limiters:
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A07-002",
                title="No Rate Limiting - Brute Force Attack Risk",
                description="No rate limiting service detected. Authentication endpoints vulnerable to brute force and credential stuffing attacks.",
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                affected_components=["architecture"],
                cvss_score=7.4,
                cwe_id="CWE-307",
                mitigation="Implement rate limiting (API Gateway throttling, Redis-based rate limiter). Add CAPTCHA after failed attempts. Implement account lockout policy.",
                confidence="high"
            ))
    
    def _check_data_integrity_failures(self, nodes: List[Dict], connections: List[Dict]):
        """A08: Software and Data Integrity Failures"""
        
        # Rule 8.1: Missing code signing / artifact verification
        ci_cd_components = [n for n in nodes if self._is_cicd_component(n)]
        signing_services = [n for n in nodes if self._is_signing_service(n)]
        
        if ci_cd_components and not signing_services:
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A08-001",
                title="CI/CD Pipeline Without Code Signing",
                description="CI/CD pipeline detected but no code signing or artifact verification. Vulnerable to supply chain attacks.",
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A08_DATA_INTEGRITY_FAILURES,
                affected_components=[c.get('id') for c in ci_cd_components],
                cvss_score=8.1,
                cwe_id="CWE-345",
                mitigation="Implement code signing for all artifacts. Use Sigstore/cosign for containers. Verify signatures before deployment.",
                confidence="medium"
            ))
        
        # Rule 8.2: No backup or integrity checking
        databases = [n for n in nodes if self._is_database(n)]
        backup_systems = [n for n in nodes if self._is_backup_system(n)]
        
        if databases and not backup_systems:
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A08-002",
                title="No Backup System for Data Integrity",
                description="Database(s) present but no backup system detected. Cannot recover from data corruption or ransomware.",
                severity=Severity.MEDIUM,
                owasp_category=OWASPCategory.A08_DATA_INTEGRITY_FAILURES,
                affected_components=[db.get('id') for db in databases],
                cvss_score=6.5,
                cwe_id="CWE-494",
                mitigation="Implement automated backup system. Use immutable backups (S3 Object Lock). Test restore procedures regularly.",
                confidence="high"
            ))
    
    def _check_logging_failures(self, nodes: List[Dict]):
        """A09: Security Logging and Monitoring Failures"""
        
        # Rule 9.1: Missing SIEM or centralized logging
        logging_components = [n for n in nodes if self._is_logging_component(n)]
        siem_components = [n for n in nodes if self._is_siem_component(n)]
        
        if not logging_components and not siem_components:
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A09-001",
                title="No Security Logging or SIEM",
                description="No centralized logging, monitoring, or SIEM detected. Cannot detect or respond to security incidents.",
                severity=Severity.CRITICAL,
                owasp_category=OWASPCategory.A09_LOGGING_FAILURES,
                affected_components=["architecture"],
                cvss_score=9.0,
                cwe_id="CWE-778",
                mitigation="Implement SIEM (Splunk, ELK Stack, Azure Sentinel). Centralize logs from all components. Set up security alerts.",
                confidence="high"
            ))
        
        # Rule 9.2: No intrusion detection
        ids_ips_components = [n for n in nodes if self._is_ids_ips(n)]
        
        if not ids_ips_components:
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A09-002",
                title="No Intrusion Detection System (IDS/IPS)",
                description="No IDS/IPS detected. Cannot detect or prevent active attacks in real-time.",
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A09_LOGGING_FAILURES,
                affected_components=["architecture"],
                cvss_score=7.5,
                cwe_id="CWE-778",
                mitigation="Deploy IDS/IPS (Snort, Suricata, AWS GuardDuty). Configure threat detection rules. Enable automated response.",
                confidence="high"
            ))
    
    def _check_ssrf_vulnerabilities(self, nodes: List[Dict], connections: List[Dict]):
        """A10: Server-Side Request Forgery"""
        
        # Rule 10.1: External API access without proxy
        external_api_calls = [c for c in connections if self._is_external_connection(c, nodes)]
        proxy_components = [n for n in nodes if self._is_proxy(n)]
        
        if external_api_calls and not proxy_components:
            self.findings.append(SecurityFinding(
                rule_id="OWASP-A10-001",
                title="External API Calls Without Proxy",
                description="Application makes external API calls without proxy. Vulnerable to SSRF attacks that could access internal resources.",
                severity=Severity.HIGH,
                owasp_category=OWASPCategory.A10_SSRF,
                affected_components=[c.get('source') for c in external_api_calls],
                cvss_score=8.5,
                cwe_id="CWE-918",
                mitigation="Implement forward proxy. Whitelist allowed external domains. Validate and sanitize all user-supplied URLs.",
                confidence="medium"
            ))
    
    # ==================== Helper Methods ====================
    
    def _is_auth_component(self, node: Dict) -> bool:
        """Check if node is authentication component"""
        keywords = ['auth', 'identity', 'oauth', 'oidc', 'saml', 'sso', 'iam', 'cognito', 'ad', 'ldap']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_database(self, node: Dict) -> bool:
        keywords = ['database', 'db', 'postgres', 'mysql', 'mongo', 'redis', 'dynamodb', 'sql', 'nosql']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_api_gateway(self, node: Dict) -> bool:
        keywords = ['api_gateway', 'api gateway', 'apigw', 'kong', 'nginx']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_web_server(self, node: Dict) -> bool:
        keywords = ['web_server', 'web server', 'apache', 'nginx', 'iis', 'tomcat']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_load_balancer(self, node: Dict) -> bool:
        keywords = ['load_balancer', 'load balancer', 'alb', 'elb', 'nlb', 'haproxy']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_waf(self, node: Dict) -> bool:
        keywords = ['waf', 'web application firewall', 'modsecurity', 'cloudflare']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_firewall(self, node: Dict) -> bool:
        keywords = ['firewall', 'fw', 'security_group', 'nacl', 'palo alto']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_ids_ips(self, node: Dict) -> bool:
        keywords = ['ids', 'ips', 'intrusion', 'snort', 'suricata', 'guardduty']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_siem_component(self, node: Dict) -> bool:
        keywords = ['siem', 'splunk', 'elk', 'sentinel', 'qradar', 'security_monitoring']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_logging_component(self, node: Dict) -> bool:
        keywords = ['log', 'logging', 'cloudwatch', 'stackdriver', 'datadog']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_encryption_component(self, node: Dict) -> bool:
        keywords = ['encryption', 'kms', 'vault', 'hsm', 'key management']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_mfa_component(self, node: Dict) -> bool:
        keywords = ['mfa', 'multi-factor', '2fa', 'totp', 'authenticator']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_backup_system(self, node: Dict) -> bool:
        keywords = ['backup', 'snapshot', 'recovery', 'disaster recovery', 'dr']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_proxy(self, node: Dict) -> bool:
        keywords = ['proxy', 'forward_proxy', 'reverse_proxy', 'squid']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_api_server(self, node: Dict) -> bool:
        keywords = ['api', 'rest', 'graphql', 'microservice']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_validation_service(self, node: Dict) -> bool:
        keywords = ['validation', 'validator', 'input_validation']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_admin_interface(self, node: Dict) -> bool:
        keywords = ['admin', 'management', 'console', 'dashboard']
        name = node.get('name', '').lower()
        return any(kw in name for kw in keywords)
    
    def _is_internal_service(self, node: Dict) -> bool:
        keywords = ['internal', 'private', 'backend']
        name = node.get('name', '').lower()
        return any(kw in name for kw in keywords)
    
    def _is_dmz_component(self, node: Dict) -> bool:
        keywords = ['dmz', 'public_subnet', 'edge']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_cicd_component(self, node: Dict) -> bool:
        keywords = ['ci', 'cd', 'jenkins', 'gitlab', 'github actions', 'pipeline']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_signing_service(self, node: Dict) -> bool:
        keywords = ['signing', 'sigstore', 'cosign', 'notary']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_rate_limiter(self, node: Dict) -> bool:
        keywords = ['rate_limit', 'throttle', 'rate limiter']
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        return any(kw in name or kw in comp_type for kw in keywords)
    
    def _is_db_connection(self, conn: Dict, nodes: List[Dict]) -> bool:
        """Check if connection is to a database"""
        target_id = conn.get('target')
        target_node = next((n for n in nodes if n.get('id') == target_id), None)
        return target_node and self._is_database(target_node)
    
    def _is_connection_encrypted(self, conn: Dict) -> bool:
        """Check if connection uses encryption"""
        props = conn.get('properties', {})
        encrypted = props.get('encrypted', False)
        protocol = props.get('protocol', '').lower()
        conn_type = conn.get('type', '').lower()
        
        secure_protocols = ['https', 'tls', 'ssl', 'ssh', 'vpn', 'ipsec']
        
        return encrypted or any(sp in protocol or sp in conn_type for sp in secure_protocols)
    
    def _uses_http_protocol(self, conn: Dict) -> bool:
        """Check if connection uses HTTP (not HTTPS)"""
        props = conn.get('properties', {})
        protocol = props.get('protocol', '').lower()
        
        return protocol == 'http'
    
    def _is_external_connection(self, conn: Dict, nodes: List[Dict]) -> bool:
        """Check if connection goes to external/internet"""
        target_id = conn.get('target')
        target_node = next((n for n in nodes if n.get('id') == target_id), None)
        
        if not target_node:
            return False
        
        external_keywords = ['external', 'internet', 'public', 'third-party', 'api']
        name = target_node.get('name', '').lower()
        
        return any(kw in name for kw in external_keywords)
    
    def _detect_network_zones(self, nodes: List[Dict], connections: List[Dict]) -> Set[str]:
        """Detect distinct network zones in architecture"""
        zones = set()
        
        for node in nodes:
            props = node.get('properties', {})
            tier = props.get('tier', 'unknown')
            zone = props.get('zone', tier)
            zones.add(zone)
        
        return zones
