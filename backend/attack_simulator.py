"""
Rule-Based Attack Simulator
Determines if specific attacks can succeed based on architecture analysis
Uses OWASP, STRIDE, and MITRE rules to validate attack feasibility
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from typing import Dict, Any, List, Tuple
from dataclasses import dataclass
from security_scanner import RuleBasedSecurityScanner

@dataclass
class AttackValidationResult:
    """Comprehensive result of attack validation with extended attributes"""
    attack_id: str
    attack_name: str
    is_possible: bool
    confidence: float  # 0.0 to 1.0
    reasons: List[str]
    vulnerable_components: List[str]
    attack_path: List[str]
    required_vulnerabilities: List[str]
    found_vulnerabilities: List[str]
    severity: str  # CRITICAL/HIGH/MEDIUM/LOW
    # Extended validation attributes
    likelihood: str = "MEDIUM"  # HIGH, MEDIUM, LOW
    impact: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW
    risk_score: float = 5.0  # 0-10 scale
    exploitability: str = "MEDIUM"  # HIGH, MEDIUM, LOW
    attack_complexity: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    required_privileges: str = "NONE"  # NONE, USER, ADMIN
    user_interaction_required: bool = False
    # Blocking and detection
    blocking_controls: List[str] = None  # Controls that would block this
    missing_controls: List[str] = None  # Controls that are missing
    detection_methods: List[str] = None  # How to detect this attack
    detection_difficulty: str = "MEDIUM"  # EASY, MEDIUM, HARD
    # Mitigation
    recommended_controls: List[str] = None  # What to add to block
    mitigation_priority: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW
    remediation_effort: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    estimated_cost: str = "$10K-$50K"
    # Framework mappings
    mitre_techniques: List[str] = None  # MITRE ATT&CK IDs
    owasp_categories: List[str] = None  # OWASP Top 10 categories
    stride_threats: List[str] = None  # STRIDE categories
    cwe_ids: List[str] = None  # Related CWE IDs
    # Business impact
    business_impact: str = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW
    data_at_risk: List[str] = None  # Types of data at risk
    affected_services: List[str] = None  # Services that would be affected
    downtime_estimate: str = "Minutes to Hours"
    financial_impact: str = "$50K-$500K"
    reputational_damage: str = "HIGH"  # HIGH, MEDIUM, LOW
    compliance_violations: List[str] = None  # Violated compliance standards
    # Threat intelligence
    known_exploits: bool = False
    exploit_availability: str = "PUBLIC"  # PRIVATE, PUBLIC, NONE
    actively_exploited: bool = False
    attack_frequency: str = "COMMON"  # RARE, UNCOMMON, COMMON, VERY_COMMON
    threat_actors: List[str] = None  # Known threat groups using this
    # Evidence and indicators
    attack_indicators: List[str] = None  # IoCs
    log_signatures: List[str] = None  # What to look for in logs
    network_signatures: List[str] = None  # Network traffic patterns
    
    def __post_init__(self):
        """Initialize list fields if None"""
        if self.blocking_controls is None:
            self.blocking_controls = []
        if self.missing_controls is None:
            self.missing_controls = []
        if self.detection_methods is None:
            self.detection_methods = []
        if self.recommended_controls is None:
            self.recommended_controls = []
        if self.mitre_techniques is None:
            self.mitre_techniques = []
        if self.owasp_categories is None:
            self.owasp_categories = []
        if self.stride_threats is None:
            self.stride_threats = []
        if self.cwe_ids is None:
            self.cwe_ids = []
        if self.data_at_risk is None:
            self.data_at_risk = []
        if self.affected_services is None:
            self.affected_services = []
        if self.compliance_violations is None:
            self.compliance_violations = []
        if self.threat_actors is None:
            self.threat_actors = []
        if self.attack_indicators is None:
            self.attack_indicators = []
        if self.log_signatures is None:
            self.log_signatures = []
        if self.network_signatures is None:
            self.network_signatures = []

class RuleBasedAttackSimulator:
    """
    Simulates attacks using rule-based vulnerability analysis
    Maps attack types to OWASP/STRIDE/MITRE findings
    """
    
    def __init__(self):
        self.scanner = RuleBasedSecurityScanner()
        
        # Attack catalog with required vulnerability mappings
        self.attack_catalog = {
            "SQL Injection": {
                "required_owasp": ["A03"],  # Injection
                "required_components": ["database"],
                "blocked_by": ["waf", "input_validation"],
                "mitre_technique": "T1190",
                "severity_base": "CRITICAL"
            },
            "Cross-Site Scripting (XSS)": {
                "required_owasp": ["A03"],  # Injection
                "required_components": ["web_server", "application"],
                "blocked_by": ["waf", "content_security_policy"],
                "mitre_technique": "T1203",
                "severity_base": "HIGH"
            },
            "DDoS Attack": {
                "required_owasp": ["A04"],  # Insecure Design
                "required_components": ["web_server", "api"],
                "blocked_by": ["load_balancer", "rate_limiter", "cdn", "ddos_protection"],
                "mitre_technique": "T1498",
                "severity_base": "HIGH"
            },
            "Man-in-the-Middle (MITM)": {
                "required_owasp": ["A02"],  # Cryptographic Failures
                "requires_unencrypted": True,
                "blocked_by": ["tls", "encryption", "vpn"],
                "mitre_technique": "T1557",
                "severity_base": "CRITICAL"
            },
            "Brute Force Attack": {
                "required_owasp": ["A07"],  # Authentication Failures
                "required_components": ["authentication", "login"],
                "blocked_by": ["rate_limiter", "mfa", "account_lockout", "captcha"],
                "mitre_technique": "T1110",
                "severity_base": "HIGH"
            },
            "Zero-Day Exploit": {
                "required_owasp": ["A06"],  # Vulnerable Components
                "required_components": ["application", "web_server"],
                "blocked_by": ["waf", "ids_ips", "patch_management"],
                "mitre_technique": "T1068",
                "severity_base": "CRITICAL"
            },
            "Ransomware": {
                "required_owasp": ["A08"],  # Data Integrity Failures
                "required_components": ["database", "file_storage"],
                "blocked_by": ["backup_system", "immutable_backup", "edr", "antivirus"],
                "mitre_technique": "T1486",
                "severity_base": "CRITICAL"
            },
            "Phishing": {
                "required_owasp": ["A07"],  # Authentication Failures
                "required_components": ["email", "authentication"],
                "blocked_by": ["mfa", "email_security", "user_training"],
                "mitre_technique": "T1078",
                "severity_base": "HIGH"
            },
            "Privilege Escalation": {
                "required_owasp": ["A01"],  # Broken Access Control
                "required_components": ["authentication", "authorization"],
                "blocked_by": ["rbac", "least_privilege", "pam"],
                "mitre_technique": "T1068",
                "severity_base": "CRITICAL"
            },
            "Data Exfiltration": {
                "required_owasp": ["A09"],  # Logging Failures
                "required_components": ["database", "storage"],
                "blocked_by": ["dlp", "egress_filtering", "siem", "network_monitoring"],
                "mitre_technique": "T1041",
                "severity_base": "CRITICAL"
            },
            "API Abuse": {
                "required_owasp": ["A01", "A05"],  # Access Control + Misconfiguration
                "required_components": ["api", "api_gateway"],
                "blocked_by": ["api_gateway", "rate_limiter", "oauth", "api_key_management"],
                "mitre_technique": "T1190",
                "severity_base": "HIGH"
            },
            "Container Escape": {
                "required_owasp": ["A04"],  # Insecure Design
                "required_components": ["container", "docker", "kubernetes"],
                "blocked_by": ["security_context", "pod_security", "runtime_security"],
                "mitre_technique": "T1611",
                "severity_base": "CRITICAL"
            },
            "Supply Chain Attack": {
                "required_owasp": ["A08"],  # Data Integrity Failures
                "required_components": ["ci_cd", "build_pipeline"],
                "blocked_by": ["code_signing", "sbom", "supply_chain_security"],
                "mitre_technique": "T1195",
                "severity_base": "CRITICAL"
            },
            "Insider Threat": {
                "required_owasp": ["A09"],  # Logging Failures
                "required_components": ["internal_network"],
                "blocked_by": ["ueba", "dlp", "privileged_access_management", "monitoring"],
                "mitre_technique": "T1078",
                "severity_base": "HIGH"
            },
            "Cloud Misconfiguration": {
                "required_owasp": ["A05"],  # Security Misconfiguration
                "required_components": ["cloud", "s3", "storage"],
                "blocked_by": ["cspm", "policy_as_code", "security_groups"],
                "mitre_technique": "T1530",
                "severity_base": "CRITICAL"
            },
            "IoT Device Compromise": {
                "required_owasp": ["A05", "A06"],  # Misconfiguration + Vulnerable Components
                "required_components": ["iot", "device"],
                "blocked_by": ["network_segmentation", "iot_security", "firmware_updates"],
                "mitre_technique": "T1200",
                "severity_base": "HIGH"
            },
            "Credential Stuffing": {
                "required_owasp": ["A07"],  # Authentication Failures
                "required_components": ["authentication", "login"],
                "blocked_by": ["mfa", "rate_limiter", "credential_monitoring", "captcha"],
                "mitre_technique": "T1110.004",
                "severity_base": "HIGH"
            },
            "DNS Spoofing": {
                "required_owasp": ["A02"],  # Cryptographic Failures
                "required_components": ["dns", "network"],
                "blocked_by": ["dnssec", "dns_filtering", "secure_dns"],
                "mitre_technique": "T1590.002",
                "severity_base": "MEDIUM"
            },
            "Session Hijacking": {
                "required_owasp": ["A02", "A07"],  # Crypto Failures + Auth Failures
                "required_components": ["web_server", "session_management"],
                "blocked_by": ["secure_cookies", "tls", "session_timeout"],
                "mitre_technique": "T1539",
                "severity_base": "HIGH"
            },
            "Cryptojacking": {
                "required_owasp": ["A04"],  # Insecure Design
                "required_components": ["compute", "server"],
                "blocked_by": ["resource_monitoring", "edr", "network_segmentation"],
                "mitre_technique": "T1496",
                "severity_base": "MEDIUM"
            }
        }
    
    def validate_attack(self, attack_name: str, architecture: Dict[str, Any]) -> AttackValidationResult:
        """
        Validate if a specific attack can succeed on the architecture
        Returns detailed validation result with reasoning
        """
        
        # Get attack definition
        attack_def = self.attack_catalog.get(attack_name)
        if not attack_def:
            # Unknown attack - assume possible for safety
            return AttackValidationResult(
                attack_id=attack_name.replace(" ", "_").lower(),
                attack_name=attack_name,
                is_possible=True,
                confidence=0.5,
                reasons=["Unknown attack type - cannot validate"],
                vulnerable_components=["unknown"],
                attack_path=["Unknown attack vector"],
                required_vulnerabilities=[],
                found_vulnerabilities=[],
                severity="MEDIUM"
            )
        
        # Analyze architecture
        assessment = self.scanner.scan_architecture(architecture)
        
        nodes = architecture.get('nodes', [])
        connections = architecture.get('connections', [])
        
        # Check if attack is possible
        is_possible, confidence, reasons, vulnerabilities, attack_path = self._evaluate_attack_feasibility(
            attack_name, attack_def, nodes, connections, assessment
        )
        
        # Identify vulnerable components
        vulnerable_components = self._identify_vulnerable_components(
            attack_def, nodes, connections
        )
        
        return AttackValidationResult(
            attack_id=attack_name.replace(" ", "_").lower(),
            attack_name=attack_name,
            is_possible=is_possible,
            confidence=confidence,
            reasons=reasons,
            vulnerable_components=vulnerable_components,
            attack_path=attack_path,
            required_vulnerabilities=attack_def.get("required_owasp", []),
            found_vulnerabilities=vulnerabilities,
            severity=attack_def.get("severity_base", "MEDIUM")
        )
    
    def _evaluate_attack_feasibility(self, 
                                    attack_name: str,
                                    attack_def: Dict,
                                    nodes: List[Dict],
                                    connections: List[Dict],
                                    assessment) -> Tuple[bool, float, List[str], List[str], List[str]]:
        """
        Evaluate if attack is feasible based on rules
        Returns: (is_possible, confidence, reasons, vulnerabilities_found, attack_path)
        """
        
        reasons = []
        vulnerabilities_found = []
        attack_path = []
        confidence = 0.0
        
        # Check 1: Required components present?
        required_components = attack_def.get("required_components", [])
        components_present = []
        
        for req_comp in required_components:
            matching = [n for n in nodes if self._component_matches(n, req_comp)]
            if matching:
                components_present.append(req_comp)
                reasons.append(f"✓ Target component found: {req_comp}")
                attack_path.append(f"Target: {matching[0].get('name', req_comp)}")
        
        if required_components and not components_present:
            return False, 0.0, ["✗ Required target components not found in architecture"], [], []
        
        confidence += 0.3  # Components present
        
        # Check 2: Required OWASP vulnerabilities present?
        required_owasp = attack_def.get("required_owasp", [])
        owasp_found = []
        
        for finding in assessment.owasp_findings:
            owasp_id = finding.owasp_category.value.split(":")[0]  # Extract "A01" from "A01:2021 - ..."
            if owasp_id in required_owasp:
                owasp_found.append(owasp_id)
                vulnerabilities_found.append(finding.rule_id)
                reasons.append(f"✓ Vulnerability: {finding.title}")
                attack_path.append(f"Exploit: {finding.title}")
        
        if required_owasp and owasp_found:
            confidence += 0.4  # Required vulnerabilities present
        elif required_owasp and not owasp_found:
            reasons.append(f"✗ Required OWASP vulnerabilities ({', '.join(required_owasp)}) not found")
            return False, 0.3, reasons, [], attack_path
        
        # Check 3: Special conditions
        if attack_def.get("requires_unencrypted", False):
            unencrypted_conns = [c for c in connections 
                               if not c.get('properties', {}).get('encrypted', False)]
            if unencrypted_conns:
                confidence += 0.2
                reasons.append(f"✓ Unencrypted connections found: {len(unencrypted_conns)}")
                attack_path.append("Intercept unencrypted traffic")
            else:
                reasons.append("✗ All connections encrypted - attack blocked")
                return False, 0.3, reasons, vulnerabilities_found, attack_path
        
        # Check 4: Blocking controls present?
        blocking_controls = attack_def.get("blocked_by", [])
        controls_present = []
        
        for control in blocking_controls:
            matching = [n for n in nodes if self._component_matches(n, control)]
            if matching:
                controls_present.append(control)
                reasons.append(f"✗ Blocking control found: {matching[0].get('name', control)}")
                attack_path.append(f"Blocked by: {matching[0].get('name', control)}")
        
        if controls_present:
            # Controls present - attack may be blocked
            confidence *= 0.5  # Reduce confidence by half
            if len(controls_present) >= len(blocking_controls) * 0.7:
                # Most controls present - attack very difficult
                reasons.append(f"⚠️ {len(controls_present)}/{len(blocking_controls)} security controls present")
                return False, confidence, reasons, vulnerabilities_found, attack_path
            else:
                reasons.append(f"⚠️ Only {len(controls_present)}/{len(blocking_controls)} controls present - attack still possible")
        else:
            # No blocking controls - attack highly likely
            confidence += 0.3
            reasons.append(f"✓ No blocking controls ({', '.join(blocking_controls)}) present")
            attack_path.append("No security controls blocking attack")
        
        # Final determination
        is_possible = confidence >= 0.5
        
        if is_possible:
            attack_path.append(f"Attack success probability: {confidence*100:.1f}%")
        
        return is_possible, confidence, reasons, vulnerabilities_found, attack_path
    
    def _component_matches(self, node: Dict, component_keyword: str) -> bool:
        """Check if node matches component keyword"""
        name = node.get('name', '').lower()
        comp_type = node.get('properties', {}).get('component_type', '').lower()
        node_type = node.get('type', '').lower()
        
        keyword = component_keyword.lower()
        
        return (keyword in name or 
                keyword in comp_type or 
                keyword in node_type or
                self._fuzzy_match(keyword, name) or
                self._fuzzy_match(keyword, comp_type))
    
    def _fuzzy_match(self, keyword: str, text: str) -> bool:
        """Fuzzy matching for component detection"""
        mappings = {
            'database': ['db', 'postgres', 'mysql', 'mongo', 'redis', 'sql'],
            'waf': ['web_application_firewall', 'cloudflare', 'aws_waf'],
            'load_balancer': ['lb', 'alb', 'elb', 'nlb', 'haproxy'],
            'authentication': ['auth', 'identity', 'oauth', 'oidc', 'saml', 'sso'],
            'mfa': ['multi_factor', '2fa', 'totp', 'authenticator'],
            'rate_limiter': ['throttle', 'rate_limit'],
            'api': ['rest', 'graphql', 'api_gateway'],
            'web_server': ['apache', 'nginx', 'iis', 'tomcat'],
            'ids_ips': ['intrusion', 'snort', 'suricata'],
            'siem': ['splunk', 'elk', 'sentinel', 'security_monitoring'],
            'backup_system': ['backup', 'snapshot', 'recovery'],
            'dlp': ['data_loss_prevention', 'data_protection'],
            'container': ['docker', 'pod', 'kubernetes', 'k8s'],
            'cloud': ['aws', 'azure', 'gcp', 's3', 'blob'],
            'encryption': ['kms', 'vault', 'hsm', 'key_management']
        }
        
        synonyms = mappings.get(keyword, [])
        return any(syn in text for syn in synonyms)
    
    def _identify_vulnerable_components(self,
                                       attack_def: Dict,
                                       nodes: List[Dict],
                                       connections: List[Dict]) -> List[str]:
        """Identify which specific components are vulnerable"""
        vulnerable = []
        
        required_components = attack_def.get("required_components", [])
        
        for req_comp in required_components:
            matching = [n for n in nodes if self._component_matches(n, req_comp)]
            for node in matching:
                vulnerable.append(node.get('id', node.get('name', 'unknown')))
        
        # Also check unencrypted connections if required
        if attack_def.get("requires_unencrypted", False):
            for conn in connections:
                if not conn.get('properties', {}).get('encrypted', False):
                    vulnerable.append(conn.get('id', f"connection_{conn.get('source')}_{conn.get('target')}"))
        
        return list(set(vulnerable))  # Remove duplicates

# Export for use in API
__all__ = ['RuleBasedAttackSimulator', 'AttackValidationResult']
