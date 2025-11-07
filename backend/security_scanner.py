"""
Rule-Based Security Scanner
Main orchestrator that applies OWASP, STRIDE, and MITRE ATT&CK rules
Provides comprehensive security assessment without LLM dependency
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from typing import List, Dict, Any, Tuple
from dataclasses import dataclass, asdict
import json

from owasp_rules import OWASPRuleEngine, SecurityFinding, Severity, OWASPCategory
from stride_rules import STRIDEThreatEngine, Threat, ThreatCategory
from mitre_attack_mapper import MITREAttackMapper, AttackTechnique, AttackTactic

@dataclass
class RiskScore:
    """Overall risk assessment"""
    total_score: float  # 0-100
    risk_level: str  # CRITICAL/HIGH/MEDIUM/LOW
    severity_breakdown: Dict[str, int]
    owasp_violations: int
    stride_threats: int
    mitre_techniques: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int

@dataclass
class SecurityAssessment:
    """Complete security assessment result"""
    architecture_id: str
    timestamp: str
    risk_score: RiskScore
    owasp_findings: List[SecurityFinding]
    stride_threats: List[Threat]
    mitre_techniques: List[AttackTechnique]
    recommendations: List[Dict[str, Any]]
    compliance_status: Dict[str, Any]

class RuleBasedSecurityScanner:
    """
    Main security scanner using rule-based analysis
    NO LLM dependency - uses predefined security rules and algorithms
    """
    
    def __init__(self):
        self.owasp_engine = OWASPRuleEngine()
        self.stride_engine = STRIDEThreatEngine()
        self.mitre_mapper = MITREAttackMapper()
    
    def scan_architecture(self, architecture: Dict[str, Any]) -> SecurityAssessment:
        """
        Perform complete security scan using all rule engines
        """
        from datetime import datetime
        
        # Run all engines
        owasp_findings = self.owasp_engine.analyze_architecture(architecture)
        stride_threats = self.stride_engine.analyze_architecture(architecture)
        mitre_techniques = self.mitre_mapper.analyze_architecture(architecture)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(owasp_findings, stride_threats, mitre_techniques)
        
        # Generate prioritized recommendations
        recommendations = self._generate_recommendations(owasp_findings, stride_threats, mitre_techniques)
        
        # Check compliance status
        compliance_status = self._check_compliance(owasp_findings, architecture)
        
        # Build assessment
        assessment = SecurityAssessment(
            architecture_id=architecture.get('metadata', {}).get('company_name', 'unknown'),
            timestamp=datetime.now().isoformat(),
            risk_score=risk_score,
            owasp_findings=owasp_findings,
            stride_threats=stride_threats,
            mitre_techniques=mitre_techniques,
            recommendations=recommendations,
            compliance_status=compliance_status
        )
        
        return assessment
    
    def _calculate_risk_score(self, 
                             owasp_findings: List[SecurityFinding],
                             stride_threats: List[Threat],
                             mitre_techniques: List[AttackTechnique]) -> RiskScore:
        """
        Calculate overall risk score using CVSS-based weighted approach
        """
        # Count by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        total_cvss_score = 0.0
        finding_count = 0
        
        # Process OWASP findings
        for finding in owasp_findings:
            severity = finding.severity.value
            severity_counts[severity] += 1
            total_cvss_score += finding.cvss_score
            finding_count += 1
        
        # Process STRIDE threats (map likelihood+impact to CVSS-like score)
        for threat in stride_threats:
            cvss_equivalent = self._threat_to_cvss(threat.likelihood, threat.impact)
            total_cvss_score += cvss_equivalent
            finding_count += 1
            
            # Map to severity
            if cvss_equivalent >= 9.0:
                severity_counts['critical'] += 1
            elif cvss_equivalent >= 7.0:
                severity_counts['high'] += 1
            elif cvss_equivalent >= 4.0:
                severity_counts['medium'] += 1
            else:
                severity_counts['low'] += 1
        
        # Process MITRE techniques (count as medium findings)
        for technique in mitre_techniques:
            if technique.possible:
                severity_counts['medium'] += 1
                total_cvss_score += 5.0  # Medium score
                finding_count += 1
        
        # Calculate weighted score (0-100)
        if finding_count == 0:
            total_score = 0.0
            risk_level = "LOW"
        else:
            # Average CVSS score
            avg_cvss = total_cvss_score / finding_count
            
            # Weight by severity distribution
            weighted_score = (
                severity_counts['critical'] * 10.0 +
                severity_counts['high'] * 7.0 +
                severity_counts['medium'] * 4.0 +
                severity_counts['low'] * 2.0 +
                severity_counts['info'] * 0.5
            )
            
            # Normalize to 0-100 scale
            total_score = min(100.0, (avg_cvss / 10.0) * 100.0 * 0.6 + (weighted_score / finding_count) * 10.0 * 0.4)
            
            # Determine risk level
            if total_score >= 80:
                risk_level = "CRITICAL"
            elif total_score >= 60:
                risk_level = "HIGH"
            elif total_score >= 40:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"
        
        return RiskScore(
            total_score=round(total_score, 1),
            risk_level=risk_level,
            severity_breakdown=severity_counts,
            owasp_violations=len(owasp_findings),
            stride_threats=len(stride_threats),
            mitre_techniques=sum(1 for t in mitre_techniques if t.possible),
            critical_findings=severity_counts['critical'],
            high_findings=severity_counts['high'],
            medium_findings=severity_counts['medium'],
            low_findings=severity_counts['low']
        )
    
    def _threat_to_cvss(self, likelihood: str, impact: str) -> float:
        """Convert STRIDE threat likelihood+impact to CVSS score"""
        likelihood_scores = {'high': 3, 'medium': 2, 'low': 1}
        impact_scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        
        l_score = likelihood_scores.get(likelihood.lower(), 2)
        i_score = impact_scores.get(impact.lower(), 2)
        
        # Simple formula: (likelihood * impact) normalized to 0-10
        return min(10.0, (l_score * i_score) * 0.8)
    
    def _generate_recommendations(self,
                                 owasp_findings: List[SecurityFinding],
                                 stride_threats: List[Threat],
                                 mitre_techniques: List[AttackTechnique]) -> List[Dict[str, Any]]:
        """
        Generate prioritized, actionable recommendations
        """
        recommendations = []
        
        # Priority 1: OWASP Critical findings
        critical_owasp = [f for f in owasp_findings if f.severity == Severity.CRITICAL]
        for finding in critical_owasp:
            recommendations.append({
                'priority': 'CRITICAL',
                'type': 'OWASP',
                'title': finding.title,
                'description': finding.description,
                'affected_components': finding.affected_components,
                'mitigation': finding.mitigation,
                'cvss_score': finding.cvss_score,
                'estimated_effort': self._estimate_effort(finding.cvss_score),
                'implementation_time': self._estimate_time(finding.cvss_score)
            })
        
        # Priority 2: High-impact STRIDE threats
        high_stride = [t for t in stride_threats if t.impact == 'critical' or t.impact == 'high']
        for threat in high_stride[:10]:  # Top 10
            recommendations.append({
                'priority': 'HIGH',
                'type': 'STRIDE',
                'title': threat.title,
                'description': threat.description,
                'threat_category': threat.category.value,
                'affected_components': threat.affected_asset,
                'mitigations': threat.mitigations,
                'estimated_effort': 'Medium',
                'implementation_time': '1-2 weeks'
            })
        
        # Priority 3: OWASP High findings
        high_owasp = [f for f in owasp_findings if f.severity == Severity.HIGH]
        for finding in high_owasp[:15]:  # Top 15
            recommendations.append({
                'priority': 'HIGH',
                'type': 'OWASP',
                'title': finding.title,
                'description': finding.description,
                'affected_components': finding.affected_components,
                'mitigation': finding.mitigation,
                'cvss_score': finding.cvss_score,
                'estimated_effort': self._estimate_effort(finding.cvss_score),
                'implementation_time': self._estimate_time(finding.cvss_score)
            })
        
        # Priority 4: High-impact MITRE techniques (based on tactic)
        critical_tactics = ['INITIAL_ACCESS', 'EXECUTION', 'IMPACT', 'EXFILTRATION']
        critical_mitre = [
            t for t in mitre_techniques 
            if t.possible and t.tactic.value in critical_tactics
        ]
        for technique in critical_mitre[:10]:
            recommendations.append({
                'priority': 'HIGH',
                'type': 'MITRE_ATTACK',
                'title': f"{technique.name} ({technique.technique_id})",
                'description': technique.description,
                'tactic': technique.tactic.value,
                'attack_path': technique.attack_path,
                'mitigations': technique.mitigations,
                'detection_methods': technique.detection_methods,
                'estimated_effort': 'High',
                'implementation_time': '2-4 weeks'
            })
        
        # Sort by priority
        priority_order = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 5))
        
        return recommendations
    
    def _estimate_effort(self, cvss_score: float) -> str:
        """Estimate implementation effort based on CVSS score"""
        if cvss_score >= 9.0:
            return 'High'
        elif cvss_score >= 7.0:
            return 'Medium'
        else:
            return 'Low'
    
    def _estimate_time(self, cvss_score: float) -> str:
        """Estimate implementation time based on CVSS score"""
        if cvss_score >= 9.0:
            return '2-4 weeks'
        elif cvss_score >= 7.0:
            return '1-2 weeks'
        elif cvss_score >= 4.0:
            return '3-5 days'
        else:
            return '1-2 days'
    
    def _check_compliance(self, findings: List[SecurityFinding], architecture: Dict) -> Dict[str, Any]:
        """
        Check compliance against common security standards
        """
        # Count violations by OWASP category
        owasp_violations = {}
        for finding in findings:
            category = finding.owasp_category.value
            owasp_violations[category] = owasp_violations.get(category, 0) + 1
        
        # Check PCI-DSS requirements (simplified)
        pci_dss_checks = {
            'firewall_protection': self._check_firewall(architecture),
            'encryption_in_transit': self._check_encryption(architecture),
            'access_control': self._check_access_control(architecture),
            'monitoring_logging': self._check_monitoring(architecture),
            'vulnerability_management': self._check_vuln_management(architecture),
            'secure_systems': self._check_secure_systems(architecture)
        }
        
        pci_dss_compliant = all(pci_dss_checks.values())
        
        # Check NIST CSF (simplified)
        nist_csf_score = sum(1 for v in pci_dss_checks.values() if v) / len(pci_dss_checks) * 100
        
        return {
            'owasp_top_10_violations': owasp_violations,
            'pci_dss': {
                'compliant': pci_dss_compliant,
                'checks': pci_dss_checks,
                'compliance_percentage': round(nist_csf_score, 1)
            },
            'nist_csf_score': round(nist_csf_score, 1),
            'gdpr_readiness': 'partial' if self._check_encryption(architecture) else 'non-compliant',
            'iso_27001_alignment': round(nist_csf_score * 0.9, 1)  # Simplified estimate
        }
    
    def _check_firewall(self, arch: Dict) -> bool:
        nodes = arch.get('nodes', [])
        return any('firewall' in n.get('name', '').lower() or 
                  'firewall' in n.get('properties', {}).get('component_type', '').lower() 
                  for n in nodes)
    
    def _check_encryption(self, arch: Dict) -> bool:
        connections = arch.get('connections', [])
        if not connections:
            return False
        encrypted_count = sum(1 for c in connections 
                            if c.get('properties', {}).get('encrypted', False) or
                            'https' in c.get('properties', {}).get('protocol', '').lower() or
                            'tls' in c.get('properties', {}).get('protocol', '').lower())
        return encrypted_count > len(connections) * 0.7  # At least 70% encrypted
    
    def _check_access_control(self, arch: Dict) -> bool:
        nodes = arch.get('nodes', [])
        return any('auth' in n.get('name', '').lower() or 
                  'identity' in n.get('name', '').lower() or
                  'auth' in n.get('properties', {}).get('component_type', '').lower()
                  for n in nodes)
    
    def _check_monitoring(self, arch: Dict) -> bool:
        nodes = arch.get('nodes', [])
        return any('log' in n.get('name', '').lower() or 
                  'siem' in n.get('name', '').lower() or
                  'monitor' in n.get('name', '').lower() or
                  'logging' in n.get('properties', {}).get('component_type', '').lower()
                  for n in nodes)
    
    def _check_vuln_management(self, arch: Dict) -> bool:
        nodes = arch.get('nodes', [])
        return any('waf' in n.get('name', '').lower() or 
                  'ids' in n.get('name', '').lower() or
                  'ips' in n.get('name', '').lower()
                  for n in nodes)
    
    def _check_secure_systems(self, arch: Dict) -> bool:
        # Check if architecture has basic security posture
        security_level = arch.get('metadata', {}).get('security_level', 'low')
        return security_level in ['high', 'hardened', 'maximum']
    
    def export_to_json(self, assessment: SecurityAssessment) -> str:
        """Export assessment as JSON"""
        
        def convert_to_dict(obj):
            if hasattr(obj, '__dict__'):
                result = {}
                for key, value in obj.__dict__.items():
                    if isinstance(value, list):
                        result[key] = [convert_to_dict(item) for item in value]
                    elif hasattr(value, '__dict__'):
                        result[key] = convert_to_dict(value)
                    elif hasattr(value, 'value'):  # Enum
                        result[key] = value.value
                    else:
                        result[key] = value
                return result
            return obj
        
        assessment_dict = convert_to_dict(assessment)
        return json.dumps(assessment_dict, indent=2)

# Example usage
if __name__ == "__main__":
    # Example architecture
    sample_architecture = {
        "metadata": {
            "company_name": "Sample Corp",
            "architecture_type": "web_application",
            "security_level": "medium"
        },
        "nodes": [
            {
                "id": "web_1",
                "name": "Web Server",
                "properties": {
                    "component_type": "web_server"
                }
            },
            {
                "id": "db_1",
                "name": "Database",
                "properties": {
                    "component_type": "database"
                }
            }
        ],
        "connections": [
            {
                "id": "conn_1",
                "source": "web_1",
                "target": "db_1",
                "properties": {
                    "protocol": "http",
                    "encrypted": False
                }
            }
        ]
    }
    
    # Run scanner
    scanner = RuleBasedSecurityScanner()
    assessment = scanner.scan_architecture(sample_architecture)
    
    # Print results
    print(f"Risk Score: {assessment.risk_score.total_score}/100")
    print(f"Risk Level: {assessment.risk_score.risk_level}")
    print(f"OWASP Findings: {len(assessment.owasp_findings)}")
    print(f"STRIDE Threats: {len(assessment.stride_threats)}")
    print(f"MITRE Techniques: {len(assessment.mitre_techniques)}")
    print(f"\nTop Recommendations:")
    for i, rec in enumerate(assessment.recommendations[:5], 1):
        print(f"{i}. [{rec['priority']}] {rec['title']}")
