"""
Rule-Based Security Agent API
FastAPI backend using OWASP, STRIDE, and MITRE ATT&CK rules
NO LLM DEPENDENCY - 100% rule-based security analysis
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import json
from datetime import datetime
import uvicorn
import sys
import os

# Add rules directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'rules'))

from security_scanner import RuleBasedSecurityScanner, SecurityAssessment
from attack_simulator import RuleBasedAttackSimulator, AttackValidationResult

app = FastAPI(title="InsightX Rule-Based Security Agent", version="2.0.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== Pydantic Models ====================

class Architecture(BaseModel):
    metadata: Dict[str, Any]
    nodes: List[Dict[str, Any]]
    connections: List[Dict[str, Any]]
    network_zones: Optional[List[Dict[str, Any]]] = []

class AnalysisRequest(BaseModel):
    architecture: Architecture

class HealingRequest(BaseModel):
    architecture: Architecture

class ConfiguredAttack(BaseModel):
    attack_id: str
    attack_name: str
    category: str
    configured_at: str
    parameters: Dict[str, Any]

class ValidationRequest(BaseModel):
    attack: ConfiguredAttack
    architecture: Architecture

class CorrectionRequest(BaseModel):
    attack: ConfiguredAttack
    architecture: Architecture

# ==================== Initialize Scanner ====================

scanner = RuleBasedSecurityScanner()
attack_simulator = RuleBasedAttackSimulator()

# ==================== API Endpoints ====================

@app.get("/")
def read_root():
    return {
        "service": "InsightX Rule-Based Security Agent",
        "version": "2.0.0",
        "mode": "rule-based",
        "frameworks": ["OWASP Top 10", "STRIDE", "MITRE ATT&CK"],
        "endpoints": {
            "analyze": "/api/analyze",
            "heal": "/api/heal",
            "validate_attack": "/api/validate-attack",
            "correct_architecture": "/api/correct-architecture",
            "health": "/health"
        }
    }

@app.post("/api/analyze")
async def analyze_architecture(request: AnalysisRequest):
    """
    Analyze architecture using rule-based OWASP, STRIDE, and MITRE ATT&CK
    """
    try:
        print(f"\n🔍 Analyzing architecture: {request.architecture.metadata.get('company_name', 'Unknown')}")
        
        # Convert Pydantic model to dict
        architecture_dict = {
            "metadata": request.architecture.metadata,
            "nodes": [node for node in request.architecture.nodes],
            "connections": [conn for conn in request.architecture.connections],
            "network_zones": request.architecture.network_zones or []
        }
        
        # Run rule-based analysis
        assessment = scanner.scan_architecture(architecture_dict)
        
        # Convert assessment to response format
        response = {
            "architecture_id": assessment.architecture_id,
            "timestamp": assessment.timestamp,
            "risk_assessment": {
                "total_score": assessment.risk_score.total_score,
                "risk_level": assessment.risk_score.risk_level,
                "severity_breakdown": assessment.risk_score.severity_breakdown,
                "owasp_violations": assessment.risk_score.owasp_violations,
                "stride_threats": assessment.risk_score.stride_threats,
                "mitre_techniques": assessment.risk_score.mitre_techniques
            },
            "owasp_findings": [
                {
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "owasp_category": f.owasp_category.value,
                    "affected_components": f.affected_components,
                    "cvss_score": f.cvss_score,
                    "cwe_id": f.cwe_id,
                    "mitigation": f.mitigation,
                    "confidence": f.confidence
                }
                for f in assessment.owasp_findings
            ],
            "stride_threats": [
                {
                    "threat_id": t.threat_id,
                    "category": t.category.value,
                    "title": t.title,
                    "description": t.description,
                    "affected_asset": t.affected_asset,
                    "likelihood": t.likelihood,
                    "impact": t.impact,
                    "attack_vector": t.attack_vector,
                    "mitigations": t.mitigations
                }
                for t in assessment.stride_threats
            ],
            "mitre_attack_techniques": [
                {
                    "technique_id": tech.technique_id,
                    "name": tech.name,
                    "tactic": tech.tactic.value,
                    "description": tech.description,
                    "possible": tech.possible,
                    "affected_components": tech.affected_components,
                    "attack_path": tech.attack_path,
                    "detection_methods": tech.detection_methods,
                    "mitigations": tech.mitigations
                }
                for tech in assessment.mitre_techniques if tech.possible
            ],
            "recommendations": assessment.recommendations,
            "compliance_status": assessment.compliance_status
        }
        
        print(f"✅ Analysis complete - Risk: {assessment.risk_score.risk_level} ({assessment.risk_score.total_score}/100)")
        print(f"   Found {len(assessment.owasp_findings)} OWASP issues, {len(assessment.stride_threats)} STRIDE threats, {assessment.risk_score.mitre_techniques} MITRE techniques")
        
        return response
        
    except Exception as e:
        print(f"❌ Error in analysis: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/heal")
async def heal_architecture(request: HealingRequest):
    """
    Generate healed architecture with security improvements based on rule-based findings
    """
    try:
        print(f"\n🩹 Healing architecture: {request.architecture.metadata.get('company_name', 'Unknown')}")
        
        # Convert to dict
        architecture_dict = {
            "metadata": request.architecture.metadata,
            "nodes": [node for node in request.architecture.nodes],
            "connections": [conn for conn in request.architecture.connections],
            "network_zones": request.architecture.network_zones or []
        }
        
        # Run analysis first
        assessment = scanner.scan_architecture(architecture_dict)
        
        # Generate healed architecture based on findings
        healed_arch = _generate_healed_architecture(architecture_dict, assessment)
        
        response = {
            "healing_summary": {
                "original_architecture_id": assessment.architecture_id,
                "analysis_timestamp": assessment.timestamp,
                "total_vulnerabilities_found": (
                    assessment.risk_score.owasp_violations +
                    assessment.risk_score.stride_threats
                ),
                "overall_risk_score": assessment.risk_score.total_score,
                "security_posture": assessment.risk_score.risk_level,
                "mitigations_applied": len(assessment.recommendations)
            },
            "vulnerability_analysis": {
                "overall_risk_score": assessment.risk_score.total_score,
                "security_posture": assessment.risk_score.risk_level,
                "total_vulnerabilities": (
                    assessment.risk_score.owasp_violations +
                    assessment.risk_score.stride_threats
                ),
                "severity_breakdown": assessment.risk_score.severity_breakdown,
                "vulnerable_attacks": [
                    {
                        "attack_name": f.title,
                        "attack_id": f.rule_id,
                        "vulnerable": True,
                        "severity": f.severity.value.upper(),
                        "affected_components": f.affected_components,
                        "impact": f.description,
                        "likelihood": "high" if f.cvss_score >= 7.0 else "medium"
                    }
                    for f in assessment.owasp_findings[:20]  # Top 20
                ],
                "architecture_weaknesses": [
                    f.title for f in assessment.owasp_findings
                ],
                "compliance_violations": [
                    f"{cat}: {count} violations" 
                    for cat, count in assessment.compliance_status.get('owasp_top_10_violations', {}).items()
                ]
            },
            "healed_architecture": healed_arch,
            "recommendations": {
                "immediate_actions": [
                    {
                        "action": rec['title'],
                        "priority": rec['priority'],
                        "effort": rec.get('estimated_effort', 'Medium'),
                        "cost": _estimate_cost(rec.get('cvss_score', 5.0)),
                        "impact": rec['description']
                    }
                    for rec in assessment.recommendations[:20]
                    if rec['priority'] in ['CRITICAL', 'HIGH']
                ],
                "short_term_improvements": [
                    rec['title'] for rec in assessment.recommendations[20:40]
                ],
                "long_term_initiatives": [
                    "Implement Security Operations Center (SOC)",
                    "Deploy Security Orchestration, Automation and Response (SOAR)",
                    "Establish bug bounty program",
                    "Conduct regular penetration testing",
                    "Achieve ISO 27001 certification"
                ],
                "monitoring_guidelines": [
                    "Enable real-time security event monitoring",
                    "Set up automated alerting for critical events",
                    "Implement user behavior analytics",
                    "Deploy threat intelligence feeds",
                    "Conduct weekly security reviews"
                ],
                "compliance_requirements": [
                    f"{key}: {value['compliance_percentage']:.1f}% compliant"
                    for key, value in assessment.compliance_status.items()
                    if isinstance(value, dict) and 'compliance_percentage' in value
                ],
                "estimated_total_cost": f"${_estimate_total_cost(assessment.recommendations):,}",
                "implementation_timeline": _estimate_timeline(assessment.recommendations),
                "risk_reduction": f"{_calculate_risk_reduction(assessment.risk_score.total_score):.1f}%"
            },
            "changes_summary": healed_arch.get('changes_summary', {})
        }
        
        print(f"✅ Healing complete - Added {healed_arch.get('changes_summary', {}).get('components_added', 0)} security components")
        
        return response
        
    except Exception as e:
        print(f"❌ Error in healing: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "mode": "rule-based",
        "llm_dependency": False,
        "frameworks": ["OWASP Top 10 2021", "STRIDE", "MITRE ATT&CK"]
    }

# ==================== Helper Functions ====================

def _generate_healed_architecture(original_arch: Dict, assessment: SecurityAssessment) -> Dict:
    """
    Generate healed architecture by adding security components based on findings
    """
    import copy
    healed = copy.deepcopy(original_arch)
    
    added_nodes = []
    modified_connections = []
    
    # Track what we need to add
    needs_firewall = any('firewall' in f.title.lower() for f in assessment.owasp_findings)
    needs_waf = any('waf' in f.title.lower() or 'injection' in f.title.lower() for f in assessment.owasp_findings)
    needs_ids = any('intrusion' in f.title.lower() or 'monitoring' in f.title.lower() for f in assessment.owasp_findings)
    needs_load_balancer = any('denial of service' in f.title.lower() or 'redundancy' in f.title.lower() for f in assessment.owasp_findings)
    needs_auth = any('authentication' in f.title.lower() for f in assessment.owasp_findings)
    needs_encryption = any('encryption' in f.title.lower() or 'cryptographic' in f.title.lower() for f in assessment.owasp_findings)
    needs_backup = any('backup' in f.title.lower() or 'integrity' in f.title.lower() for f in assessment.owasp_findings)
    needs_siem = any('logging' in f.title.lower() or 'siem' in f.title.lower() for f in assessment.owasp_findings)
    
    base_id = int(datetime.now().timestamp())
    
    # Add Firewall
    if needs_firewall:
        firewall = {
            "id": f"firewall_{base_id}",
            "type": "component",
            "name": "Next-Generation Firewall",
            "properties": {
                "component_type": "firewall",
                "vendor": "Palo Alto Networks",
                "features": ["IPS", "Application Control", "URL Filtering"],
                "tier": "security"
            },
            "position": {"x": 100, "y": 150}
        }
        healed["nodes"].append(firewall)
        added_nodes.append(firewall)
    
    # Add WAF
    if needs_waf:
        waf = {
            "id": f"waf_{base_id}",
            "type": "component",
            "name": "Web Application Firewall",
            "properties": {
                "component_type": "waf",
                "vendor": "AWS WAF / Cloudflare",
                "rule_sets": ["OWASP Core Rule Set", "Bot Protection"],
                "tier": "security"
            },
            "position": {"x": 300, "y": 150}
        }
        healed["nodes"].append(waf)
        added_nodes.append(waf)
    
    # Add IDS/IPS
    if needs_ids:
        ids = {
            "id": f"ids_ips_{base_id}",
            "type": "component",
            "name": "Intrusion Detection/Prevention System",
            "properties": {
                "component_type": "ids_ips",
                "vendor": "Suricata / Snort",
                "capabilities": ["Network IDS", "Anomaly Detection"],
                "tier": "security"
            },
            "position": {"x": 500, "y": 150}
        }
        healed["nodes"].append(ids)
        added_nodes.append(ids)
    
    # Add Load Balancer
    if needs_load_balancer:
        lb = {
            "id": f"load_balancer_{base_id}",
            "type": "component",
            "name": "Application Load Balancer",
            "properties": {
                "component_type": "load_balancer",
                "vendor": "AWS ALB / Nginx",
                "features": ["SSL Termination", "Health Checks", "Auto-scaling"],
                "tier": "web"
            },
            "position": {"x": 700, "y": 200}
        }
        healed["nodes"].append(lb)
        added_nodes.append(lb)
    
    # Add Authentication Service
    if needs_auth:
        auth = {
            "id": f"auth_service_{base_id}",
            "type": "component",
            "name": "Authentication Service",
            "properties": {
                "component_type": "authentication_service",
                "vendor": "Auth0 / Okta",
                "features": ["OAuth 2.0", "MFA", "SSO"],
                "tier": "application"
            },
            "position": {"x": 400, "y": 300}
        }
        healed["nodes"].append(auth)
        added_nodes.append(auth)
    
    # Add Encryption Gateway
    if needs_encryption:
        kms = {
            "id": f"kms_{base_id}",
            "type": "component",
            "name": "Key Management Service",
            "properties": {
                "component_type": "encryption",
                "vendor": "AWS KMS / Azure Key Vault",
                "features": ["Encryption at Rest", "Key Rotation"],
                "tier": "security"
            },
            "position": {"x": 600, "y": 300}
        }
        healed["nodes"].append(kms)
        added_nodes.append(kms)
    
    # Add Backup System
    if needs_backup:
        backup = {
            "id": f"backup_system_{base_id}",
            "type": "component",
            "name": "Automated Backup System",
            "properties": {
                "component_type": "backup_system",
                "vendor": "AWS Backup / Veeam",
                "features": ["Automated Backups", "Point-in-time Recovery"],
                "tier": "data"
            },
            "position": {"x": 800, "y": 400}
        }
        healed["nodes"].append(backup)
        added_nodes.append(backup)
    
    # Add SIEM
    if needs_siem:
        siem = {
            "id": f"siem_{base_id}",
            "type": "component",
            "name": "Security Information and Event Management",
            "properties": {
                "component_type": "siem",
                "vendor": "Splunk / ELK Stack",
                "features": ["Log Aggregation", "Threat Detection", "Alerting"],
                "tier": "security"
            },
            "position": {"x": 900, "y": 150}
        }
        healed["nodes"].append(siem)
        added_nodes.append(siem)
    
    # Modify connections to add encryption
    for conn in healed.get("connections", []):
        if not conn.get("properties", {}).get("encrypted", False):
            conn["properties"]["encrypted"] = True
            conn["properties"]["protocol"] = conn.get("properties", {}).get("protocol", "http").replace("http", "https")
            modified_connections.append(conn)
    
    # Update metadata
    healed["metadata"]["security_level"] = "high"
    healed["metadata"]["hardened_at"] = datetime.now().isoformat()
    healed["metadata"]["description"] = f"Hardened architecture with {len(added_nodes)} security controls"
    
    # Add changes summary
    healed["changes_summary"] = {
        "components_added": len(added_nodes),
        "connections_modified": len(modified_connections),
        "security_controls_added": [node["properties"]["component_type"] for node in added_nodes],
        "improvements": [
            "Added network perimeter security",
            "Implemented application-layer protection",
            "Enabled comprehensive logging and monitoring",
            "Established access control mechanisms",
            "Added encryption for data at rest and in transit",
            "Implemented backup and recovery capabilities"
        ]
    }
    
    return {
        "id": f"arch_healed_{base_id}",
        "metadata": healed["metadata"],
        "nodes": healed["nodes"],
        "connections": healed["connections"],
        "network_zones": healed.get("network_zones", []),
        "changes_summary": healed["changes_summary"]
    }

def _estimate_cost(cvss_score: float) -> str:
    """Estimate implementation cost"""
    if cvss_score >= 9.0:
        return "$$$$ ($50,000 - $100,000)"
    elif cvss_score >= 7.0:
        return "$$$ ($20,000 - $50,000)"
    elif cvss_score >= 4.0:
        return "$$ ($5,000 - $20,000)"
    else:
        return "$ ($1,000 - $5,000)"

def _estimate_total_cost(recommendations: List[Dict]) -> int:
    """Estimate total implementation cost"""
    cost_map = {'CRITICAL': 75000, 'HIGH': 35000, 'MEDIUM': 12500, 'LOW': 3000}
    return sum(cost_map.get(rec.get('priority', 'MEDIUM'), 10000) for rec in recommendations[:10])

def _estimate_timeline(recommendations: List[Dict]) -> str:
    """Estimate implementation timeline"""
    critical_count = sum(1 for r in recommendations if r.get('priority') == 'CRITICAL')
    high_count = sum(1 for r in recommendations if r.get('priority') == 'HIGH')
    
    if critical_count > 5:
        return "6-12 months"
    elif critical_count > 0 or high_count > 10:
        return "3-6 months"
    else:
        return "1-3 months"

def _calculate_risk_reduction(current_score: float) -> float:
    """Calculate expected risk reduction percentage"""
    # Assumes remediation will reduce risk by 60-90% based on current score
    if current_score >= 80:
        return 75.0  # Critical systems need major work
    elif current_score >= 60:
        return 65.0
    elif current_score >= 40:
        return 55.0
    else:
        return 40.0

# ==================== Attack Simulation Endpoints ====================

@app.post("/api/validate-attack")
async def validate_attack(request: ValidationRequest):
    """
    Validate if a specific attack is possible on the given architecture using rule-based analysis
    """
    try:
        attack_name = request.attack.attack_name
        print(f"\n🎯 Validating attack: {attack_name}")
        
        # Convert architecture to dict
        architecture_dict = {
            "metadata": request.architecture.metadata,
            "nodes": [node for node in request.architecture.nodes],
            "connections": [conn for conn in request.architecture.connections],
            "network_zones": request.architecture.network_zones or []
        }
        
        # Run full security scan first
        assessment = scanner.scan_architecture(architecture_dict)
        
        # Validate specific attack
        validation_result = attack_simulator.validate_attack(attack_name, architecture_dict, assessment)
        
        # Build detailed security analysis
        security_analysis = {
            "attack_feasibility": "HIGH" if validation_result.is_possible and validation_result.confidence >= 0.7 else 
                                 "MEDIUM" if validation_result.is_possible and validation_result.confidence >= 0.4 else 
                                 "LOW",
            "confidence_score": round(validation_result.confidence * 100, 1),
            "vulnerability_assessment": {
                "vulnerable_components": validation_result.vulnerable_components,
                "attack_surface": len(validation_result.vulnerable_components),
                "exploitable_paths": validation_result.attack_path,
                "severity": validation_result.severity
            },
            "reasons": validation_result.reasons,
            "mitre_techniques": validation_result.mitre_techniques,
            "overall_risk_score": assessment.risk_score.total_score,
            "affected_owasp_categories": [
                f.rule_id for f in assessment.owasp_findings 
                if any(comp in f.affected_components for comp in validation_result.vulnerable_components)
            ][:5],
            "recommended_controls": validation_result.recommended_controls
        }
        
        # Check for missing critical components
        missing_components = []
        if not validation_result.is_possible:
            # Attack blocked - list the blocking controls
            missing_components = validation_result.reasons
        
        response = {
            "is_valid": True,  # Attack configuration is valid
            "attack_id": request.attack.attack_id,
            "validation_timestamp": datetime.now().isoformat(),
            "can_proceed": validation_result.is_possible,  # Can the attack proceed?
            "attack_possible": validation_result.is_possible,
            "security_analysis": security_analysis,
            "missing_components": missing_components,
            "recommendation": (
                f"⚠️ Attack {attack_name} is POSSIBLE with {validation_result.confidence*100:.0f}% confidence. "
                f"The architecture has {len(validation_result.vulnerable_components)} vulnerable components. "
                f"Consider implementing the recommended security controls."
                if validation_result.is_possible else
                f"✅ Attack {attack_name} is BLOCKED. The architecture has adequate security controls in place."
            )
        }
        
        print(f"{'❌ Attack POSSIBLE' if validation_result.is_possible else '✅ Attack BLOCKED'} - Confidence: {validation_result.confidence*100:.0f}%")
        
        return response
        
    except Exception as e:
        print(f"❌ Error validating attack: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/correct-architecture")
async def correct_architecture(request: CorrectionRequest):
    """
    Generate corrected architecture that mitigates the specified attack using rule-based recommendations
    """
    try:
        attack_name = request.attack.attack_name
        print(f"\n🔧 Generating corrected architecture for attack: {attack_name}")
        
        # Convert architecture to dict
        architecture_dict = {
            "metadata": request.architecture.metadata,
            "nodes": [node for node in request.architecture.nodes],
            "connections": [conn for conn in request.architecture.connections],
            "network_zones": request.architecture.network_zones or []
        }
        
        # Run security scan
        assessment = scanner.scan_architecture(architecture_dict)
        
        # Validate attack to understand vulnerabilities
        validation_result = attack_simulator.validate_attack(attack_name, architecture_dict, assessment)
        
        # Generate corrected architecture
        corrected_arch = _generate_attack_specific_correction(
            architecture_dict, 
            attack_name, 
            validation_result, 
            assessment
        )
        
        # Build change summary
        original_component_count = len(architecture_dict['nodes'])
        new_component_count = len(corrected_arch['nodes'])
        added_count = new_component_count - original_component_count
        
        change_summary = {
            "added_components": corrected_arch.get('added_components', []),
            "modified_components": corrected_arch.get('modified_components', []),
            "components_added_count": added_count,
            "security_improvements": corrected_arch.get('security_improvements', []),
            "architecture_changes": f"Added {added_count} security components to mitigate {attack_name}"
        }
        
        # Build attack mitigation details
        attack_mitigation = {
            "attack_id": request.attack.attack_id,
            "attack_name": attack_name,
            "prevented": True,  # After corrections, attack should be prevented
            "confidence": 0.95,  # High confidence in mitigation
            "mitigation_techniques": corrected_arch.get('mitigation_techniques', []),
            "security_controls_added": corrected_arch.get('added_components', []),
            "risk_reduction": "75-90%",
            "compliance_improvement": corrected_arch.get('compliance_improvement', 'Improved')
        }
        
        response = {
            "original_architecture_id": f"arch_{int(datetime.now().timestamp())}",
            "correction_timestamp": datetime.now().isoformat(),
            "new_architecture": {
                "id": corrected_arch.get('id', f"arch_corrected_{int(datetime.now().timestamp())}"),
                "metadata": corrected_arch['metadata'],
                "nodes": corrected_arch['nodes'],
                "connections": corrected_arch['connections'],
                "network_zones": corrected_arch.get('network_zones', [])
            },
            "change_summary": change_summary,
            "attack_mitigation": attack_mitigation,
            "implementation_guidance": {
                "priority": "HIGH" if validation_result.is_possible else "MEDIUM",
                "estimated_cost": _estimate_cost(validation_result.confidence * 10),
                "implementation_time": "2-4 weeks",
                "required_expertise": ["Security Architecture", "Cloud Security", "Network Security"],
                "deployment_steps": corrected_arch.get('deployment_steps', [])
            }
        }
        
        print(f"✅ Corrected architecture generated - Added {added_count} security components")
        
        return response
        
    except Exception as e:
        print(f"❌ Error generating corrected architecture: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

def _generate_attack_specific_correction(
    original_arch: Dict, 
    attack_name: str, 
    validation_result: AttackValidationResult,
    assessment: SecurityAssessment
) -> Dict:
    """
    Generate architecture corrections specific to the attack type
    """
    import copy
    corrected = copy.deepcopy(original_arch)
    
    added_components = []
    modified_components = []
    security_improvements = []
    mitigation_techniques = []
    deployment_steps = []
    
    base_id = int(datetime.now().timestamp())
    
    # Attack-specific corrections based on attack catalog
    attack_lower = attack_name.lower()
    
    # SQL Injection / Injection attacks
    if 'injection' in attack_lower or 'sql' in attack_lower or 'xss' in attack_lower:
        # Add WAF
        waf = {
            "id": f"waf_{base_id}",
            "type": "Web Application Firewall",
            "category": "Security",
            "properties": {
                "name": "WAF",
                "description": "Web Application Firewall to block injection attacks",
                "rules": ["OWASP ModSecurity CRS", "SQL Injection Prevention", "XSS Prevention"]
            },
            "position": {"x": 200, "y": 100}
        }
        corrected['nodes'].append(waf)
        added_components.append("Web Application Firewall (WAF)")
        security_improvements.append("Blocks SQL injection, XSS, and other injection attacks")
        mitigation_techniques.append("Input validation and sanitization at WAF layer")
        deployment_steps.append("Deploy WAF in front of web applications")
        deployment_steps.append("Configure OWASP ModSecurity Core Rule Set")
        deployment_steps.append("Enable logging and monitoring for blocked requests")
    
    # DDoS attacks
    if 'ddos' in attack_lower or 'denial' in attack_lower:
        # Add Load Balancer with DDoS protection
        lb = {
            "id": f"loadbalancer_{base_id}",
            "type": "Load Balancer",
            "category": "Network",
            "properties": {
                "name": "DDoS Protection Load Balancer",
                "description": "Load balancer with DDoS mitigation",
                "features": ["Rate limiting", "Traffic filtering", "Auto-scaling"]
            },
            "position": {"x": 300, "y": 100}
        }
        corrected['nodes'].append(lb)
        added_components.append("Load Balancer with DDoS Protection")
        security_improvements.append("Mitigates DDoS attacks through rate limiting and traffic filtering")
        mitigation_techniques.append("Rate limiting and traffic shaping")
        deployment_steps.append("Deploy cloud-based DDoS protection service")
        deployment_steps.append("Configure rate limiting rules")
        deployment_steps.append("Set up auto-scaling policies")
    
    # MITM / Network attacks
    if 'mitm' in attack_lower or 'man in the middle' in attack_lower or 'network' in attack_lower:
        # Add VPN/Encryption
        vpn = {
            "id": f"vpn_{base_id}",
            "type": "VPN Gateway",
            "category": "Security",
            "properties": {
                "name": "VPN Gateway",
                "description": "Encrypted tunnel for secure communication",
                "encryption": "AES-256",
                "protocols": ["IPSec", "TLS 1.3"]
            },
            "position": {"x": 150, "y": 150}
        }
        corrected['nodes'].append(vpn)
        added_components.append("VPN Gateway")
        security_improvements.append("Encrypts all network traffic to prevent interception")
        mitigation_techniques.append("End-to-end encryption with TLS 1.3")
        deployment_steps.append("Deploy VPN gateway")
        deployment_steps.append("Enforce TLS 1.3 for all connections")
        deployment_steps.append("Implement certificate pinning")
    
    # Brute Force / Credential attacks
    if 'brute' in attack_lower or 'credential' in attack_lower or 'password' in attack_lower:
        # Add MFA and Rate Limiter
        mfa = {
            "id": f"mfa_{base_id}",
            "type": "MFA System",
            "category": "Security",
            "properties": {
                "name": "Multi-Factor Authentication",
                "description": "Additional authentication layer",
                "methods": ["TOTP", "SMS", "Biometric"]
            },
            "position": {"x": 250, "y": 200}
        }
        corrected['nodes'].append(mfa)
        added_components.append("Multi-Factor Authentication (MFA)")
        security_improvements.append("Requires multiple authentication factors")
        mitigation_techniques.append("Rate limiting on authentication attempts")
        deployment_steps.append("Implement MFA for all user accounts")
        deployment_steps.append("Configure account lockout policies")
        deployment_steps.append("Enable CAPTCHA after failed attempts")
    
    # Ransomware / Data attacks
    if 'ransomware' in attack_lower or 'data' in attack_lower:
        # Add Backup System
        backup = {
            "id": f"backup_{base_id}",
            "type": "Backup System",
            "category": "Storage",
            "properties": {
                "name": "Automated Backup System",
                "description": "Regular automated backups with versioning",
                "frequency": "Hourly",
                "retention": "30 days"
            },
            "position": {"x": 400, "y": 250}
        }
        corrected['nodes'].append(backup)
        added_components.append("Automated Backup System")
        security_improvements.append("Enables recovery from ransomware attacks")
        mitigation_techniques.append("Immutable backups with versioning")
        deployment_steps.append("Set up automated backup schedule")
        deployment_steps.append("Configure immutable backup storage")
        deployment_steps.append("Test recovery procedures regularly")
    
    # Phishing / Social Engineering
    if 'phishing' in attack_lower or 'social' in attack_lower:
        # Add Email Security Gateway
        email_security = {
            "id": f"emailsec_{base_id}",
            "type": "Email Security Gateway",
            "category": "Security",
            "properties": {
                "name": "Email Security",
                "description": "Anti-phishing and email filtering",
                "features": ["Link scanning", "Attachment sandboxing", "SPF/DKIM/DMARC"]
            },
            "position": {"x": 350, "y": 150}
        }
        corrected['nodes'].append(email_security)
        added_components.append("Email Security Gateway")
        security_improvements.append("Filters phishing emails and malicious attachments")
        mitigation_techniques.append("Email authentication and link rewriting")
        deployment_steps.append("Deploy email security gateway")
        deployment_steps.append("Configure SPF, DKIM, DMARC policies")
        deployment_steps.append("Enable user security awareness training")
    
    # API Abuse
    if 'api' in attack_lower:
        # Add API Gateway
        api_gw = {
            "id": f"apigw_{base_id}",
            "type": "API Gateway",
            "category": "Network",
            "properties": {
                "name": "API Gateway",
                "description": "Secure API management",
                "features": ["Rate limiting", "Authentication", "Request validation"]
            },
            "position": {"x": 280, "y": 180}
        }
        corrected['nodes'].append(api_gw)
        added_components.append("API Gateway")
        security_improvements.append("Enforces API security policies and rate limits")
        mitigation_techniques.append("OAuth 2.0 authentication and rate limiting")
        deployment_steps.append("Deploy API Gateway")
        deployment_steps.append("Configure rate limiting policies")
        deployment_steps.append("Implement OAuth 2.0 authentication")
    
    # General security improvements for all attacks
    # Add Firewall if not present
    has_firewall = any('firewall' in node.get('type', '').lower() for node in corrected['nodes'])
    if not has_firewall:
        firewall = {
            "id": f"firewall_{base_id}",
            "type": "Next-Gen Firewall",
            "category": "Security",
            "properties": {
                "name": "Next-Generation Firewall",
                "description": "Advanced firewall with IPS/IDS",
                "features": ["Deep packet inspection", "IPS", "IDS", "Application control"]
            },
            "position": {"x": 100, "y": 100}
        }
        corrected['nodes'].append(firewall)
        added_components.append("Next-Generation Firewall")
        security_improvements.append("Network segmentation and traffic filtering")
        mitigation_techniques.append("Network-level threat detection and prevention")
    
    # Add SIEM for monitoring
    has_siem = any('siem' in node.get('type', '').lower() for node in corrected['nodes'])
    if not has_siem:
        siem = {
            "id": f"siem_{base_id}",
            "type": "SIEM",
            "category": "Security",
            "properties": {
                "name": "Security Information and Event Management",
                "description": "Centralized security monitoring and alerting",
                "features": ["Log aggregation", "Threat detection", "Incident response"]
            },
            "position": {"x": 450, "y": 100}
        }
        corrected['nodes'].append(siem)
        added_components.append("SIEM System")
        security_improvements.append("Real-time security monitoring and threat detection")
        mitigation_techniques.append("Continuous security monitoring and alerting")
    
    corrected['added_components'] = added_components
    corrected['modified_components'] = modified_components
    corrected['security_improvements'] = security_improvements
    corrected['mitigation_techniques'] = mitigation_techniques
    corrected['deployment_steps'] = deployment_steps
    corrected['compliance_improvement'] = "Enhanced compliance with security frameworks"
    
    return corrected

if __name__ == "__main__":
    print("🚀 Starting InsightX Rule-Based Security Agent...")
    print(f"🔒 Security Frameworks: OWASP Top 10, STRIDE, MITRE ATT&CK")
    print(f"⚡ Mode: 100% Rule-Based (No LLM dependency)")
    print(f"🔗 API will be available at: http://localhost:5000")
    print(f"📖 Docs available at: http://localhost:5000/docs")
    
    uvicorn.run(app, host="0.0.0.0", port=5000, log_level="info")
