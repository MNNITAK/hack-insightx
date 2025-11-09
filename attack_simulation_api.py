"""
ATTACK SIMULATION API ENDPOINT
===============================

API endpoint to integrate attack simulation with the main backend
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List
import json
import tempfile
import os
from attack_simulation import AttackSimulationEngine

app = FastAPI()

class ArchitectureData(BaseModel):
    name: str
    nodes: List[Dict[str, Any]]
    connections: List[Dict[str, Any]]

class AttackData(BaseModel):
    name: str
    description: str
    target: List[str]
    attack_path: List[Dict[str, Any]]

class SimulationRequest(BaseModel):
    architecture: ArchitectureData
    attack: AttackData

class SimulationResponse(BaseModel):
    simulation_id: str
    success: bool
    error: str = None
    summary: Dict[str, Any] = None
    detailed_report: str = None
    full_result: Dict[str, Any] = None

@app.post("/api/simulate-attack", response_model=SimulationResponse)
async def simulate_attack(request: SimulationRequest):
    """
    Simulate an attack against an architecture and return detailed analysis
    """
    
    try:
        # Create temporary files for architecture and attack data
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as arch_file:
            json.dump(request.architecture.dict(), arch_file, indent=2)
            architecture_path = arch_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as attack_file:
            json.dump(request.attack.dict(), attack_file, indent=2)
            attack_path = attack_file.name
        
        # Initialize simulation engine
        engine = AttackSimulationEngine()
        
        # Run simulation
        result = engine.analyze_attack_on_architecture(architecture_path, attack_path)
        
        # Clean up temporary files
        os.unlink(architecture_path)
        os.unlink(attack_path)
        
        # Check for errors
        if "error" in result:
            return SimulationResponse(
                simulation_id="",
                success=False,
                error=result["error"]
            )
        
        # Generate detailed report
        detailed_report = engine.generate_detailed_report(result)
        
        # Create summary for quick display
        total_impact = result["total_impact"]
        post_analysis = result["post_attack_analysis"]
        
        summary = {
            "attack_success_rate": f"{post_analysis['attack_success_rate']*100:.1f}%",
            "components_compromised": len(total_impact["compromised_components"]),
            "data_assets_breached": len(total_impact["breached_data"]),
            "credentials_exposed": len(total_impact["exposed_credentials"]),
            "lateral_movement_achieved": len(total_impact["lateral_movement_paths"]) > 0,
            "business_impact": {
                "operational": post_analysis["business_impact_assessment"]["operational_impact"],
                "financial": post_analysis["business_impact_assessment"]["financial_impact"],
                "regulatory": post_analysis["business_impact_assessment"]["regulatory_impact"],
                "reputation": post_analysis["business_impact_assessment"]["reputation_impact"]
            },
            "security_gaps_count": len(result["security_gaps_identified"]),
            "immediate_actions_required": len(post_analysis["recovery_requirements"]["immediate_actions"])
        }
        
        return SimulationResponse(
            simulation_id=result["simulation_id"],
            success=True,
            summary=summary,
            detailed_report=detailed_report,
            full_result=result
        )
        
    except Exception as e:
        return SimulationResponse(
            simulation_id="",
            success=False,
            error=f"Simulation failed: {str(e)}"
        )

@app.get("/api/attack-templates")
async def get_attack_templates():
    """Get available attack templates"""
    
    attack_templates = [
        {
            "id": "sql_injection_attack",
            "name": "SQL Injection with Data Exfiltration",
            "description": "Multi-stage attack targeting web application vulnerabilities",
            "target_types": ["web_server", "database_server"],
            "phases": ["sql_injection", "credential_theft", "data_exfiltration"],
            "estimated_duration": "90 minutes",
            "severity": "HIGH"
        },
        {
            "id": "brute_force_lateral",
            "name": "Brute Force with Lateral Movement", 
            "description": "Credential-based attack with network propagation",
            "target_types": ["user_workstation", "domain_controller"],
            "phases": ["brute_force", "privilege_escalation", "lateral_movement"],
            "estimated_duration": "120 minutes",
            "severity": "HIGH"
        },
        {
            "id": "web_app_compromise",
            "name": "Web Application Compromise",
            "description": "File upload and XSS-based web application attack",
            "target_types": ["web_server", "load_balancer"],
            "phases": ["file_upload", "xss", "remote_code_execution"],
            "estimated_duration": "60 minutes", 
            "severity": "MEDIUM"
        },
        {
            "id": "insider_threat",
            "name": "Insider Threat Simulation",
            "description": "Privileged user account compromise scenario",
            "target_types": ["user_workstation", "database_server", "domain_controller"],
            "phases": ["privilege_escalation", "data_exfiltration", "lateral_movement"],
            "estimated_duration": "45 minutes",
            "severity": "CRITICAL"
        },
        {
            "id": "network_reconnaissance",
            "name": "Network Reconnaissance and Exploitation",
            "description": "Comprehensive network-based attack scenario",
            "target_types": ["firewall", "web_server", "database_server"],
            "phases": ["reconnaissance", "firewall_bypass", "service_exploitation"],
            "estimated_duration": "180 minutes",
            "severity": "HIGH"
        }
    ]
    
    return {"attack_templates": attack_templates}

@app.post("/api/generate-attack-from-template/{template_id}")
async def generate_attack_from_template(template_id: str, architecture: ArchitectureData):
    """Generate attack scenario from template based on architecture"""
    
    template_attacks = {
        "sql_injection_attack": {
            "name": "SQL Injection with Data Exfiltration",
            "description": "Multi-stage attack targeting web application and database vulnerabilities to extract sensitive data",
            "target": ["web_server", "database_server"],
            "attack_path": [
                {
                    "name": "Initial Reconnaissance",
                    "type": "reconnaissance",
                    "description": "Scan target web application for vulnerabilities",
                    "technique": "Automated vulnerability scanning",
                    "estimated_time": "15 minutes"
                },
                {
                    "name": "SQL Injection Exploit",
                    "type": "sql_injection", 
                    "description": "Exploit SQL injection vulnerability in web application",
                    "technique": "Union-based SQL injection attack",
                    "estimated_time": "30 minutes"
                },
                {
                    "name": "Database Credential Theft",
                    "type": "credential_theft",
                    "description": "Extract database credentials from compromised web server",
                    "technique": "Configuration file analysis and memory dumps",
                    "estimated_time": "15 minutes"
                },
                {
                    "name": "Direct Database Access",
                    "type": "data_exfiltration",
                    "description": "Access database directly using stolen credentials",
                    "technique": "Direct database connection and data extraction",
                    "estimated_time": "45 minutes"
                }
            ]
        },
        
        "brute_force_lateral": {
            "name": "Brute Force with Lateral Movement",
            "description": "Credential-based attack targeting user accounts with subsequent network propagation",
            "target": ["user_workstation", "domain_controller"],
            "attack_path": [
                {
                    "name": "User Account Brute Force",
                    "type": "brute_force",
                    "description": "Brute force attack against user login credentials",
                    "technique": "Dictionary-based password attacks",
                    "estimated_time": "60 minutes"
                },
                {
                    "name": "Privilege Escalation", 
                    "type": "privilege_escalation",
                    "description": "Escalate privileges on compromised user workstation",
                    "technique": "Local privilege escalation exploits",
                    "estimated_time": "30 minutes"
                },
                {
                    "name": "Network Lateral Movement",
                    "type": "lateral_movement",
                    "description": "Move laterally through network to compromise additional systems",
                    "technique": "Pass-the-hash and credential reuse",
                    "estimated_time": "45 minutes"
                }
            ]
        },
        
        "web_app_compromise": {
            "name": "Web Application Compromise",
            "description": "Multi-vector web application attack using file upload and XSS vulnerabilities",
            "target": ["web_server", "load_balancer"],
            "attack_path": [
                {
                    "name": "Malicious File Upload",
                    "type": "file_upload",
                    "description": "Upload malicious file to web server through file upload vulnerability",
                    "technique": "PHP web shell upload via unrestricted file upload",
                    "estimated_time": "20 minutes"
                },
                {
                    "name": "Cross-Site Scripting",
                    "type": "xss",
                    "description": "Execute malicious JavaScript to steal user sessions",
                    "technique": "Stored XSS in user-generated content",
                    "estimated_time": "25 minutes"
                },
                {
                    "name": "Remote Code Execution",
                    "type": "remote_code_execution",
                    "description": "Execute arbitrary commands on web server",
                    "technique": "Web shell command execution",
                    "estimated_time": "30 minutes"
                }
            ]
        },
        
        "insider_threat": {
            "name": "Insider Threat Simulation",
            "description": "Simulation of malicious insider with legitimate access credentials",
            "target": ["user_workstation", "database_server", "domain_controller"],
            "attack_path": [
                {
                    "name": "Legitimate Access Abuse",
                    "type": "privilege_escalation",
                    "description": "Abuse legitimate user credentials to access unauthorized resources",
                    "technique": "Credential abuse and access expansion",
                    "estimated_time": "15 minutes"
                },
                {
                    "name": "Sensitive Data Exfiltration",
                    "type": "data_exfiltration",
                    "description": "Extract sensitive business and customer data",
                    "technique": "Direct database queries and file system access",
                    "estimated_time": "30 minutes"
                },
                {
                    "name": "Evidence Concealment",
                    "type": "lateral_movement",
                    "description": "Attempt to hide malicious activities and maintain persistence",
                    "technique": "Log manipulation and backdoor installation",
                    "estimated_time": "20 minutes"
                }
            ]
        },
        
        "network_reconnaissance": {
            "name": "Network Reconnaissance and Exploitation",
            "description": "Comprehensive network-based attack starting with reconnaissance",
            "target": ["firewall", "web_server", "database_server"],
            "attack_path": [
                {
                    "name": "Network Reconnaissance",
                    "type": "reconnaissance", 
                    "description": "Scan network infrastructure for vulnerabilities and services",
                    "technique": "Port scanning and vulnerability assessment",
                    "estimated_time": "45 minutes"
                },
                {
                    "name": "Firewall Bypass",
                    "type": "firewall_bypass",
                    "description": "Identify and exploit firewall configuration weaknesses",
                    "technique": "Rule analysis and traffic manipulation",
                    "estimated_time": "60 minutes"
                },
                {
                    "name": "Service Exploitation",
                    "type": "service_exploitation",
                    "description": "Exploit identified services and applications",
                    "technique": "Known CVE exploitation and service-specific attacks",
                    "estimated_time": "75 minutes"
                }
            ]
        }
    }
    
    if template_id not in template_attacks:
        raise HTTPException(status_code=404, detail="Attack template not found")
    
    # Get template and customize based on architecture
    attack_template = template_attacks[template_id].copy()
    
    # Filter targets based on available architecture nodes
    available_node_types = [node.get("type", "").lower() for node in architecture.nodes]
    filtered_targets = [t for t in attack_template["target"] if t in available_node_types]
    
    if not filtered_targets:
        # If no direct matches, include all node types for broader attack
        filtered_targets = available_node_types
    
    attack_template["target"] = filtered_targets
    
    return {"attack": attack_template}

@app.get("/api/vm-components")
async def get_vm_components():
    """Get available VM component types and their capabilities"""
    
    from vm_components import VM_COMPONENTS
    
    component_info = {}
    for comp_type, comp_data in VM_COMPONENTS.items():
        component_info[comp_type] = {
            "description": comp_data.get("description", ""),
            "vulnerabilities_count": len(comp_data.get("vulnerabilities", [])),
            "data_assets_count": len(comp_data.get("data_assets", [])),
            "user_accounts_count": len(comp_data.get("user_accounts", [])),
            "services_count": len(comp_data.get("services", [])),
            "sample_vulnerabilities": [v["type"] for v in comp_data.get("vulnerabilities", [])[:3]]
        }
    
    return {"vm_components": component_info}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)