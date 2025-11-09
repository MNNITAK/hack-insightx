"""
ENHANCED API WITH VM ATTACK OPTION
==================================

Extends the existing API to provide VM attack simulation as an additional option
alongside regular security analysis.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import json
from datetime import datetime

# Import both engines
from enhanced_vm_attack_engine import EnhancedVMAttackEngine

app = FastAPI()

class ArchitectureData(BaseModel):
    name: str = None
    metadata: Dict[str, Any] = None
    nodes: List[Dict[str, Any]]
    connections: List[Dict[str, Any]]
    network_zones: List[Dict[str, Any]] = []

class AttackConfigurationData(BaseModel):
    intensity: str = "medium"  # low, medium, high
    stealth_level: str = "normal"  # noisy, normal, stealthy
    speed: str = "normal"  # slow, normal, fast
    scope: str = "multiple_targets"  # single_target, multiple_targets, full_architecture
    persistence_level: str = "short_term"  # temporary, short_term, long_term
    lateral_movement: str = "limited"  # none, limited, extensive
    data_collection: str = "moderate"  # minimal, moderate, comprehensive

class VMAttackRequest(BaseModel):
    architecture: ArchitectureData
    attack_scenario_id: str
    configuration: AttackConfigurationData

class VMAttackResponse(BaseModel):
    simulation_id: str
    success: bool
    error: str = None
    attack_scenario: Dict[str, Any] = None
    simulation_results: Dict[str, Any] = None
    canvas_state: Dict[str, Any] = None
    detailed_report: str = None

class AnalysisOptionResponse(BaseModel):
    options: List[str]
    descriptions: Dict[str, str]

# Initialize VM attack engine
vm_engine = EnhancedVMAttackEngine()

@app.get("/api/analysis-options", response_model=AnalysisOptionResponse)
async def get_analysis_options():
    """
    Get available analysis options for the user to choose from
    """
    
    options = [
        "regular_security_analysis",
        "vm_attack_simulation",
        "combined_analysis"
    ]
    
    descriptions = {
        "regular_security_analysis": "Standard security analysis using OWASP, MITRE, and STRIDE rules to identify vulnerabilities and provide recommendations",
        "vm_attack_simulation": "Interactive virtual machine attack simulation with 20+ customizable attack scenarios and real-time canvas updates",
        "combined_analysis": "Comprehensive analysis combining security assessment with attack simulation for complete security posture evaluation"
    }
    
    return AnalysisOptionResponse(
        options=options,
        descriptions=descriptions
    )

@app.post("/api/vm-attack-scenarios")
async def get_vm_attack_scenarios(architecture: ArchitectureData):
    """
    Get available VM attack scenarios based on the provided architecture
    """
    
    try:
        # Convert architecture to dict
        arch_dict = architecture.dict()
        
        # Get attack scenarios from enhanced engine
        scenarios = vm_engine.get_attack_options(arch_dict)
        
        return {
            "success": True,
            "total_scenarios": len(scenarios),
            "scenarios": scenarios,
            "categories": list(set([s["category"] for s in scenarios])),
            "severity_distribution": {
                "CRITICAL": len([s for s in scenarios if s["severity"] == "CRITICAL"]),
                "HIGH": len([s for s in scenarios if s["severity"] == "HIGH"]),
                "MEDIUM": len([s for s in scenarios if s["severity"] == "MEDIUM"]),
                "LOW": len([s for s in scenarios if s["severity"] == "LOW"])
            }
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate attack scenarios: {str(e)}"
        )

@app.post("/api/vm-attack-execute", response_model=VMAttackResponse)
async def execute_vm_attack(request: VMAttackRequest):
    """
    Execute a VM attack simulation with real-time canvas updates
    """
    
    try:
        # Get architecture and configuration
        arch_dict = request.architecture.dict()
        config_dict = request.configuration.dict()
        
        # Get the selected attack scenario
        scenarios = vm_engine.get_attack_options(arch_dict)
        selected_scenario = next(
            (s for s in scenarios if s["id"] == request.attack_scenario_id), 
            None
        )
        
        if not selected_scenario:
            return VMAttackResponse(
                simulation_id="",
                success=False,
                error=f"Attack scenario '{request.attack_scenario_id}' not found"
            )
        
        # Execute VM attack with canvas updates
        results = vm_engine.execute_vm_attack_with_canvas_updates(
            arch_dict, 
            selected_scenario, 
            config_dict
        )
        
        # Generate detailed report
        detailed_report = vm_engine.generate_detailed_report(results)
        
        return VMAttackResponse(
            simulation_id=results["simulation_id"],
            success=True,
            attack_scenario=selected_scenario,
            simulation_results=results,
            canvas_state=vm_engine.get_canvas_status(),
            detailed_report=detailed_report
        )
        
    except Exception as e:
        return VMAttackResponse(
            simulation_id="",
            success=False,
            error=f"VM attack execution failed: {str(e)}"
        )

@app.get("/api/vm-attack-status/{simulation_id}")
async def get_vm_attack_status(simulation_id: str):
    """
    Get real-time status of ongoing VM attack simulation for canvas updates
    """
    
    try:
        canvas_state = vm_engine.get_canvas_status()
        
        return {
            "success": True,
            "simulation_id": simulation_id,
            "canvas_state": canvas_state,
            "last_updated": datetime.now().isoformat(),
            "active_simulation": bool(canvas_state)
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get attack status: {str(e)}"
        )

@app.post("/api/vm-attack-configure/{scenario_id}")
async def get_vm_attack_configuration_options(scenario_id: str, architecture: ArchitectureData):
    """
    Get configuration options for a specific attack scenario
    """
    
    try:
        arch_dict = architecture.dict()
        scenarios = vm_engine.get_attack_options(arch_dict)
        
        selected_scenario = next(
            (s for s in scenarios if s["id"] == scenario_id), 
            None
        )
        
        if not selected_scenario:
            raise HTTPException(
                status_code=404,
                detail=f"Attack scenario '{scenario_id}' not found"
            )
        
        return {
            "success": True,
            "scenario": selected_scenario,
            "configurable_parameters": selected_scenario.get("configurable_parameters", {}),
            "recommended_configuration": {
                "intensity": "medium",
                "stealth_level": "normal", 
                "speed": "normal",
                "scope": "multiple_targets"
            },
            "configuration_descriptions": {
                "intensity": {
                    "low": "Gentle attack with lower success probability",
                    "medium": "Balanced attack approach",
                    "high": "Aggressive attack with higher success probability"
                },
                "stealth_level": {
                    "noisy": "Obvious attack easily detected",
                    "normal": "Standard attack signature",
                    "stealthy": "Advanced evasion techniques"
                },
                "speed": {
                    "slow": "Extended timeline for careful approach",
                    "normal": "Standard attack timeline",
                    "fast": "Rapid attack execution"
                },
                "scope": {
                    "single_target": "Focus on one primary component",
                    "multiple_targets": "Attack multiple related components",
                    "full_architecture": "Comprehensive architecture-wide attack"
                }
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get configuration options: {str(e)}"
        )

@app.get("/api/vm-attack-library")
async def get_vm_attack_library():
    """
    Get information about the VM attack library and capabilities
    """
    
    return {
        "success": True,
        "library_info": vm_engine.attack_library,
        "rule_integrations": [
            "OWASP Top 10 2021",
            "MITRE ATT&CK Framework",
            "STRIDE Threat Modeling",
            "Component-Specific Vulnerabilities"
        ],
        "supported_components": list(vm_engine.VM_COMPONENTS.keys()) if hasattr(vm_engine, 'VM_COMPONENTS') else [
            "web_server",
            "database_server", 
            "user_workstation",
            "firewall",
            "domain_controller",
            "load_balancer"
        ],
        "canvas_features": [
            "Real-time node status updates",
            "Compromise level tracking",
            "Attack indicator visualization",
            "Security event timeline"
        ]
    }

@app.post("/api/combined-analysis")
async def perform_combined_analysis(architecture: ArchitectureData):
    """
    Perform combined security analysis and VM attack simulation
    """
    
    try:
        arch_dict = architecture.dict()
        
        # Get VM attack scenarios
        scenarios = vm_engine.get_attack_options(arch_dict)
        
        # Perform analysis on top 3 highest severity scenarios
        high_risk_scenarios = sorted(
            scenarios, 
            key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x["severity"], 0),
            reverse=True
        )[:3]
        
        combined_results = {
            "architecture_analysis": {
                "total_attack_scenarios": len(scenarios),
                "severity_distribution": {
                    "CRITICAL": len([s for s in scenarios if s["severity"] == "CRITICAL"]),
                    "HIGH": len([s for s in scenarios if s["severity"] == "HIGH"]),
                    "MEDIUM": len([s for s in scenarios if s["severity"] == "MEDIUM"]),
                    "LOW": len([s for s in scenarios if s["severity"] == "LOW"])
                }
            },
            "top_risk_scenarios": high_risk_scenarios,
            "vm_attack_readiness": {
                "supported_components": len([n for n in arch_dict.get("nodes", []) if vm_engine.get_component_by_type(n.get("type", ""))]),
                "total_components": len(arch_dict.get("nodes", [])),
                "coverage_percentage": round(
                    len([n for n in arch_dict.get("nodes", []) if vm_engine.get_component_by_type(n.get("type", ""))]) / 
                    max(1, len(arch_dict.get("nodes", []))) * 100, 1
                )
            },
            "recommendations": [
                "Execute top 3 high-risk attack scenarios to validate security posture",
                "Focus on CRITICAL and HIGH severity vulnerabilities first",
                "Use VM attack simulation to test incident response procedures",
                "Implement real-time monitoring for attack indicators identified"
            ]
        }
        
        return {
            "success": True,
            "combined_analysis": combined_results,
            "next_actions": [
                "Select and configure attack scenarios from the top risk list",
                "Execute VM simulations with appropriate intensity settings",
                "Review detailed attack reports and implement mitigations",
                "Use canvas visualization to track security improvements"
            ]
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Combined analysis failed: {str(e)}"
        )

# Legacy endpoint for backward compatibility
@app.post("/api/simulate-attack")
async def simulate_attack_legacy(request: dict):
    """
    Legacy endpoint that redirects to VM attack system
    """
    
    try:
        # Convert legacy format to new format
        architecture_data = ArchitectureData(**request.get("architecture", {}))
        
        # Get scenarios and use first available
        scenarios = vm_engine.get_attack_options(architecture_data.dict())
        if not scenarios:
            raise HTTPException(status_code=400, detail="No attack scenarios available for this architecture")
        
        # Use first scenario with default configuration
        default_config = AttackConfigurationData()
        vm_request = VMAttackRequest(
            architecture=architecture_data,
            attack_scenario_id=scenarios[0]["id"],
            configuration=default_config
        )
        
        # Execute and return in legacy format
        result = await execute_vm_attack(vm_request)
        
        # Convert to legacy response format
        return {
            "simulation_id": result.simulation_id,
            "success": result.success,
            "error": result.error,
            "summary": {
                "components_compromised": len(result.simulation_results.get("total_impact", {}).get("compromised_components", [])) if result.simulation_results else 0,
                "attack_scenario": result.attack_scenario["name"] if result.attack_scenario else "Unknown"
            } if result.success else None,
            "detailed_report": result.detailed_report
        }
        
    except Exception as e:
        return {
            "simulation_id": "",
            "success": False,
            "error": f"Legacy simulation failed: {str(e)}"
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)