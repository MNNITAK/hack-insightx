"""
Virtual Cybersecurity Sandbox - API Endpoints
FastAPI endpoints for sandbox orchestration, attack simulation, and defense monitoring
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict, List, Any, Optional
import json
import time
from datetime import datetime

from .container_orchestrator import RuleBasedContainerOrchestrator
from .attack_simulator import RuleBasedAttackSimulator
from .defense_agent import RuleBasedDefenseAgent

# Initialize sandbox components with error handling
try:
    orchestrator = RuleBasedContainerOrchestrator()
    attack_simulator = RuleBasedAttackSimulator(orchestrator)
    defense_agent = RuleBasedDefenseAgent(orchestrator, attack_simulator)
    print("✅ Sandbox API components initialized")
except Exception as e:
    print(f"⚠️  Sandbox API initialization error: {e}")
    # Create mock instances for graceful fallback
    orchestrator = None
    attack_simulator = None 
    defense_agent = None

# Pydantic models for API requests
class ArchitectureDeployRequest(BaseModel):
    architecture: Dict[str, Any]
    security_level: str = "vulnerable"  # "vulnerable", "hardened"
    enable_monitoring: bool = True

class AttackRequest(BaseModel):
    sandbox_id: str
    attack_id: str
    target_container_id: str
    parameters: Optional[Dict[str, Any]] = None

class AttackScenarioRequest(BaseModel):
    sandbox_id: str
    scenario_name: str
    target_components: Optional[List[str]] = None

class SandboxAPI:
    """API endpoints for Virtual Cybersecurity Sandbox"""
    
    def __init__(self, app: FastAPI):
        self.app = app
        self.setup_routes()

    def setup_routes(self):
        """Setup all API routes"""
        
        @self.app.post("/api/sandbox/deploy")
        async def deploy_sandbox(request: ArchitectureDeployRequest, background_tasks: BackgroundTasks):
            """Deploy architecture as live container sandbox"""
            try:
                print(f"🚀 API: Deploying sandbox with {len(request.architecture.get('nodes', []))} components")
                
                # Deploy sandbox
                sandbox_id = orchestrator.deploy_architecture_sandbox(
                    request.architecture,
                    request.security_level
                )
                
                # Start monitoring if requested
                if request.enable_monitoring:
                    background_tasks.add_task(defense_agent.start_monitoring, sandbox_id)
                
                return {
                    "success": True,
                    "sandbox_id": sandbox_id,
                    "status": "deployed",
                    "monitoring_enabled": request.enable_monitoring,
                    "containers_deployed": len(orchestrator.sandbox_environments[sandbox_id].containers),
                    "deployment_time": datetime.now().isoformat()
                }
                
            except Exception as e:
                print(f"❌ API: Failed to deploy sandbox: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/sandbox/{sandbox_id}/status")
        async def get_sandbox_status(sandbox_id: str):
            """Get current status of sandbox environment"""
            try:
                status = orchestrator.get_sandbox_status(sandbox_id)
                
                if "error" in status:
                    raise HTTPException(status_code=404, detail=status["error"])
                
                # Add security monitoring data if available
                if defense_agent.monitoring_active:
                    security_dashboard = defense_agent.get_security_dashboard()
                    status["security_monitoring"] = security_dashboard
                
                return status
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/api/sandbox/{sandbox_id}/attack")
        async def execute_attack(sandbox_id: str, request: AttackRequest):
            """Execute single attack against target container"""
            try:
                print(f"🎯 API: Executing attack {request.attack_id} against {request.target_container_id}")
                
                execution_id = attack_simulator.execute_single_attack(
                    sandbox_id,
                    request.attack_id,
                    request.target_container_id,
                    request.parameters
                )
                
                return {
                    "success": True,
                    "execution_id": execution_id,
                    "attack_type": request.attack_id,
                    "target": request.target_container_id,
                    "status": "started",
                    "start_time": datetime.now().isoformat()
                }
                
            except Exception as e:
                print(f"❌ API: Failed to execute attack: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/api/sandbox/{sandbox_id}/attack-scenario")
        async def execute_attack_scenario(sandbox_id: str, request: AttackScenarioRequest):
            """Execute complete attack scenario"""
            try:
                print(f"🎬 API: Starting attack scenario {request.scenario_name}")
                
                scenario_id = attack_simulator.execute_attack_scenario(
                    sandbox_id,
                    request.scenario_name,
                    request.target_components
                )
                
                return {
                    "success": True,
                    "scenario_id": scenario_id,
                    "scenario_name": request.scenario_name,
                    "status": "started",
                    "start_time": datetime.now().isoformat()
                }
                
            except Exception as e:
                print(f"❌ API: Failed to execute scenario: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/attack/{execution_id}/status")
        async def get_attack_status(execution_id: str):
            """Get status of specific attack execution"""
            try:
                status = attack_simulator.get_attack_status(execution_id)
                
                if "error" in status:
                    raise HTTPException(status_code=404, detail=status["error"])
                
                return status
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/scenario/{scenario_id}/status")
        async def get_scenario_status(scenario_id: str):
            """Get status of attack scenario"""
            try:
                status = attack_simulator.get_scenario_status(scenario_id)
                
                if "error" in status:
                    raise HTTPException(status_code=404, detail=status["error"])
                
                return status
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/sandbox/{sandbox_id}/security-events")
        async def get_security_events(sandbox_id: str, limit: int = 50):
            """Get recent security events for sandbox"""
            try:
                # Get recent events from defense agent
                all_events = list(defense_agent.security_events.values())
                
                # Filter by time and limit
                recent_events = sorted(all_events, key=lambda x: x.timestamp, reverse=True)[:limit]
                
                return {
                    "sandbox_id": sandbox_id,
                    "total_events": len(all_events),
                    "events_returned": len(recent_events),
                    "events": [
                        {
                            "event_id": event.event_id,
                            "timestamp": event.timestamp,
                            "type": event.event_type,
                            "severity": event.severity,
                            "container": event.target_container,
                            "description": event.description,
                            "status": event.status
                        }
                        for event in recent_events
                    ]
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/security-event/{event_id}")
        async def get_security_event_details(event_id: str):
            """Get detailed information about specific security event"""
            try:
                details = defense_agent.get_event_details(event_id)
                
                if "error" in details:
                    raise HTTPException(status_code=404, detail=details["error"])
                
                return details
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/api/sandbox/{sandbox_id}/start-monitoring")
        async def start_monitoring(sandbox_id: str):
            """Start security monitoring for sandbox"""
            try:
                defense_agent.start_monitoring(sandbox_id)
                
                return {
                    "success": True,
                    "sandbox_id": sandbox_id,
                    "monitoring_status": "active",
                    "start_time": datetime.now().isoformat()
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/api/sandbox/stop-monitoring")
        async def stop_monitoring():
            """Stop security monitoring"""
            try:
                defense_agent.stop_monitoring()
                
                return {
                    "success": True,
                    "monitoring_status": "inactive",
                    "stop_time": datetime.now().isoformat()
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/security-dashboard")
        async def get_security_dashboard():
            """Get real-time security monitoring dashboard"""
            try:
                dashboard = defense_agent.get_security_dashboard()
                return dashboard
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.delete("/api/sandbox/{sandbox_id}")
        async def destroy_sandbox(sandbox_id: str):
            """Destroy sandbox and clean up all resources"""
            try:
                print(f"🧹 API: Destroying sandbox {sandbox_id}")
                
                success = orchestrator.destroy_sandbox(sandbox_id)
                
                if not success:
                    raise HTTPException(status_code=500, detail="Failed to destroy sandbox")
                
                return {
                    "success": True,
                    "sandbox_id": sandbox_id,
                    "status": "destroyed",
                    "destroy_time": datetime.now().isoformat()
                }
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/sandbox/list")
        async def list_sandboxes():
            """List all active sandbox environments"""
            try:
                sandboxes = []
                
                for sandbox_id, env in orchestrator.sandbox_environments.items():
                    sandbox_info = {
                        "sandbox_id": sandbox_id,
                        "architecture_id": env.architecture_id,
                        "status": env.status,
                        "container_count": len(env.containers),
                        "created_at": env.created_at,
                        "last_activity": env.last_activity
                    }
                    sandboxes.append(sandbox_info)
                
                return {
                    "total_sandboxes": len(sandboxes),
                    "sandboxes": sandboxes
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/attack-catalog")
        async def get_attack_catalog():
            """Get available attack types and scenarios"""
            try:
                return {
                    "attack_types": attack_simulator.attack_catalog,
                    "attack_scenarios": attack_simulator.ATTACK_SCENARIOS,
                    "penetration_tools": list(attack_simulator.PENETRATION_TOOLS.keys())
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/security-rules")
        async def get_security_rules():
            """Get available detection and response rules"""
            try:
                return {
                    "detection_rules": defense_agent.DETECTION_RULES,
                    "response_actions": list(defense_agent.RESPONSE_ACTIONS.keys())
                }
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.post("/api/sandbox/{sandbox_id}/network-visualization")
        async def get_network_visualization(sandbox_id: str):
            """Get real-time network topology for 3D visualization"""
            try:
                sandbox_env = orchestrator.sandbox_environments.get(sandbox_id)
                if not sandbox_env:
                    raise HTTPException(status_code=404, detail="Sandbox not found")
                
                # Build network topology
                nodes = []
                edges = []
                
                # Add container nodes
                for node_id, container in sandbox_env.containers.items():
                    node_status = "healthy"  # Would check actual container health
                    
                    # Check for recent security events
                    recent_events = [
                        event for event in defense_agent.security_events.values()
                        if event.target_container == container.container_name and
                        defense_agent._is_recent_event(event.timestamp, minutes=5)
                    ]
                    
                    if recent_events:
                        high_severity = any(event.severity in ["high", "critical"] for event in recent_events)
                        node_status = "under_attack" if high_severity else "suspicious"
                    
                    nodes.append({
                        "id": node_id,
                        "name": container.container_name,
                        "type": container.component_type,
                        "status": node_status,
                        "ip_address": "192.168.1.100",  # Would get actual IP
                        "security_events": len(recent_events),
                        "position": {"x": 0, "y": 0, "z": 0}  # Would calculate 3D position
                    })
                
                # Add network connections
                # This would be derived from actual network traffic analysis
                for i, node1 in enumerate(nodes):
                    for j, node2 in enumerate(nodes[i+1:], i+1):
                        # Simulate network connections
                        edges.append({
                            "source": node1["id"],
                            "target": node2["id"],
                            "traffic_volume": 1024,  # bytes/sec
                            "connection_type": "tcp",
                            "security_status": "normal"
                        })
                
                return {
                    "sandbox_id": sandbox_id,
                    "timestamp": datetime.now().isoformat(),
                    "topology": {
                        "nodes": nodes,
                        "edges": edges
                    },
                    "attack_indicators": {
                        "active_attacks": len([node for node in nodes if node["status"] == "under_attack"]),
                        "suspicious_nodes": len([node for node in nodes if node["status"] == "suspicious"])
                    }
                }
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        @self.app.get("/api/sandbox/{sandbox_id}/metrics")
        async def get_sandbox_metrics(sandbox_id: str):
            """Get comprehensive sandbox metrics for monitoring"""
            try:
                sandbox_env = orchestrator.sandbox_environments.get(sandbox_id)
                if not sandbox_env:
                    raise HTTPException(status_code=404, detail="Sandbox not found")
                
                # Collect metrics from all containers
                container_metrics = {}
                for node_id, container in sandbox_env.containers.items():
                    # Get container stats (CPU, memory, network)
                    # This would be real Docker stats
                    container_metrics[node_id] = {
                        "cpu_percent": 25.5,
                        "memory_usage_mb": 128,
                        "memory_percent": 12.8,
                        "network_rx_bytes": 1024000,
                        "network_tx_bytes": 512000,
                        "uptime_seconds": 3600,
                        "health_status": "healthy"
                    }
                
                # Security metrics
                recent_events = [
                    event for event in defense_agent.security_events.values()
                    if defense_agent._is_recent_event(event.timestamp, minutes=60)
                ]
                
                security_metrics = {
                    "events_last_hour": len(recent_events),
                    "critical_events": sum(1 for e in recent_events if e.severity == "critical"),
                    "attacks_detected": sum(1 for e in recent_events if "attack" in e.event_type),
                    "actions_taken": len([a for a in defense_agent.defense_actions.values() 
                                        if defense_agent._is_recent_event(a.execution_time, minutes=60)])
                }
                
                return {
                    "sandbox_id": sandbox_id,
                    "timestamp": datetime.now().isoformat(),
                    "container_metrics": container_metrics,
                    "security_metrics": security_metrics,
                    "overall_health": "good",  # Would calculate based on metrics
                    "threat_level": defense_agent._calculate_threat_level(recent_events)
                }
                
            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

# Initialize API routes when this module is imported
def setup_sandbox_api(app: FastAPI):
    """Setup sandbox API routes on FastAPI app"""
    sandbox_api = SandboxAPI(app)
    return sandbox_api