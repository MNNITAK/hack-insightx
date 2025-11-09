"""
ENHANCED VM ATTACK ENGINE WITH RULE INTEGRATION
==============================================

Integrates VM attack simulation with existing OWASP, MITRE, and STRIDE rules
to provide comprehensive attack scenario library and real-time canvas updates.
"""

import json
import sys
from datetime import datetime
from typing import Dict, Any, List, Optional
import importlib.util
import os

# Import existing rule engines
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend', 'rules'))

try:
    from backend.rules.owasp_rules import OWASPRuleEngine, SecurityFinding
    from backend.rules.mitre_attack_mapper import AttackTechnique, AttackTactic
    from backend.rules.stride_rules import Threat, ThreatCategory
except ImportError:
    print("Warning: Could not import existing rule engines. Creating mock classes...")
    # Create mock classes for standalone operation
    class SecurityFinding:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    
    class OWASPRuleEngine:
        def analyze_architecture(self, arch):
            return []
    
    class AttackTechnique:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    
    class AttackTactic:
        INITIAL_ACCESS = "Initial Access"
        PRIVILEGE_ESCALATION = "Privilege Escalation"
        LATERAL_MOVEMENT = "Lateral Movement"
        COLLECTION = "Collection"
        EXFILTRATION = "Exfiltration"
    
    class Threat:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    
    class ThreatCategory:
        SPOOFING = "Spoofing"
        TAMPERING = "Tampering"
        INFORMATION_DISCLOSURE = "Information Disclosure"

from attack_simulation import AttackSimulationEngine
from vm_components import VM_COMPONENTS, get_component_by_type

class EnhancedVMAttackEngine(AttackSimulationEngine):
    """
    Enhanced attack simulation engine that integrates with existing rule systems
    """
    
    def __init__(self):
        super().__init__()
        self.owasp_engine = OWASPRuleEngine()
        self.attack_library = self._build_attack_library()
        self.canvas_state = {}
    
    def get_attack_options(self, architecture: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get 20+ attack options based on architecture vulnerabilities using existing rules
        """
        
        # Analyze architecture with existing rule engines
        owasp_findings = self.owasp_engine.analyze_architecture(architecture)
        
        # Generate attack scenarios based on findings
        attack_scenarios = []
        
        # 1. OWASP-based attacks
        owasp_attacks = self._generate_owasp_attacks(owasp_findings, architecture)
        attack_scenarios.extend(owasp_attacks)
        
        # 2. MITRE ATT&CK-based attacks
        mitre_attacks = self._generate_mitre_attacks(architecture)
        attack_scenarios.extend(mitre_attacks)
        
        # 3. STRIDE-based attacks
        stride_attacks = self._generate_stride_attacks(architecture)
        attack_scenarios.extend(stride_attacks)
        
        # 4. Component-specific attacks
        component_attacks = self._generate_component_attacks(architecture)
        attack_scenarios.extend(component_attacks)
        
        # Ensure we have at least 20 options
        while len(attack_scenarios) < 20:
            attack_scenarios.extend(self._get_generic_attacks(architecture))
            break
        
        return attack_scenarios[:25]  # Return top 25 scenarios
    
    def _generate_owasp_attacks(self, findings: List[SecurityFinding], architecture: Dict) -> List[Dict]:
        """Generate attack scenarios based on OWASP findings"""
        
        attacks = []
        
        for finding in findings:
            if hasattr(finding, 'owasp_category'):
                attack = {
                    "id": f"owasp_{finding.rule_id.lower().replace('-', '_')}",
                    "name": f"OWASP {finding.title}",
                    "description": finding.description,
                    "category": "OWASP Top 10",
                    "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                    "target_components": finding.affected_components,
                    "estimated_duration": self._estimate_duration_from_severity(finding.severity),
                    "success_probability": self._calculate_success_probability_from_finding(finding),
                    "configurable_parameters": {
                        "intensity": ["low", "medium", "high"],
                        "stealth_level": ["noisy", "normal", "stealthy"],
                        "speed": ["slow", "normal", "fast"],
                        "scope": ["single_target", "multiple_targets", "full_architecture"]
                    },
                    "attack_phases": self._build_owasp_attack_phases(finding),
                    "rule_mapping": {
                        "owasp_rule": finding.rule_id,
                        "cwe_id": getattr(finding, 'cwe_id', ''),
                        "cvss_score": getattr(finding, 'cvss_score', 0)
                    },
                    "detection_likelihood": self._estimate_detection_likelihood_from_finding(finding),
                    "business_impact": getattr(finding, 'business_impact', 'Medium impact to business operations'),
                    "required_privileges": getattr(finding, 'privileges_required', 'None'),
                    "prerequisites": self._get_attack_prerequisites(finding)
                }
                attacks.append(attack)
        
        return attacks
    
    def _generate_mitre_attacks(self, architecture: Dict) -> List[Dict]:
        """Generate MITRE ATT&CK-based attack scenarios"""
        
        attacks = []
        nodes = architecture.get('nodes', [])
        
        # Map components to MITRE techniques
        mitre_scenarios = [
            {
                "technique": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": AttackTactic.INITIAL_ACCESS,
                "targets": ["web_server", "api_server"],
                "description": "Exploit vulnerabilities in public-facing web applications"
            },
            {
                "technique": "T1078",
                "name": "Valid Accounts",
                "tactic": AttackTactic.INITIAL_ACCESS,
                "targets": ["user_workstation", "database"],
                "description": "Use legitimate credentials to gain access"
            },
            {
                "technique": "T1055",
                "name": "Process Injection",
                "tactic": AttackTactic.PRIVILEGE_ESCALATION,
                "targets": ["web_server", "user_workstation"],
                "description": "Inject malicious code into legitimate processes"
            },
            {
                "technique": "T1021",
                "name": "Remote Services",
                "tactic": AttackTactic.LATERAL_MOVEMENT,
                "targets": ["user_workstation", "database_server"],
                "description": "Use remote services to move laterally"
            },
            {
                "technique": "T1005",
                "name": "Data from Local System",
                "tactic": AttackTactic.COLLECTION,
                "targets": ["database", "user_workstation"],
                "description": "Collect data from local systems"
            },
            {
                "technique": "T1041",
                "name": "Exfiltration Over C2 Channel",
                "tactic": AttackTactic.EXFILTRATION,
                "targets": ["database", "web_server"],
                "description": "Exfiltrate data over command and control channel"
            }
        ]
        
        for scenario in mitre_scenarios:
            # Check if architecture has target components
            available_targets = [n for n in nodes if any(target in n.get('type', '').lower() for target in scenario["targets"])]
            
            if available_targets:
                attack = {
                    "id": f"mitre_{scenario['technique'].lower()}",
                    "name": f"MITRE {scenario['technique']}: {scenario['name']}",
                    "description": scenario["description"],
                    "category": "MITRE ATT&CK",
                    "severity": "HIGH",
                    "target_components": [t.get('id') for t in available_targets],
                    "estimated_duration": "60-120 minutes",
                    "success_probability": 0.75,
                    "configurable_parameters": {
                        "stealth_level": ["low", "medium", "high"],
                        "persistence_level": ["temporary", "short_term", "long_term"],
                        "lateral_movement": ["none", "limited", "extensive"],
                        "data_collection": ["minimal", "moderate", "comprehensive"]
                    },
                    "attack_phases": self._build_mitre_attack_phases(scenario),
                    "rule_mapping": {
                        "mitre_technique": scenario["technique"],
                        "mitre_tactic": scenario["tactic"],
                        "attack_pattern": scenario["name"]
                    },
                    "detection_likelihood": "MEDIUM",
                    "business_impact": "Potential system compromise and data breach",
                    "required_privileges": "User" if "workstation" in str(scenario["targets"]) else "None",
                    "prerequisites": [f"Access to {', '.join(scenario['targets'])}"]
                }
                attacks.append(attack)
        
        return attacks
    
    def _generate_stride_attacks(self, architecture: Dict) -> List[Dict]:
        """Generate STRIDE-based threat scenarios"""
        
        attacks = []
        nodes = architecture.get('nodes', [])
        connections = architecture.get('connections', [])
        
        stride_scenarios = [
            {
                "threat": ThreatCategory.SPOOFING,
                "name": "Identity Spoofing Attack",
                "targets": ["user_workstation", "auth_server"],
                "description": "Spoof user identities to gain unauthorized access"
            },
            {
                "threat": ThreatCategory.TAMPERING,
                "name": "Data Tampering Attack", 
                "targets": ["database", "web_server"],
                "description": "Modify data in transit or at rest"
            },
            {
                "threat": ThreatCategory.INFORMATION_DISCLOSURE,
                "name": "Information Disclosure Attack",
                "targets": ["database", "api_server"],
                "description": "Extract sensitive information from systems"
            }
        ]
        
        for scenario in stride_scenarios:
            available_targets = [n for n in nodes if any(target in n.get('type', '').lower() for target in scenario["targets"])]
            
            if available_targets:
                attack = {
                    "id": f"stride_{scenario['threat'].value.lower().replace(' ', '_')}",
                    "name": f"STRIDE {scenario['name']}",
                    "description": scenario["description"],
                    "category": "STRIDE Threat Model",
                    "severity": "MEDIUM",
                    "target_components": [t.get('id') for t in available_targets],
                    "estimated_duration": "45-90 minutes",
                    "success_probability": 0.65,
                    "configurable_parameters": {
                        "threat_level": ["low", "medium", "high"],
                        "attack_sophistication": ["basic", "intermediate", "advanced"],
                        "target_scope": ["single", "multiple", "architecture_wide"]
                    },
                    "attack_phases": self._build_stride_attack_phases(scenario),
                    "rule_mapping": {
                        "stride_category": scenario["threat"],
                        "threat_type": scenario["name"]
                    },
                    "detection_likelihood": "MEDIUM",
                    "business_impact": "Data confidentiality, integrity, or availability compromise",
                    "required_privileges": "None to User",
                    "prerequisites": [f"Network access to {', '.join(scenario['targets'])}"]
                }
                attacks.append(attack)
        
        return attacks
    
    def _generate_component_attacks(self, architecture: Dict) -> List[Dict]:
        """Generate component-specific attacks based on VM components"""
        
        attacks = []
        nodes = architecture.get('nodes', [])
        
        component_scenarios = [
            {
                "component": "web_server",
                "attacks": [
                    {
                        "name": "Web Server SQL Injection",
                        "type": "sql_injection",
                        "description": "Exploit SQL injection vulnerabilities in web applications"
                    },
                    {
                        "name": "Web Server File Upload Attack",
                        "type": "file_upload",
                        "description": "Upload malicious files through web application"
                    }
                ]
            },
            {
                "component": "database",
                "attacks": [
                    {
                        "name": "Database Credential Brute Force",
                        "type": "brute_force",
                        "description": "Brute force database authentication credentials"
                    },
                    {
                        "name": "Database Data Exfiltration",
                        "type": "data_exfiltration",
                        "description": "Extract sensitive data from database systems"
                    }
                ]
            },
            {
                "component": "user_workstation",
                "attacks": [
                    {
                        "name": "Workstation Privilege Escalation",
                        "type": "privilege_escalation",
                        "description": "Escalate privileges on user workstation"
                    },
                    {
                        "name": "Workstation Lateral Movement",
                        "type": "lateral_movement",
                        "description": "Use compromised workstation to access other systems"
                    }
                ]
            }
        ]
        
        for comp_scenario in component_scenarios:
            matching_nodes = [n for n in nodes if comp_scenario["component"] in n.get('type', '').lower()]
            
            if matching_nodes:
                for attack_def in comp_scenario["attacks"]:
                    attack = {
                        "id": f"component_{comp_scenario['component']}_{attack_def['type']}",
                        "name": attack_def["name"],
                        "description": attack_def["description"],
                        "category": "Component-Specific",
                        "severity": "HIGH",
                        "target_components": [n.get('id') for n in matching_nodes],
                        "estimated_duration": "30-60 minutes",
                        "success_probability": 0.70,
                        "configurable_parameters": {
                            "attack_intensity": ["gentle", "normal", "aggressive"],
                            "detection_avoidance": ["none", "basic", "advanced"],
                            "payload_type": ["standard", "custom", "zero_day"]
                        },
                        "attack_phases": self._build_component_attack_phases(attack_def),
                        "rule_mapping": {
                            "component_type": comp_scenario["component"],
                            "attack_type": attack_def["type"]
                        },
                        "detection_likelihood": "MEDIUM",
                        "business_impact": f"Compromise of {comp_scenario['component']} systems",
                        "required_privileges": "None to User",
                        "prerequisites": [f"Network access to {comp_scenario['component']}"]
                    }
                    attacks.append(attack)
        
        return attacks
    
    def _get_generic_attacks(self, architecture: Dict) -> List[Dict]:
        """Generate generic attack scenarios to reach 20+ options"""
        
        return [
            {
                "id": "generic_phishing",
                "name": "Phishing Campaign",
                "description": "Social engineering attack targeting user credentials",
                "category": "Social Engineering",
                "severity": "MEDIUM",
                "target_components": ["users"],
                "estimated_duration": "2-4 hours",
                "success_probability": 0.60,
                "configurable_parameters": {
                    "email_sophistication": ["basic", "intermediate", "advanced"],
                    "target_scope": ["single_user", "department", "organization"],
                    "payload_type": ["credential_theft", "malware", "information_gathering"]
                },
                "attack_phases": [
                    {"name": "Target Research", "duration": "30 minutes"},
                    {"name": "Email Crafting", "duration": "45 minutes"},
                    {"name": "Campaign Launch", "duration": "60 minutes"},
                    {"name": "Credential Harvesting", "duration": "45 minutes"}
                ],
                "detection_likelihood": "LOW",
                "business_impact": "User credential compromise"
            },
            {
                "id": "generic_ddos",
                "name": "Distributed Denial of Service",
                "description": "Overwhelm services with traffic to cause availability issues",
                "category": "Availability Attack",
                "severity": "HIGH",
                "target_components": ["all_public_facing"],
                "estimated_duration": "1-6 hours",
                "success_probability": 0.85,
                "configurable_parameters": {
                    "attack_volume": ["low", "medium", "high"],
                    "attack_duration": ["short", "medium", "sustained"],
                    "attack_type": ["volumetric", "protocol", "application_layer"]
                },
                "attack_phases": [
                    {"name": "Target Reconnaissance", "duration": "15 minutes"},
                    {"name": "Botnet Preparation", "duration": "30 minutes"},
                    {"name": "Attack Launch", "duration": "Variable"},
                    {"name": "Impact Assessment", "duration": "15 minutes"}
                ],
                "detection_likelihood": "HIGH",
                "business_impact": "Service unavailability and revenue loss"
            }
        ]
    
    def execute_vm_attack_with_canvas_updates(self, architecture: Dict, attack_scenario: Dict, config: Dict) -> Dict:
        """
        Execute VM attack with real-time canvas node status updates
        """
        
        # Initialize canvas state
        self._initialize_canvas_state(architecture)
        
        # Configure attack based on user parameters
        configured_attack = self._configure_attack(attack_scenario, config)
        
        # Execute attack with real-time updates
        result = self._execute_attack_with_updates(architecture, configured_attack)
        
        return result
    
    def _initialize_canvas_state(self, architecture: Dict):
        """Initialize canvas node states"""
        
        self.canvas_state = {}
        for node in architecture.get('nodes', []):
            self.canvas_state[node.get('id')] = {
                "status": "safe",
                "compromise_level": 0,
                "last_updated": datetime.now().isoformat(),
                "attack_indicators": [],
                "security_events": []
            }
    
    def _configure_attack(self, scenario: Dict, config: Dict) -> Dict:
        """Configure attack scenario based on user parameters"""
        
        configured = scenario.copy()
        
        # Adjust based on configuration
        if config.get('intensity') == 'high':
            configured['success_probability'] = min(1.0, scenario['success_probability'] * 1.2)
            configured['estimated_duration'] = self._reduce_duration(scenario['estimated_duration'])
        elif config.get('intensity') == 'low':
            configured['success_probability'] = scenario['success_probability'] * 0.8
            configured['estimated_duration'] = self._extend_duration(scenario['estimated_duration'])
        
        if config.get('stealth_level') == 'stealthy':
            configured['detection_likelihood'] = "LOW"
        elif config.get('stealth_level') == 'noisy':
            configured['detection_likelihood'] = "HIGH"
        
        return configured
    
    def _execute_attack_with_updates(self, architecture: Dict, attack: Dict) -> Dict:
        """Execute attack with real-time canvas updates"""
        
        # Convert to format expected by base simulation engine
        attack_data = {
            "name": attack["name"],
            "description": attack["description"],
            "target": attack["target_components"],
            "attack_path": attack["attack_phases"]
        }
        
        # Execute using base engine
        result = self.analyze_attack_on_architecture_dict(architecture, attack_data)
        
        # Update canvas states based on results
        self._update_canvas_from_results(result)
        
        # Add canvas state to result
        result["canvas_state"] = self.canvas_state
        result["attack_configuration"] = attack
        
        return result
    
    def analyze_attack_on_architecture_dict(self, architecture: Dict, attack: Dict) -> Dict:
        """Analyze attack against architecture using dictionaries instead of files"""
        
        # Create simulation result structure
        simulation_result = {
            "simulation_id": f"vm_sim_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "architecture_name": architecture.get("name", architecture.get("metadata", {}).get("company_name", "Unknown")),
            "attack_name": attack.get("name", "VM Attack Simulation"),
            "timestamp": datetime.now().isoformat(),
            "attack_phases": [],
            "total_impact": {
                "compromised_components": [],
                "breached_data": [],
                "exposed_credentials": [],
                "lateral_movement_paths": [],
                "business_impact_summary": ""
            },
            "security_gaps_identified": [],
            "post_attack_analysis": {}
        }
        
        # Identify target components
        target_components = self._identify_target_components(architecture, attack)
        
        # Simulate attack execution
        attack_path = attack.get("attack_path", [])
        
        for phase_idx, phase in enumerate(attack_path):
            phase_result = self._simulate_attack_phase(
                phase, 
                target_components, 
                architecture,
                phase_idx
            )
            
            simulation_result["attack_phases"].append(phase_result)
            self._update_total_impact(simulation_result["total_impact"], phase_result)
        
        # Generate post-attack analysis
        simulation_result["post_attack_analysis"] = self._generate_post_attack_analysis(
            simulation_result, architecture, attack
        )
        
        # Identify security gaps
        simulation_result["security_gaps_identified"] = self._identify_security_gaps(
            simulation_result, architecture
        )
        
        return simulation_result
    
    def _update_canvas_from_results(self, results: Dict):
        """Update canvas state based on attack simulation results"""
        
        for phase in results.get("attack_phases", []):
            for compromise in phase.get("successful_compromises", []):
                component_id = compromise.get("target_component")
                if component_id in self.canvas_state:
                    self.canvas_state[component_id]["status"] = "compromised"
                    self.canvas_state[component_id]["compromise_level"] = self._calculate_compromise_level(compromise)
                    self.canvas_state[component_id]["last_updated"] = datetime.now().isoformat()
                    self.canvas_state[component_id]["attack_indicators"].append({
                        "type": compromise.get("attack_vector", "unknown"),
                        "severity": compromise.get("impact_severity", "medium"),
                        "timestamp": datetime.now().isoformat()
                    })
        
        # Mark components under attack but not yet compromised
        for phase in results.get("attack_phases", []):
            for attempt in phase.get("failed_attempts", []):
                # Extract component name from attempt description if available
                target = attempt.get("target", "unknown")
                for node_id in self.canvas_state:
                    if target in node_id or node_id in target:
                        if self.canvas_state[node_id]["status"] == "safe":
                            self.canvas_state[node_id]["status"] = "under_attack"
                            self.canvas_state[node_id]["last_updated"] = datetime.now().isoformat()
    
    def get_canvas_status(self) -> Dict:
        """Get current canvas node status for real-time updates"""
        return self.canvas_state
    
    # Helper methods for attack phase building
    def _build_owasp_attack_phases(self, finding) -> List[Dict]:
        """Build attack phases from OWASP finding"""
        return [
            {
                "name": "Vulnerability Discovery",
                "type": "reconnaissance",
                "description": f"Discover {finding.title} vulnerability",
                "estimated_time": "15 minutes"
            },
            {
                "name": "Exploit Development",
                "type": "weaponization",
                "description": f"Develop exploit for {finding.rule_id}",
                "estimated_time": "30 minutes"
            },
            {
                "name": "Attack Execution",
                "type": self._map_owasp_to_attack_type(finding),
                "description": f"Execute attack against {', '.join(finding.affected_components)}",
                "estimated_time": "20 minutes"
            }
        ]
    
    def _build_mitre_attack_phases(self, scenario) -> List[Dict]:
        """Build attack phases from MITRE scenario"""
        return [
            {
                "name": f"{scenario['tactic']} - {scenario['name']}",
                "type": self._map_mitre_to_attack_type(scenario['technique']),
                "description": scenario['description'],
                "estimated_time": "30 minutes"
            }
        ]
    
    def _build_stride_attack_phases(self, scenario) -> List[Dict]:
        """Build attack phases from STRIDE scenario"""
        return [
            {
                "name": f"{scenario['threat']} Attack",
                "type": self._map_stride_to_attack_type(scenario['threat']),
                "description": scenario['description'],
                "estimated_time": "45 minutes"
            }
        ]
    
    def _build_component_attack_phases(self, attack_def) -> List[Dict]:
        """Build attack phases from component attack definition"""
        return [
            {
                "name": attack_def['name'],
                "type": attack_def['type'],
                "description": attack_def['description'],
                "estimated_time": "30 minutes"
            }
        ]
    
    # Mapping functions
    def _map_owasp_to_attack_type(self, finding) -> str:
        """Map OWASP finding to attack type"""
        mapping = {
            "injection": "sql_injection",
            "access_control": "privilege_escalation",
            "cryptographic": "credential_theft",
            "misconfiguration": "reconnaissance",
            "auth": "brute_force"
        }
        
        rule_id = finding.rule_id.lower()
        for key, attack_type in mapping.items():
            if key in rule_id:
                return attack_type
        
        return "unknown"
    
    def _map_mitre_to_attack_type(self, technique) -> str:
        """Map MITRE technique to attack type"""
        mapping = {
            "T1190": "sql_injection",
            "T1078": "credential_theft",
            "T1055": "privilege_escalation",
            "T1021": "lateral_movement",
            "T1005": "data_exfiltration",
            "T1041": "data_exfiltration"
        }
        
        return mapping.get(technique, "unknown")
    
    def _map_stride_to_attack_type(self, threat) -> str:
        """Map STRIDE threat to attack type"""
        mapping = {
            ThreatCategory.SPOOFING: "credential_theft",
            ThreatCategory.TAMPERING: "privilege_escalation",
            ThreatCategory.INFORMATION_DISCLOSURE: "data_exfiltration"
        }
        
        return mapping.get(threat, "unknown")
    
    def _estimate_duration_from_severity(self, severity) -> str:
        """Estimate attack duration from severity"""
        severity_str = severity.value if hasattr(severity, 'value') else str(severity)
        
        mapping = {
            "CRITICAL": "15-30 minutes",
            "HIGH": "30-60 minutes", 
            "MEDIUM": "60-120 minutes",
            "LOW": "120-240 minutes"
        }
        
        return mapping.get(severity_str.upper(), "60-120 minutes")
    
    def _calculate_success_probability_from_finding(self, finding) -> float:
        """Calculate success probability from security finding"""
        severity_str = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
        
        mapping = {
            "CRITICAL": 0.95,
            "HIGH": 0.80,
            "MEDIUM": 0.65,
            "LOW": 0.40
        }
        
        return mapping.get(severity_str.upper(), 0.65)
    
    def _estimate_detection_likelihood_from_finding(self, finding) -> str:
        """Estimate detection likelihood from finding"""
        confidence = getattr(finding, 'confidence', 'medium')
        
        mapping = {
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW"
        }
        
        return mapping.get(confidence.lower(), "MEDIUM")
    
    def _get_attack_prerequisites(self, finding) -> List[str]:
        """Get attack prerequisites from finding"""
        return [
            f"Access to {', '.join(finding.affected_components)}",
            "Network connectivity to target",
            "Basic attack tools"
        ]
    
    def _calculate_compromise_level(self, compromise) -> int:
        """Calculate compromise level (0-100)"""
        severity = compromise.get("impact_severity", "MEDIUM")
        
        mapping = {
            "CRITICAL": 90,
            "HIGH": 70,
            "MEDIUM": 50,
            "LOW": 30
        }
        
        return mapping.get(severity, 50)
    
    def _reduce_duration(self, duration: str) -> str:
        """Reduce duration for high intensity attacks"""
        # Simple string manipulation - in practice would parse and recalculate
        return duration.replace("60-120", "30-60").replace("30-60", "15-30")
    
    def _extend_duration(self, duration: str) -> str:
        """Extend duration for low intensity attacks"""
        return duration.replace("30-60", "60-120").replace("15-30", "30-60")
    
    def _build_attack_library(self) -> Dict:
        """Build comprehensive attack library"""
        return {
            "categories": [
                "OWASP Top 10",
                "MITRE ATT&CK", 
                "STRIDE Threat Model",
                "Component-Specific",
                "Social Engineering",
                "Availability Attack"
            ],
            "total_scenarios": 25,
            "configurable_parameters": [
                "intensity",
                "stealth_level",
                "speed",
                "scope",
                "persistence_level",
                "lateral_movement",
                "data_collection"
            ]
        }

def main():
    """Test the enhanced VM attack engine"""
    
    # Test with sample architecture
    sample_architecture = {
        "metadata": {"company_name": "Test Corp"},
        "nodes": [
            {"id": "web1", "type": "web_server", "name": "Web Server"},
            {"id": "db1", "type": "database", "name": "Database"},
            {"id": "user1", "type": "user_workstation", "name": "User PC"}
        ],
        "connections": [
            {"source": "web1", "target": "db1"},
            {"source": "user1", "target": "web1"}
        ]
    }
    
    engine = EnhancedVMAttackEngine()
    
    print("🎯 Getting attack options for architecture...")
    attack_options = engine.get_attack_options(sample_architecture)
    
    print(f"✅ Generated {len(attack_options)} attack scenarios:")
    for i, attack in enumerate(attack_options[:5], 1):
        print(f"  {i}. {attack['name']} ({attack['category']}) - {attack['severity']}")
    
    print(f"\n📊 Attack Library Summary:")
    print(f"  Total Categories: {len(engine.attack_library['categories'])}")
    print(f"  Total Scenarios: {engine.attack_library['total_scenarios']}")
    print(f"  Configurable Parameters: {len(engine.attack_library['configurable_parameters'])}")

if __name__ == "__main__":
    main()