#!/usr/bin/env python3
"""
🚀 Virtual Cybersecurity Sandbox - Docker Orchestrator
Main orchestration logic for managing virtual environments and attacks
"""

import docker
import logging
import json
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path
import asyncio
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ComponentConfig:
    """Configuration for a virtual component"""
    name: str
    type: str
    image: str
    ports: Dict[str, int]
    environment: Dict[str, str]
    volumes: Dict[str, str]
    networks: List[str]
    vulnerabilities: List[str]
    security_level: str

@dataclass
class NetworkTopology:
    """Represents a complete network architecture"""
    name: str
    components: List[ComponentConfig]
    network_segments: List[str]
    attack_surface: List[str]
    metadata: Dict[str, Any]

class VirtualEnvironmentOrchestrator:
    """
    🎯 Main orchestrator for virtual cybersecurity environments
    
    Responsibilities:
    - Create and manage Docker containers for each component
    - Set up network topologies
    - Execute attacks on live infrastructure
    - Monitor and report results
    """
    
    def __init__(self):
        self.client = docker.from_env()
        self.active_environments: Dict[str, Dict] = {}
        self.component_templates = self._load_component_templates()
        self.network_templates = self._load_network_templates()
        
    def _load_component_templates(self) -> Dict[str, ComponentConfig]:
        """Load component templates from configuration"""
        templates = {}
        
        # Web Server Template
        templates['web_server'] = ComponentConfig(
            name="web_server",
            type="web_server",
            image="insightx/vulnerable-nginx",
            ports={"80": 80, "443": 443},
            environment={
                "NGINX_MODE": "vulnerable",
                "ENABLE_LOGGING": "true"
            },
            volumes={
                "./web-content": "/var/www/html",
                "./logs": "/var/log/nginx"
            },
            networks=["dmz", "internal"],
            vulnerabilities=[
                "CVE-2021-23017",  # Nginx off-by-one
                "directory_traversal",
                "weak_ssl_config"
            ],
            security_level="low"
        )
        
        # Database Template
        templates['database_server'] = ComponentConfig(
            name="database_server",
            type="database_server",
            image="insightx/vulnerable-mysql",
            ports={"3306": 3306},
            environment={
                "MYSQL_ROOT_PASSWORD": "admin123",
                "MYSQL_DATABASE": "ecommerce",
                "MYSQL_USER": "webapp",
                "MYSQL_PASSWORD": "password123"
            },
            volumes={
                "./db-data": "/var/lib/mysql",
                "./db-logs": "/var/log/mysql"
            },
            networks=["internal"],
            vulnerabilities=[
                "weak_credentials",
                "sql_injection_possible",
                "unencrypted_connections",
                "privilege_escalation"
            ],
            security_level="low"
        )
        
        # Firewall Template
        templates['firewall'] = ComponentConfig(
            name="firewall",
            type="firewall",
            image="insightx/virtual-firewall",
            ports={},
            environment={
                "FIREWALL_MODE": "permissive",
                "LOG_LEVEL": "debug"
            },
            volumes={
                "./firewall-logs": "/var/log/firewall",
                "./firewall-rules": "/etc/firewall/rules"
            },
            networks=["dmz", "internal", "external"],
            vulnerabilities=[
                "permissive_rules",
                "unmonitored_traffic",
                "weak_authentication"
            ],
            security_level="medium"
        )
        
        # User Workstation Template
        templates['user_workstation'] = ComponentConfig(
            name="user_workstation",
            type="user_workstation",
            image="insightx/vulnerable-workstation",
            ports={"3389": 3389},
            environment={
                "USER_BEHAVIOR": "normal",
                "ANTIVIRUS": "disabled",
                "PATCHES": "outdated"
            },
            volumes={
                "./user-data": "/home/user",
                "./user-logs": "/var/log/user"
            },
            networks=["internal"],
            vulnerabilities=[
                "unpatched_os",
                "weak_passwords",
                "no_antivirus",
                "phishing_susceptible"
            ],
            security_level="low"
        )
        
        return templates
    
    def _load_network_templates(self) -> Dict[str, NetworkTopology]:
        """Load pre-configured network topologies"""
        templates = {}
        
        # E-commerce Vulnerable Template
        templates['ecommerce_vulnerable'] = NetworkTopology(
            name="E-commerce Platform (Vulnerable)",
            components=[
                self.component_templates['web_server'],
                self.component_templates['database_server'],
                self.component_templates['user_workstation']
            ],
            network_segments=["external", "dmz", "internal"],
            attack_surface=[
                "web_application",
                "database_injection",
                "lateral_movement",
                "credential_theft"
            ],
            metadata={
                "industry": "retail",
                "risk_level": "high",
                "compliance_required": ["PCI-DSS"],
                "description": "Typical e-commerce setup with multiple vulnerabilities"
            }
        )
        
        # Healthcare Vulnerable Template
        templates['healthcare_vulnerable'] = NetworkTopology(
            name="Healthcare Network (Vulnerable)",
            components=[
                self.component_templates['web_server'],
                self.component_templates['database_server'],
                self.component_templates['firewall'],
                self.component_templates['user_workstation']
            ],
            network_segments=["external", "dmz", "internal", "secure"],
            attack_surface=[
                "patient_data_exposure",
                "ransomware_targets",
                "medical_device_compromise",
                "insider_threats"
            ],
            metadata={
                "industry": "healthcare",
                "risk_level": "critical",
                "compliance_required": ["HIPAA", "HITECH"],
                "description": "Healthcare network with patient data vulnerabilities"
            }
        )
        
        return templates
    
    async def create_virtual_environment(self, architecture_data: Dict, environment_id: str) -> Dict:
        """
        🏗️ Create a virtual environment based on architecture data
        
        Args:
            architecture_data: JSON data from frontend canvas
            environment_id: Unique identifier for this environment
            
        Returns:
            Environment details and status
        """
        logger.info(f"🚀 Creating virtual environment: {environment_id}")
        
        try:
            # Parse architecture components
            components = architecture_data.get('nodes', [])
            connections = architecture_data.get('connections', [])
            
            # Create Docker network
            network_name = f"insightx_{environment_id}"
            network = self._create_docker_network(network_name)
            
            # Deploy components as containers
            containers = {}
            for component in components:
                container = await self._deploy_component(component, network_name, environment_id)
                containers[component['id']] = container
            
            # Configure network connections
            await self._configure_network_connections(containers, connections)
            
            # Store environment state
            environment = {
                'id': environment_id,
                'network': network,
                'containers': containers,
                'status': 'running',
                'created_at': time.time(),
                'architecture': architecture_data
            }
            
            self.active_environments[environment_id] = environment
            
            logger.info(f"✅ Virtual environment created successfully: {environment_id}")
            return {
                'status': 'success',
                'environment_id': environment_id,
                'containers': list(containers.keys()),
                'network': network_name,
                'endpoints': await self._get_environment_endpoints(environment)
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to create environment {environment_id}: {e}")
            await self._cleanup_environment(environment_id)
            raise
    
    def _create_docker_network(self, network_name: str):
        """Create isolated Docker network for environment"""
        try:
            # Remove existing network if exists
            try:
                existing = self.client.networks.get(network_name)
                existing.remove()
                logger.info(f"🗑️ Removed existing network: {network_name}")
            except docker.errors.NotFound:
                pass
            
            # Create new network
            network = self.client.networks.create(
                name=network_name,
                driver="bridge",
                options={
                    "com.docker.network.bridge.enable_icc": "true",
                    "com.docker.network.bridge.enable_ip_masquerade": "true"
                },
                labels={
                    "insightx.environment": "virtual_sandbox",
                    "insightx.type": "security_testing"
                }
            )
            
            logger.info(f"🌐 Created Docker network: {network_name}")
            return network
            
        except Exception as e:
            logger.error(f"❌ Failed to create network {network_name}: {e}")
            raise
    
    async def _deploy_component(self, component_data: Dict, network_name: str, environment_id: str):
        """Deploy a single component as Docker container"""
        component_type = component_data.get('type', 'unknown')
        component_id = component_data.get('id')
        
        if component_type not in self.component_templates:
            logger.warning(f"⚠️ Unknown component type: {component_type}")
            component_type = 'web_server'  # Default fallback
        
        template = self.component_templates[component_type]
        container_name = f"insightx_{environment_id}_{component_id}_{int(time.time())}"  # Add timestamp for uniqueness
        
        try:
            # Remove any existing container with similar name
            try:
                existing_containers = self.client.containers.list(all=True, filters={'name': f"insightx_{environment_id}_{component_id}"})
                for container in existing_containers:
                    logger.info(f"🗑️ Removing existing container: {container.name}")
                    container.remove(force=True)
            except Exception as e:
                logger.debug(f"No existing containers to remove: {e}")
            
            # Build or pull container image
            await self._ensure_component_image(template.image, component_type)
            
            # Configure container
            data_dir = Path(__file__).parent.parent / f"docker-components/{component_type}/data"
            data_dir.mkdir(parents=True, exist_ok=True)  # Ensure directory exists
            
            container_config = {
                'image': template.image,
                'name': container_name,
                'network': network_name,
                'ports': template.ports,
                'environment': {
                    **template.environment,
                    'COMPONENT_ID': component_id,
                    'ENVIRONMENT_ID': environment_id
                },
                'volumes': {
                    str(data_dir): {
                        'bind': '/app/data',
                        'mode': 'rw'
                    }
                },
                'labels': {
                    'insightx.environment': environment_id,
                    'insightx.component.type': component_type,
                    'insightx.component.id': component_id
                },
                'detach': True
            }
            
            # Run container
            container = self.client.containers.run(**container_config)
            
            # Wait for container to be ready
            await self._wait_for_container_ready(container)
            
            logger.info(f"🐳 Deployed container: {container_name}")
            return container
            
        except Exception as e:
            logger.error(f"❌ Failed to deploy component {component_id}: {e}")
            raise
    
    async def _ensure_component_image(self, image_name: str, component_type: str):
        """Ensure Docker image exists, build if necessary"""
        try:
            # Try to get existing image
            self.client.images.get(image_name)
            logger.info(f"✅ Image exists: {image_name}")
            
        except docker.errors.ImageNotFound:
            # Build image from Dockerfile
            dockerfile_path = Path(__file__).parent.parent / f"docker-components/{component_type}"
            
            if dockerfile_path.exists() and (dockerfile_path / "Dockerfile").exists():
                logger.info(f"🔨 Building image: {image_name}")
                self.client.images.build(
                    path=str(dockerfile_path),
                    tag=image_name,
                    rm=True
                )
                logger.info(f"✅ Built image: {image_name}")
            else:
                logger.error(f"❌ No Dockerfile found for {component_type}")
                logger.error(f"❌ Checked path: {dockerfile_path}")
                raise FileNotFoundError(f"Dockerfile not found: {dockerfile_path}")
    
    async def _wait_for_container_ready(self, container, timeout: int = 30):
        """Wait for container to be ready to accept connections"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                container.reload()
                logger.debug(f"Container status: {container.status}")
                
                if container.status == 'running':
                    # Give it a moment to fully initialize
                    await asyncio.sleep(2)
                    logger.info(f"✅ Container is running: {container.name}")
                    return True
                elif container.status in ['exited', 'dead']:
                    # Container failed to start, get logs
                    try:
                        logs = container.logs().decode('utf-8')
                        logger.error(f"❌ Container failed to start. Logs: {logs[-500:]}")  # Last 500 chars
                    except:
                        logger.error(f"❌ Container failed to start: {container.status}")
                    raise RuntimeError(f"Container failed with status: {container.status}")
                    
            except Exception as e:
                logger.warning(f"⏳ Waiting for container readiness: {e}")
                
            await asyncio.sleep(1)
        
        # If we get here, container didn't become ready in time
        try:
            container.reload()
            logs = container.logs().decode('utf-8')
            logger.error(f"❌ Container timeout. Status: {container.status}, Logs: {logs[-500:]}")
        except Exception as e:
            logger.error(f"❌ Container timeout. Could not get status/logs: {e}")
            
        raise TimeoutError(f"Container failed to become ready within {timeout}s")
    
    async def _configure_network_connections(self, containers: Dict, connections: List):
        """Configure network connections between containers"""
        # In a real implementation, this would configure:
        # - Network policies
        # - Port forwarding
        # - Service discovery
        # - Load balancing
        
        for connection in connections:
            source_id = connection.get('source')
            target_id = connection.get('target')
            
            if source_id in containers and target_id in containers:
                # Configure connection between containers
                logger.info(f"🔗 Configured connection: {source_id} -> {target_id}")
    
    async def _get_environment_endpoints(self, environment: Dict) -> Dict:
        """Get accessible endpoints for the environment"""
        endpoints = {}
        
        for container_id, container in environment['containers'].items():
            try:
                container.reload()
                ports = container.attrs['NetworkSettings']['Ports']
                
                for internal_port, bindings in ports.items():
                    if bindings:
                        host_port = bindings[0]['HostPort']
                        endpoints[container_id] = f"http://localhost:{host_port}"
                        
            except Exception as e:
                logger.warning(f"⚠️ Could not get endpoint for {container_id}: {e}")
        
        return endpoints
    
    async def list_available_attacks(self, environment_id: str) -> List[Dict]:
        """
        🎯 List available attacks for the given environment
        """
        if environment_id not in self.active_environments:
            raise ValueError(f"Environment not found: {environment_id}")
        
        environment = self.active_environments[environment_id]
        
        # Analyze environment to determine applicable attacks
        attacks = [
            {
                'id': 'sql_injection',
                'name': 'SQL Injection Attack',
                'description': 'Exploit SQL injection vulnerabilities in web applications',
                'target_components': ['web_server', 'database_server'],
                'severity': 'high',
                'estimated_time': '2-5 minutes'
            },
            {
                'id': 'port_scan',
                'name': 'Port Scanning',
                'description': 'Discover open ports and services',
                'target_components': ['all'],
                'severity': 'low',
                'estimated_time': '1-2 minutes'
            },
            {
                'id': 'brute_force',
                'name': 'Credential Brute Force',
                'description': 'Attempt to crack passwords through brute force',
                'target_components': ['web_server', 'user_workstation'],
                'severity': 'medium',
                'estimated_time': '3-10 minutes'
            },
            {
                'id': 'lateral_movement',
                'name': 'Lateral Movement',
                'description': 'Move from compromised system to other network segments',
                'target_components': ['user_workstation', 'internal_network'],
                'severity': 'high',
                'estimated_time': '5-15 minutes'
            }
        ]
        
        return attacks
    
    async def execute_attack(self, environment_id: str, attack_id: str, target_components: List[str] = None) -> Dict:
        """
        ⚔️ Execute attack on virtual environment
        
        Args:
            environment_id: Target environment
            attack_id: Attack to execute
            target_components: Specific components to target
            
        Returns:
            Attack results and impact assessment
        """
        logger.info(f"⚔️ Executing attack {attack_id} on environment {environment_id}")
        
        if environment_id not in self.active_environments:
            raise ValueError(f"Environment not found: {environment_id}")
        
        environment = self.active_environments[environment_id]
        
        # Import and execute attack script
        attack_module = await self._load_attack_script(attack_id)
        
        attack_result = await attack_module.execute_attack(
            environment=environment,
            target_components=target_components or [],
            orchestrator=self
        )
        
        # Assess impact and generate report
        impact_assessment = await self._assess_attack_impact(environment, attack_result)
        
        result = {
            'attack_id': attack_id,
            'environment_id': environment_id,
            'status': 'completed',
            'timestamp': time.time(),
            'results': attack_result,
            'impact': impact_assessment,
            'recommendations': self._generate_security_recommendations(attack_result)
        }
        
        logger.info(f"✅ Attack completed: {attack_id}")
        return result
    
    async def _load_attack_script(self, attack_id: str):
        """Dynamically load attack script module"""
        script_path = Path(f"attack-scripts/{attack_id}.py")
        
        if not script_path.exists():
            raise FileNotFoundError(f"Attack script not found: {script_path}")
        
        # Dynamic import would go here
        # For now, return a mock module
        class MockAttackModule:
            async def execute_attack(self, environment, target_components, orchestrator):
                return {
                    'success': True,
                    'vulnerabilities_exploited': ['example_vuln'],
                    'systems_compromised': target_components,
                    'data_accessed': ['user_data', 'configuration'],
                    'persistence_achieved': False,
                    'lateral_movement': []
                }
        
        return MockAttackModule()
    
    async def _assess_attack_impact(self, environment: Dict, attack_result: Dict) -> Dict:
        """Assess the impact of the attack on the environment"""
        return {
            'systems_affected': len(attack_result.get('systems_compromised', [])),
            'data_compromised': attack_result.get('data_accessed', []),
            'business_impact': 'medium',
            'recovery_time': '2-4 hours',
            'financial_cost': '$10,000 - $50,000'
        }
    
    def _generate_security_recommendations(self, attack_result: Dict) -> List[str]:
        """Generate security recommendations based on attack results"""
        recommendations = [
            "Implement input validation and parameterized queries",
            "Enable Web Application Firewall (WAF)",
            "Regular security patching and updates",
            "Implement network segmentation",
            "Deploy endpoint detection and response (EDR)",
            "Conduct regular penetration testing"
        ]
        return recommendations
    
    async def cleanup_environment(self, environment_id: str) -> bool:
        """
        🧹 Clean up virtual environment
        """
        logger.info(f"🧹 Cleaning up environment: {environment_id}")
        return await self._cleanup_environment(environment_id)
    
    async def _cleanup_environment(self, environment_id: str) -> bool:
        """Internal cleanup method"""
        try:
            if environment_id in self.active_environments:
                environment = self.active_environments[environment_id]
                
                # Stop and remove containers
                for container in environment.get('containers', {}).values():
                    try:
                        container.stop(timeout=10)
                        container.remove()
                        logger.info(f"🗑️ Removed container: {container.name}")
                    except Exception as e:
                        logger.warning(f"⚠️ Error removing container: {e}")
                
                # Remove network
                try:
                    environment['network'].remove()
                    logger.info(f"🗑️ Removed network: {environment['network'].name}")
                except Exception as e:
                    logger.warning(f"⚠️ Error removing network: {e}")
                
                # Remove from active environments
                del self.active_environments[environment_id]
            
            logger.info(f"✅ Environment cleanup completed: {environment_id}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Environment cleanup failed: {e}")
            return False
    
    def get_environment_status(self, environment_id: str) -> Dict:
        """Get current status of virtual environment"""
        if environment_id not in self.active_environments:
            return {'status': 'not_found'}
        
        environment = self.active_environments[environment_id]
        
        container_status = {}
        for container_id, container in environment['containers'].items():
            try:
                container.reload()
                container_status[container_id] = {
                    'status': container.status,
                    'health': 'healthy' if container.status == 'running' else 'unhealthy'
                }
            except Exception as e:
                container_status[container_id] = {'status': 'error', 'error': str(e)}
        
        return {
            'environment_id': environment_id,
            'status': environment['status'],
            'containers': container_status,
            'uptime': time.time() - environment['created_at']
        }

# Global orchestrator instance
orchestrator = VirtualEnvironmentOrchestrator()

if __name__ == "__main__":
    # Test the orchestrator
    import asyncio
    
    async def test_orchestrator():
        # Sample architecture data
        architecture = {
            'nodes': [
                {'id': 'web1', 'type': 'web_server'},
                {'id': 'db1', 'type': 'database_server'}
            ],
            'connections': [
                {'source': 'web1', 'target': 'db1'}
            ]
        }
        
        env_id = "test_env_001"
        result = await orchestrator.create_virtual_environment(architecture, env_id)
        print("Environment created:", result)
        
        # List attacks
        attacks = await orchestrator.list_available_attacks(env_id)
        print("Available attacks:", attacks)
        
        # Execute an attack
        attack_result = await orchestrator.execute_attack(env_id, 'port_scan')
        print("Attack result:", attack_result)
        
        # Cleanup
        await orchestrator.cleanup_environment(env_id)
        print("Environment cleaned up")
    
    asyncio.run(test_orchestrator())