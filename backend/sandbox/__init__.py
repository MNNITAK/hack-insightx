"""
Virtual Cybersecurity Sandbox Package
Provides container orchestration, attack simulation, and defense capabilities
"""

# Container orchestrator with Docker error handling
try:
    from .container_orchestrator import RuleBasedContainerOrchestrator
    CONTAINER_ORCHESTRATOR_AVAILABLE = True
    print("✅ Container Orchestrator module loaded")
except Exception as e:
    print(f"⚠️  Container Orchestrator module error: {e}")
    CONTAINER_ORCHESTRATOR_AVAILABLE = False
    # Create a mock class
    class RuleBasedContainerOrchestrator:
        def __init__(self, *args, **kwargs):
            self.mock_mode = True
            self.docker_available = False
        def __getattr__(self, name):
            return lambda *args, **kwargs: {"status": "mock_mode", "message": "Docker not available"}

# Import modules that depend on container orchestrator
from .attack_simulator import RuleBasedAttackSimulator as _RuleBasedAttackSimulator
from .defense_agent import RuleBasedDefenseAgent as _RuleBasedDefenseAgent

# Create factory functions that handle missing dependencies
def create_attack_simulator(container_orchestrator=None):
    """Create attack simulator with optional container orchestrator"""
    if container_orchestrator is None:
        container_orchestrator = RuleBasedContainerOrchestrator()
    return _RuleBasedAttackSimulator(container_orchestrator)

def create_defense_agent(container_orchestrator=None, attack_simulator=None):
    """Create defense agent with optional dependencies"""
    if container_orchestrator is None:
        container_orchestrator = RuleBasedContainerOrchestrator()
    if attack_simulator is None:
        attack_simulator = create_attack_simulator(container_orchestrator)
    return _RuleBasedDefenseAgent(container_orchestrator, attack_simulator)

# Export the original classes and factory functions
RuleBasedAttackSimulator = _RuleBasedAttackSimulator
RuleBasedDefenseAgent = _RuleBasedDefenseAgent

try:
    from .api import setup_sandbox_api
except ImportError:
    # Graceful fallback if API dependencies not available
    def setup_sandbox_api(*args, **kwargs):
        return None

__version__ = "1.0.0"
__all__ = [
    "RuleBasedAttackSimulator",
    "RuleBasedDefenseAgent", 
    "RuleBasedContainerOrchestrator",
    "create_attack_simulator",
    "create_defense_agent",
    "setup_sandbox_api",
    "CONTAINER_ORCHESTRATOR_AVAILABLE"
]