/**
 * FRONTEND-BACKEND INTEGRATION HOOK
 * =================================
 * 
 * React hook to connect frontend with the VM attack backend API
 */

import { useState, useEffect } from 'react';

interface ArchitectureNode {
  id: string;
  name: string;
  type: string;
  label?: string;
}

interface Architecture {
  metadata?: any;
  nodes: ArchitectureNode[];
  connections: any[];
}

interface AttackScenario {
  id: string;
  name: string;
  category: string;
  severity: string;
  estimated_duration: string;
  success_probability: number;
  description: string;
  target_components: string[];
  configurable_parameters: Record<string, string[]>;
}

interface CanvasNodeState {
  status: 'safe' | 'under_attack' | 'compromised';
  compromise_level: number;
  last_updated: string;
  attack_indicators: Array<{
    type: string;
    severity: string;
    timestamp: string;
  }>;
}

interface AttackConfig {
  intensity: string;
  stealth_level: string;
  speed: string;
  scope: string;
}

export const useVMAttackAPI = (apiBaseUrl: string = 'http://localhost:8080') => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [canvasState, setCanvasState] = useState<Record<string, CanvasNodeState>>({});
  const [simulationActive, setSimulationActive] = useState(false);

  // Get analysis options (regular vs VM attack)
  const getAnalysisOptions = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch(`${apiBaseUrl}/api/analysis-options`);
      const data = await response.json();
      
      return data;
    } catch (err) {
      setError(`Failed to get analysis options: ${err}`);
      return null;
    } finally {
      setLoading(false);
    }
  };

  // Get VM attack scenarios for architecture
  const getVMAttackScenarios = async (architecture: Architecture): Promise<AttackScenario[]> => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch(`${apiBaseUrl}/api/vm-attack-scenarios`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(architecture),
      });
      
      const data = await response.json();
      
      if (data.success) {
        return data.scenarios;
      } else {
        throw new Error(data.error || 'Failed to get attack scenarios');
      }
    } catch (err) {
      setError(`Failed to get VM attack scenarios: ${err}`);
      return [];
    } finally {
      setLoading(false);
    }
  };

  // Execute VM attack simulation
  const executeVMAttack = async (
    architecture: Architecture, 
    attackScenarioId: string, 
    config: AttackConfig
  ) => {
    try {
      setLoading(true);
      setError(null);
      setSimulationActive(true);
      
      const response = await fetch(`${apiBaseUrl}/api/vm-attack-execute`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          architecture,
          attack_scenario_id: attackScenarioId,
          configuration: config,
        }),
      });
      
      const data = await response.json();
      
      if (data.success) {
        // Update canvas state from simulation results
        if (data.canvas_state) {
          setCanvasState(data.canvas_state);
        }
        return data;
      } else {
        throw new Error(data.error || 'VM attack execution failed');
      }
    } catch (err) {
      setError(`Failed to execute VM attack: ${err}`);
      return null;
    } finally {
      setLoading(false);
      setSimulationActive(false);
    }
  };

  // Get real-time attack status for canvas updates
  const getAttackStatus = async (simulationId: string) => {
    try {
      const response = await fetch(`${apiBaseUrl}/api/vm-attack-status/${simulationId}`);
      const data = await response.json();
      
      if (data.success && data.canvas_state) {
        setCanvasState(data.canvas_state);
        return data;
      }
      
      return null;
    } catch (err) {
      console.warn(`Failed to get attack status: ${err}`);
      return null;
    }
  };

  // Get attack configuration options
  const getAttackConfigurationOptions = async (
    scenarioId: string, 
    architecture: Architecture
  ) => {
    try {
      const response = await fetch(`${apiBaseUrl}/api/vm-attack-configure/${scenarioId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(architecture),
      });
      
      const data = await response.json();
      return data.success ? data : null;
    } catch (err) {
      setError(`Failed to get configuration options: ${err}`);
      return null;
    }
  };

  // Perform combined analysis (security + VM attacks)
  const performCombinedAnalysis = async (architecture: Architecture) => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await fetch(`${apiBaseUrl}/api/combined-analysis`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(architecture),
      });
      
      const data = await response.json();
      return data.success ? data : null;
    } catch (err) {
      setError(`Failed to perform combined analysis: ${err}`);
      return null;
    } finally {
      setLoading(false);
    }
  };

  // Real-time canvas state updates (polling)
  useEffect(() => {
    let interval: NodeJS.Timeout;
    
    if (simulationActive) {
      interval = setInterval(async () => {
        // This would poll for updates during active simulation
        // You could implement WebSocket connection here for real-time updates
      }, 2000);
    }
    
    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [simulationActive]);

  return {
    // State
    loading,
    error,
    canvasState,
    simulationActive,
    
    // API Methods
    getAnalysisOptions,
    getVMAttackScenarios,
    executeVMAttack,
    getAttackStatus,
    getAttackConfigurationOptions,
    performCombinedAnalysis,
    
    // Canvas Methods
    updateCanvasState: setCanvasState,
    setSimulationActive,
  };
};

// Helper function to integrate with existing canvas
export const integrateWithExistingCanvas = (
  canvasState: Record<string, CanvasNodeState>,
  updateCanvasNodeVisual: (nodeId: string, status: string) => void
) => {
  Object.entries(canvasState).forEach(([nodeId, state]) => {
    // Update your existing canvas visualization
    updateCanvasNodeVisual(nodeId, state.status);
  });
};

export default useVMAttackAPI;