/*
Virtual Cybersecurity Sandbox - Frontend Component
React component for deploying and managing live container environments
*/

import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '../ui/card';

interface SandboxEnvironment {
  sandbox_id: string;
  architecture_id: string;
  status: string;
  container_count: number;
  created_at: string;
  last_activity: string;
}

interface AttackExecution {
  execution_id: string;
  attack_type: string;
  target: string;
  status: string;
  success: boolean;
  detected: boolean;
}

interface SecurityEvent {
  event_id: string;
  timestamp: string;
  type: string;
  severity: string;
  container: string;
  description: string;
  status: string;
}

const VirtualSandboxModal: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  architecture: any;
}> = ({ isOpen, onClose, architecture }) => {
  const [sandboxStatus, setSandboxStatus] = useState<string>('idle');
  const [currentSandbox, setCurrentSandbox] = useState<SandboxEnvironment | null>(null);
  const [activeAttacks, setActiveAttacks] = useState<AttackExecution[]>([]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([]);
  const [isDeploying, setIsDeploying] = useState(false);
  const [selectedAttackType, setSelectedAttackType] = useState('');
  const [selectedTarget, setSelectedTarget] = useState('');
  const [monitoringEnabled, setMonitoringEnabled] = useState(true);

  // Available attack types for manual execution
  const attackTypes = [
    { id: 'ATK001', name: 'Port Scanning', category: 'reconnaissance' },
    { id: 'ATK002', name: 'Brute Force Authentication', category: 'credential_access' },
    { id: 'ATK003', name: 'SQL Injection', category: 'initial_access' },
    { id: 'ATK004', name: 'DDoS Attack', category: 'impact' },
    { id: 'ATK006', name: 'XSS Attack', category: 'execution' },
    { id: 'ATK007', name: 'Lateral Movement', category: 'lateral_movement' },
    { id: 'ATK011', name: 'Ransomware', category: 'impact' }
  ];

  // Available attack scenarios
  const attackScenarios = [
    { id: 'apt_simulation', name: 'Advanced Persistent Threat', duration: '2-4 hours' },
    { id: 'web_application_attack', name: 'Web Application Attack Chain', duration: '1-2 hours' },
    { id: 'insider_threat', name: 'Insider Threat Simulation', duration: '30-60 minutes' },
    { id: 'cloud_attack', name: 'Cloud Infrastructure Attack', duration: '1-3 hours' }
  ];

  // Deploy sandbox environment
  const deploySandbox = async () => {
    setIsDeploying(true);
    setSandboxStatus('deploying');

    try {
      const response = await fetch('http://localhost:8080/api/sandbox/deploy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          architecture: architecture,
          security_level: 'vulnerable', // Start with vulnerable for testing
          enable_monitoring: monitoringEnabled
        })
      });

      if (response.ok) {
        const result = await response.json();
        setSandboxStatus('deployed');
        
        // Start polling for sandbox status
        pollSandboxStatus(result.sandbox_id);
        
        console.log('🚀 Sandbox deployed:', result);
      } else {
        throw new Error('Failed to deploy sandbox');
      }
    } catch (error) {
      console.error('❌ Sandbox deployment failed:', error);
      setSandboxStatus('error');
    } finally {
      setIsDeploying(false);
    }
  };

  // Poll sandbox status
  const pollSandboxStatus = async (sandboxId: string) => {
    try {
      const response = await fetch(`http://localhost:8080/api/sandbox/${sandboxId}/status`);
      if (response.ok) {
        const status = await response.json();
        setCurrentSandbox(status);
        
        // Get security events
        const eventsResponse = await fetch(`http://localhost:8080/api/sandbox/${sandboxId}/security-events?limit=10`);
        if (eventsResponse.ok) {
          const eventsData = await eventsResponse.json();
          setSecurityEvents(eventsData.events);
        }
      }
    } catch (error) {
      console.error('Failed to get sandbox status:', error);
    }
  };

  // Execute single attack
  const executeAttack = async () => {
    if (!currentSandbox || !selectedAttackType || !selectedTarget) return;

    try {
      const response = await fetch(`http://localhost:8080/api/sandbox/${currentSandbox.sandbox_id}/attack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sandbox_id: currentSandbox.sandbox_id,
          attack_id: selectedAttackType,
          target_container_id: selectedTarget
        })
      });

      if (response.ok) {
        const result = await response.json();
        console.log('🎯 Attack started:', result);
        
        // Poll attack status
        pollAttackStatus(result.execution_id);
      }
    } catch (error) {
      console.error('❌ Attack execution failed:', error);
    }
  };

  // Execute attack scenario
  const executeScenario = async (scenarioName: string) => {
    if (!currentSandbox) return;

    try {
      const response = await fetch(`http://localhost:8080/api/sandbox/${currentSandbox.sandbox_id}/attack-scenario`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sandbox_id: currentSandbox.sandbox_id,
          scenario_name: scenarioName
        })
      });

      if (response.ok) {
        const result = await response.json();
        console.log('🎬 Attack scenario started:', result);
      }
    } catch (error) {
      console.error('❌ Scenario execution failed:', error);
    }
  };

  // Poll attack status
  const pollAttackStatus = async (executionId: string) => {
    try {
      const response = await fetch(`http://localhost:8080/api/attack/${executionId}/status`);
      if (response.ok) {
        const status = await response.json();
        
        setActiveAttacks(prev => {
          const updated = [...prev];
          const existingIndex = updated.findIndex(a => a.execution_id === executionId);
          
          if (existingIndex >= 0) {
            updated[existingIndex] = status;
          } else {
            updated.push(status);
          }
          
          return updated;
        });
      }
    } catch (error) {
      console.error('Failed to get attack status:', error);
    }
  };

  // Destroy sandbox
  const destroySandbox = async () => {
    if (!currentSandbox) return;

    try {
      const response = await fetch(`http://localhost:8080/api/sandbox/${currentSandbox.sandbox_id}`, {
        method: 'DELETE'
      });

      if (response.ok) {
        setSandboxStatus('idle');
        setCurrentSandbox(null);
        setActiveAttacks([]);
        setSecurityEvents([]);
        console.log('🧹 Sandbox destroyed');
      }
    } catch (error) {
      console.error('❌ Failed to destroy sandbox:', error);
    }
  };

  // Get severity color
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400';
      case 'high': return 'text-orange-400';
      case 'medium': return 'text-yellow-400';
      case 'low': return 'text-green-400';
      default: return 'text-gray-400';
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-900 rounded-lg shadow-xl max-w-6xl w-full max-h-[90vh] overflow-auto">
        <div className="p-6 border-b border-gray-700">
          <div className="flex justify-between items-center">
            <h2 className="text-xl font-bold text-white flex items-center gap-2">
              🚀 Virtual Cybersecurity Sandbox
              <span className="text-sm font-normal text-gray-400">
                Live Container Testing Environment
              </span>
            </h2>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-white transition-colors"
            >
              ✕
            </button>
          </div>
        </div>

        <div className="p-6 space-y-6">
          {/* Sandbox Status */}
          <Card className="bg-gray-800 border-gray-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                🏗️ Sandbox Environment
              </CardTitle>
            </CardHeader>
            <CardContent>
              {sandboxStatus === 'idle' && (
                <div className="space-y-4">
                  <div className="text-gray-300">
                    Deploy your architecture as live Docker containers for real security testing.
                  </div>
                  
                  <div className="flex items-center gap-4">
                    <label className="flex items-center gap-2 text-gray-300">
                      <input
                        type="checkbox"
                        checked={monitoringEnabled}
                        onChange={(e) => setMonitoringEnabled(e.target.checked)}
                        className="rounded"
                      />
                      Enable Real-time Security Monitoring
                    </label>
                  </div>

                  <button
                    onClick={deploySandbox}
                    disabled={isDeploying}
                    className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded flex items-center gap-2 disabled:opacity-50"
                  >
                    {isDeploying ? '🔄 Deploying...' : '🚀 Deploy Live Sandbox'}
                  </button>
                </div>
              )}

              {sandboxStatus === 'deployed' && currentSandbox && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-gray-400">Sandbox ID:</span>
                      <div className="text-white font-mono">{currentSandbox.sandbox_id}</div>
                    </div>
                    <div>
                      <span className="text-gray-400">Status:</span>
                      <div className="text-green-400">{currentSandbox.status}</div>
                    </div>
                    <div>
                      <span className="text-gray-400">Containers:</span>
                      <div className="text-white">{currentSandbox.container_count}</div>
                    </div>
                    <div>
                      <span className="text-gray-400">Created:</span>
                      <div className="text-white">{new Date(currentSandbox.created_at).toLocaleTimeString()}</div>
                    </div>
                  </div>

                  <button
                    onClick={destroySandbox}
                    className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded flex items-center gap-2"
                  >
                    🧹 Destroy Sandbox
                  </button>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Attack Execution */}
          {currentSandbox && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Manual Attack Execution */}
              <Card className="bg-gray-800 border-gray-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center gap-2">
                    🎯 Execute Attack
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <label className="block text-gray-400 text-sm mb-2">Attack Type</label>
                    <select
                      value={selectedAttackType}
                      onChange={(e) => setSelectedAttackType(e.target.value)}
                      className="w-full bg-gray-700 text-white rounded px-3 py-2"
                    >
                      <option value="">Select Attack Type</option>
                      {attackTypes.map(attack => (
                        <option key={attack.id} value={attack.id}>
                          {attack.name} ({attack.category})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="block text-gray-400 text-sm mb-2">Target Container</label>
                    <select
                      value={selectedTarget}
                      onChange={(e) => setSelectedTarget(e.target.value)}
                      className="w-full bg-gray-700 text-white rounded px-3 py-2"
                    >
                      <option value="">Select Target</option>
                      {architecture.nodes?.map((node: any) => (
                        <option key={node.id} value={node.id}>
                          {node.name} ({node.type})
                        </option>
                      ))}
                    </select>
                  </div>

                  <button
                    onClick={executeAttack}
                    disabled={!selectedAttackType || !selectedTarget}
                    className="w-full bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded disabled:opacity-50"
                  >
                    🎯 Execute Attack
                  </button>
                </CardContent>
              </Card>

              {/* Attack Scenarios */}
              <Card className="bg-gray-800 border-gray-700">
                <CardHeader>
                  <CardTitle className="text-white flex items-center gap-2">
                    🎬 Attack Scenarios
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {attackScenarios.map(scenario => (
                    <div key={scenario.id} className="border border-gray-600 rounded p-3">
                      <div className="flex justify-between items-start mb-2">
                        <div>
                          <div className="text-white font-medium">{scenario.name}</div>
                          <div className="text-gray-400 text-sm">Duration: {scenario.duration}</div>
                        </div>
                        <button
                          onClick={() => executeScenario(scenario.id)}
                          className="bg-purple-600 hover:bg-purple-700 text-white px-3 py-1 rounded text-sm"
                        >
                          Start
                        </button>
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>
          )}

          {/* Active Attacks */}
          {activeAttacks.length > 0 && (
            <Card className="bg-gray-800 border-gray-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  ⚡ Active Attacks
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {activeAttacks.map(attack => (
                    <div key={attack.execution_id} className="border border-gray-600 rounded p-3">
                      <div className="flex justify-between items-center">
                        <div>
                          <div className="text-white font-medium">{attack.attack_type}</div>
                          <div className="text-gray-400 text-sm">Target: {attack.target}</div>
                        </div>
                        <div className="text-right">
                          <div className={`text-sm ${attack.status === 'completed' ? 'text-green-400' : 'text-yellow-400'}`}>
                            {attack.status}
                          </div>
                          {attack.status === 'completed' && (
                            <div className="text-xs space-x-2">
                              <span className={attack.success ? 'text-red-400' : 'text-green-400'}>
                                {attack.success ? '✓ Successful' : '✗ Failed'}
                              </span>
                              <span className={attack.detected ? 'text-orange-400' : 'text-gray-400'}>
                                {attack.detected ? '🚨 Detected' : '👻 Undetected'}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Security Events */}
          {securityEvents.length > 0 && (
            <Card className="bg-gray-800 border-gray-700">
              <CardHeader>
                <CardTitle className="text-white flex items-center gap-2">
                  🚨 Security Events
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {securityEvents.map(event => (
                    <div key={event.event_id} className="border border-gray-600 rounded p-3">
                      <div className="flex justify-between items-start">
                        <div>
                          <div className="text-white font-medium">{event.type.replace(/_/g, ' ')}</div>
                          <div className="text-gray-300 text-sm">{event.description}</div>
                          <div className="text-gray-400 text-xs">{event.container}</div>
                        </div>
                        <div className="text-right">
                          <div className={`text-sm font-medium ${getSeverityColor(event.severity)}`}>
                            {event.severity.toUpperCase()}
                          </div>
                          <div className="text-gray-400 text-xs">
                            {new Date(event.timestamp).toLocaleTimeString()}
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};

export default VirtualSandboxModal;