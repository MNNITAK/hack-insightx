/**
 * VM ATTACK OPTION COMPONENT
 * ==========================
 * 
 * React component that provides users with the option to choose between
 * regular security analysis and VM attack simulation.
 */

import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { 
  Shield, 
  Zap, 
  Target, 
  Settings, 
  Play, 
  Eye,
  AlertTriangle,
  Info,
  ChevronRight
} from 'lucide-react';

interface AnalysisOption {
  id: string;
  name: string;
  description: string;
  icon: React.ReactNode;
  features: string[];
  recommended?: boolean;
}

interface VMAttackScenario {
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

interface VMAttackOptionProps {
  architecture: any;
  onOptionSelect: (option: string) => void;
  onVMAttackExecute: (scenarioId: string, config: any) => void;
}

export const VMAttackOption: React.FC<VMAttackOptionProps> = ({
  architecture,
  onOptionSelect,
  onVMAttackExecute
}) => {
  const [selectedOption, setSelectedOption] = useState<string>('');
  const [vmScenarios, setVmScenarios] = useState<VMAttackScenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<VMAttackScenario | null>(null);
  const [showConfiguration, setShowConfiguration] = useState(false);
  const [attackConfig, setAttackConfig] = useState({
    intensity: 'medium',
    stealth_level: 'normal',
    speed: 'normal',
    scope: 'multiple_targets'
  });
  const [loading, setLoading] = useState(false);

  const analysisOptions: AnalysisOption[] = [
    {
      id: 'regular_security_analysis',
      name: 'Regular Security Analysis',
      description: 'Traditional security assessment using OWASP, MITRE, and STRIDE frameworks',
      icon: <Shield className="h-6 w-6 text-blue-600" />,
      features: [
        'OWASP Top 10 vulnerability assessment',
        'MITRE ATT&CK technique mapping', 
        'STRIDE threat modeling',
        'Security recommendations',
        'Compliance gap analysis'
      ]
    },
    {
      id: 'vm_attack_simulation',
      name: 'VM Attack Simulation',
      description: 'Interactive virtual attack scenarios with real-time impact visualization',
      icon: <Target className="h-6 w-6 text-red-600" />,
      features: [
        '20+ customizable attack scenarios',
        'Real-time canvas node updates',
        'Detailed impact analysis',
        'Attack configuration options',
        'Business impact assessment'
      ],
      recommended: true
    },
    {
      id: 'combined_analysis',
      name: 'Combined Analysis',
      description: 'Comprehensive security assessment with attack simulation',
      icon: <Zap className="h-6 w-6 text-purple-600" />,
      features: [
        'Complete security analysis',
        'Top attack scenarios execution',
        'Integrated reporting',
        'Prioritized recommendations',
        'Risk-based approach'
      ]
    }
  ];

  useEffect(() => {
    if (selectedOption === 'vm_attack_simulation' || selectedOption === 'combined_analysis') {
      fetchVMScenarios();
    }
  }, [selectedOption, architecture]);

  const fetchVMScenarios = async () => {
    try {
      setLoading(true);
      const response = await fetch('/api/vm-attack-scenarios', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(architecture)
      });
      
      const data = await response.json();
      if (data.success) {
        setVmScenarios(data.scenarios);
      }
    } catch (error) {
      console.error('Failed to fetch VM scenarios:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleOptionSelect = (optionId: string) => {
    setSelectedOption(optionId);
    onOptionSelect(optionId);
  };

  const handleScenarioSelect = (scenario: VMAttackScenario) => {
    setSelectedScenario(scenario);
    setShowConfiguration(true);
  };

  const handleExecuteAttack = () => {
    if (selectedScenario) {
      onVMAttackExecute(selectedScenario.id, attackConfig);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL': return 'bg-red-500 text-white';
      case 'HIGH': return 'bg-orange-500 text-white';
      case 'MEDIUM': return 'bg-yellow-500 text-black';
      case 'LOW': return 'bg-green-500 text-white';
      default: return 'bg-gray-500 text-white';
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'OWASP Top 10': return <Shield className="h-4 w-4" />;
      case 'MITRE ATT&CK': return <Target className="h-4 w-4" />;
      case 'STRIDE Threat Model': return <AlertTriangle className="h-4 w-4" />;
      default: return <Info className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Option Selection */}
      {!selectedOption && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {analysisOptions.map((option) => (
            <Card 
              key={option.id}
              className={`cursor-pointer transition-all hover:shadow-lg border-2 ${
                selectedOption === option.id ? 'border-blue-500' : 'border-gray-200'
              } ${option.recommended ? 'ring-2 ring-green-200' : ''}`}
              onClick={() => handleOptionSelect(option.id)}
            >
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    {option.icon}
                    <CardTitle className="text-lg">{option.name}</CardTitle>
                  </div>
                  {option.recommended && (
                    <Badge className="bg-green-100 text-green-800">Recommended</Badge>
                  )}
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-gray-600 mb-3">{option.description}</p>
                <ul className="space-y-1">
                  {option.features.map((feature, idx) => (
                    <li key={idx} className="text-xs text-gray-500 flex items-center">
                      <ChevronRight className="h-3 w-3 mr-1" />
                      {feature}
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* VM Attack Scenarios */}
      {(selectedOption === 'vm_attack_simulation' || selectedOption === 'combined_analysis') && !showConfiguration && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xl font-semibold">Available Attack Scenarios</h3>
            <Button variant="outline" onClick={() => setSelectedOption('')}>
              ← Back to Options
            </Button>
          </div>
          
          {loading ? (
            <div className="flex justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 max-h-96 overflow-y-auto">
              {vmScenarios.map((scenario) => (
                <Card 
                  key={scenario.id}
                  className="cursor-pointer hover:shadow-md transition-shadow"
                  onClick={() => handleScenarioSelect(scenario)}
                >
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center space-x-2">
                        {getCategoryIcon(scenario.category)}
                        <h4 className="font-medium text-sm">{scenario.name}</h4>
                      </div>
                      <Badge className={getSeverityColor(scenario.severity)}>
                        {scenario.severity}
                      </Badge>
                    </div>
                    
                    <p className="text-xs text-gray-600 mb-3 line-clamp-2">
                      {scenario.description}
                    </p>
                    
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div>
                        <span className="font-medium">Duration:</span>
                        <br />
                        <span className="text-gray-600">{scenario.estimated_duration}</span>
                      </div>
                      <div>
                        <span className="font-medium">Success Rate:</span>
                        <br />
                        <span className="text-gray-600">{(scenario.success_probability * 100).toFixed(0)}%</span>
                      </div>
                    </div>
                    
                    <div className="mt-3">
                      <Badge variant="outline" className="text-xs">
                        {scenario.category}
                      </Badge>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Attack Configuration */}
      {showConfiguration && selectedScenario && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h3 className="text-xl font-semibold">Configure Attack: {selectedScenario.name}</h3>
            <Button variant="outline" onClick={() => setShowConfiguration(false)}>
              ← Back to Scenarios
            </Button>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Settings className="h-5 w-5" />
                <span>Attack Parameters</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Intensity */}
              <div>
                <label className="block text-sm font-medium mb-2">Intensity Level</label>
                <div className="grid grid-cols-3 gap-2">
                  {['low', 'medium', 'high'].map((level) => (
                    <Button
                      key={level}
                      variant={attackConfig.intensity === level ? 'default' : 'outline'}
                      size="sm"
                      onClick={() => setAttackConfig({...attackConfig, intensity: level})}
                    >
                      {level.charAt(0).toUpperCase() + level.slice(1)}
                    </Button>
                  ))}
                </div>
              </div>

              {/* Stealth Level */}
              <div>
                <label className="block text-sm font-medium mb-2">Stealth Level</label>
                <div className="grid grid-cols-3 gap-2">
                  {['noisy', 'normal', 'stealthy'].map((level) => (
                    <Button
                      key={level}
                      variant={attackConfig.stealth_level === level ? 'default' : 'outline'}
                      size="sm"
                      onClick={() => setAttackConfig({...attackConfig, stealth_level: level})}
                    >
                      {level.charAt(0).toUpperCase() + level.slice(1)}
                    </Button>
                  ))}
                </div>
              </div>

              {/* Speed */}
              <div>
                <label className="block text-sm font-medium mb-2">Attack Speed</label>
                <div className="grid grid-cols-3 gap-2">
                  {['slow', 'normal', 'fast'].map((speed) => (
                    <Button
                      key={speed}
                      variant={attackConfig.speed === speed ? 'default' : 'outline'}
                      size="sm"
                      onClick={() => setAttackConfig({...attackConfig, speed: speed})}
                    >
                      {speed.charAt(0).toUpperCase() + speed.slice(1)}
                    </Button>
                  ))}
                </div>
              </div>

              {/* Scope */}
              <div>
                <label className="block text-sm font-medium mb-2">Attack Scope</label>
                <div className="grid grid-cols-3 gap-2">
                  {['single_target', 'multiple_targets', 'full_architecture'].map((scope) => (
                    <Button
                      key={scope}
                      variant={attackConfig.scope === scope ? 'default' : 'outline'}
                      size="sm"
                      onClick={() => setAttackConfig({...attackConfig, scope: scope})}
                    >
                      {scope.replace('_', ' ').split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')}
                    </Button>
                  ))}
                </div>
              </div>

              {/* Execute Button */}
              <div className="pt-4 border-t">
                <Button 
                  className="w-full bg-red-600 hover:bg-red-700 text-white"
                  onClick={handleExecuteAttack}
                >
                  <Play className="h-4 w-4 mr-2" />
                  Execute Attack Simulation
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Scenario Details */}
          <Card>
            <CardHeader>
              <CardTitle>Scenario Details</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <strong>Category:</strong> {selectedScenario.category}
                </div>
                <div>
                  <strong>Severity:</strong> 
                  <Badge className={`ml-2 ${getSeverityColor(selectedScenario.severity)}`}>
                    {selectedScenario.severity}
                  </Badge>
                </div>
                <div>
                  <strong>Duration:</strong> {selectedScenario.estimated_duration}
                </div>
                <div>
                  <strong>Success Rate:</strong> {(selectedScenario.success_probability * 100).toFixed(0)}%
                </div>
                <div className="col-span-2">
                  <strong>Description:</strong>
                  <p className="mt-1 text-gray-600">{selectedScenario.description}</p>
                </div>
                <div className="col-span-2">
                  <strong>Target Components:</strong>
                  <div className="mt-1 space-x-1">
                    {selectedScenario.target_components.map((component, idx) => (
                      <Badge key={idx} variant="outline" className="text-xs">
                        {component}
                      </Badge>
                    ))}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Regular Analysis */}
      {selectedOption === 'regular_security_analysis' && (
        <div className="text-center py-8">
          <Shield className="h-16 w-16 text-blue-600 mx-auto mb-4" />
          <h3 className="text-xl font-semibold mb-2">Regular Security Analysis</h3>
          <p className="text-gray-600 mb-4">
            Performing traditional security assessment using industry frameworks...
          </p>
          <Button onClick={() => setSelectedOption('')}>
            ← Back to Options
          </Button>
        </div>
      )}

      {/* Combined Analysis */}
      {selectedOption === 'combined_analysis' && !showConfiguration && vmScenarios.length > 0 && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xl font-semibold">Combined Analysis</h3>
            <Button variant="outline" onClick={() => setSelectedOption('')}>
              ← Back to Options
            </Button>
          </div>
          
          <Card>
            <CardHeader>
              <CardTitle>Recommended Actions</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-gray-600 mb-4">
                Based on your architecture analysis, we recommend executing these high-priority attack scenarios:
              </p>
              
              <div className="space-y-2">
                {vmScenarios.slice(0, 3).map((scenario, idx) => (
                  <div key={scenario.id} className="flex items-center justify-between p-3 border rounded">
                    <div className="flex items-center space-x-3">
                      <Badge className="w-6 h-6 rounded-full flex items-center justify-center text-xs">
                        {idx + 1}
                      </Badge>
                      <div>
                        <h4 className="font-medium text-sm">{scenario.name}</h4>
                        <p className="text-xs text-gray-600">{scenario.category}</p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Badge className={getSeverityColor(scenario.severity)}>
                        {scenario.severity}
                      </Badge>
                      <Button 
                        size="sm" 
                        variant="outline"
                        onClick={() => handleScenarioSelect(scenario)}
                      >
                        Configure
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
};

export default VMAttackOption;