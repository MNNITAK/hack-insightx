/**
 * COMPLETE VM ATTACK INTEGRATION COMPONENT
 * ========================================
 * 
 * This component integrates VM attack functionality with your existing canvas.
 * Add this to your main architecture analysis component.
 */

import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  Shield, 
  Target, 
  Zap, 
  Play, 
  Settings,
  Eye,
  AlertTriangle,
  Activity
} from 'lucide-react';

// Import the hook we just created
import { useVMAttackAPI } from './useVMAttackAPI';

interface VMAttackIntegrationProps {
  // Your existing architecture data
  architecture: {
    metadata?: any;
    nodes: Array<{
      id: string;
      name: string;
      type: string;
      label?: string;
    }>;
    connections: any[];
  };
  
  // Your existing canvas update function
  onCanvasNodeUpdate?: (nodeId: string, status: 'safe' | 'under_attack' | 'compromised', data?: any) => void;
  
  // Callback when analysis type is selected
  onAnalysisTypeChange?: (type: 'regular' | 'vm_attack' | 'combined') => void;
}

export const VMAttackIntegration: React.FC<VMAttackIntegrationProps> = ({
  architecture,
  onCanvasNodeUpdate,
  onAnalysisTypeChange
}) => {
  // Use our API hook
  const {
    loading,
    error,
    canvasState,
    simulationActive,
    getAnalysisOptions,
    getVMAttackScenarios,
    executeVMAttack,
    performCombinedAnalysis
  } = useVMAttackAPI();

  // Component state
  const [analysisType, setAnalysisType] = useState<string>('');
  const [attackScenarios, setAttackScenarios] = useState<any[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<any>(null);
  const [attackConfig, setAttackConfig] = useState({
    intensity: 'medium',
    stealth_level: 'normal',
    speed: 'normal',
    scope: 'multiple_targets'
  });
  const [showConfiguration, setShowConfiguration] = useState(false);

  // Update canvas when canvasState changes
  useEffect(() => {
    if (onCanvasNodeUpdate) {
      Object.entries(canvasState).forEach(([nodeId, state]) => {
        onCanvasNodeUpdate(nodeId, state.status, {
          compromise_level: state.compromise_level,
          attack_indicators: state.attack_indicators
        });
      });
    }
  }, [canvasState, onCanvasNodeUpdate]);

  // Handle analysis type selection
  const handleAnalysisTypeSelect = async (type: string) => {
    setAnalysisType(type);
    onAnalysisTypeChange?.(type as any);

    if (type === 'vm_attack' || type === 'combined') {
      // Load VM attack scenarios
      const scenarios = await getVMAttackScenarios(architecture);
      setAttackScenarios(scenarios);
    }
  };

  // Handle scenario selection
  const handleScenarioSelect = (scenario: any) => {
    setSelectedScenario(scenario);
    setShowConfiguration(true);
  };

  // Execute VM attack
  const handleExecuteAttack = async () => {
    if (!selectedScenario) return;

    const result = await executeVMAttack(
      architecture,
      selectedScenario.id,
      attackConfig
    );

    if (result) {
      // Attack executed successfully
      console.log('VM Attack completed:', result);
    }
  };

  // Handle combined analysis
  const handleCombinedAnalysis = async () => {
    const result = await performCombinedAnalysis(architecture);
    if (result) {
      console.log('Combined analysis completed:', result);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'bg-red-500 text-white';
      case 'HIGH': return 'bg-orange-500 text-white';
      case 'MEDIUM': return 'bg-yellow-500 text-black';
      case 'LOW': return 'bg-green-500 text-white';
      default: return 'bg-gray-500 text-white';
    }
  };

  return (
    <div className="space-y-6">
      {/* Error Display */}
      {error && (
        <Alert className="border-red-200 bg-red-50">
          <AlertTriangle className="h-4 w-4 text-red-600" />
          <AlertDescription className="text-red-800">{error}</AlertDescription>
        </Alert>
      )}

      {/* Analysis Type Selection */}
      {!analysisType && (
        <Card>
          <CardHeader>
            <CardTitle>Choose Analysis Type</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Regular Analysis */}
              <Button
                variant="outline"
                className="h-auto p-4 flex flex-col items-start space-y-2"
                onClick={() => handleAnalysisTypeSelect('regular')}
              >
                <Shield className="h-8 w-8 text-blue-600" />
                <div className="text-left">
                  <h3 className="font-semibold">Regular Security Analysis</h3>
                  <p className="text-sm text-gray-600">Traditional OWASP, MITRE, STRIDE analysis</p>
                </div>
              </Button>

              {/* VM Attack Simulation */}
              <Button
                variant="outline"
                className="h-auto p-4 flex flex-col items-start space-y-2 border-green-200 bg-green-50"
                onClick={() => handleAnalysisTypeSelect('vm_attack')}
              >
                <Target className="h-8 w-8 text-red-600" />
                <div className="text-left">
                  <h3 className="font-semibold">VM Attack Simulation</h3>
                  <p className="text-sm text-gray-600">Interactive attack scenarios with canvas updates</p>
                  <Badge className="bg-green-100 text-green-800 mt-1">Recommended</Badge>
                </div>
              </Button>

              {/* Combined Analysis */}
              <Button
                variant="outline"
                className="h-auto p-4 flex flex-col items-start space-y-2"
                onClick={() => handleAnalysisTypeSelect('combined')}
              >
                <Zap className="h-8 w-8 text-purple-600" />
                <div className="text-left">
                  <h3 className="font-semibold">Combined Analysis</h3>
                  <p className="text-sm text-gray-600">Security analysis + VM attack simulation</p>
                </div>
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* VM Attack Scenarios */}
      {analysisType === 'vm_attack' && !showConfiguration && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Available Attack Scenarios ({attackScenarios.length})</span>
              <Button variant="outline" size="sm" onClick={() => setAnalysisType('')}>
                ← Back
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="flex justify-center py-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              </div>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 max-h-96 overflow-y-auto">
                {attackScenarios.map((scenario) => (
                  <Card 
                    key={scenario.id}
                    className="cursor-pointer hover:shadow-md transition-shadow"
                    onClick={() => handleScenarioSelect(scenario)}
                  >
                    <CardContent className="p-4">
                      <div className="flex items-start justify-between mb-2">
                        <h4 className="font-medium text-sm">{scenario.name}</h4>
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
                      <Badge variant="outline" className="text-xs mt-2">
                        {scenario.category}
                      </Badge>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Attack Configuration */}
      {showConfiguration && selectedScenario && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Configure: {selectedScenario.name}</span>
              <Button variant="outline" size="sm" onClick={() => setShowConfiguration(false)}>
                ← Back
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Intensity */}
            <div>
              <label className="block text-sm font-medium mb-2">Attack Intensity</label>
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

            {/* Execute Button */}
            <div className="pt-4 border-t">
              <Button 
                className="w-full bg-red-600 hover:bg-red-700 text-white"
                onClick={handleExecuteAttack}
                disabled={loading || simulationActive}
              >
                <Play className="h-4 w-4 mr-2" />
                {simulationActive ? 'Executing Attack...' : 'Execute Attack Simulation'}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Combined Analysis */}
      {analysisType === 'combined' && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Combined Security Analysis</span>
              <Button variant="outline" size="sm" onClick={() => setAnalysisType('')}>
                ← Back
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-gray-600 mb-4">
              This will perform comprehensive security analysis plus execute top attack scenarios.
            </p>
            <Button 
              className="w-full"
              onClick={handleCombinedAnalysis}
              disabled={loading}
            >
              <Zap className="h-4 w-4 mr-2" />
              Start Combined Analysis
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Regular Analysis */}
      {analysisType === 'regular' && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span>Regular Security Analysis</span>
              <Button variant="outline" size="sm" onClick={() => setAnalysisType('')}>
                ← Back
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-gray-600 mb-4">
              Performing traditional security assessment using OWASP, MITRE, and STRIDE frameworks...
            </p>
            {/* Your existing regular analysis component would go here */}
          </CardContent>
        </Card>
      )}

      {/* Simulation Active Status */}
      {simulationActive && (
        <Card className="bg-blue-50 border-blue-200">
          <CardContent className="p-4">
            <div className="flex items-center space-x-3">
              <Activity className="h-5 w-5 text-blue-600 animate-pulse" />
              <div>
                <h3 className="font-medium text-blue-900">VM Attack Simulation Active</h3>
                <p className="text-sm text-blue-700">
                  Watch your canvas for real-time node status updates
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default VMAttackIntegration;