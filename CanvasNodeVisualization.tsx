/**
 * CANVAS NODE STATUS VISUALIZATION
 * ================================
 * 
 * React component for real-time visualization of node status during VM attacks.
 * Shows compromised/safe/under attack status with visual indicators.
 */

import React, { useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { 
  Shield, 
  ShieldAlert, 
  ShieldX, 
  Zap, 
  AlertTriangle,
  Eye,
  Activity,
  Clock
} from 'lucide-react';

interface NodeStatus {
  status: 'safe' | 'under_attack' | 'compromised';
  compromise_level: number;
  last_updated: string;
  attack_indicators: Array<{
    type: string;
    severity: string;
    timestamp: string;
  }>;
  security_events: Array<{
    event_type: string;
    description: string;
    timestamp: string;
  }>;
}

interface CanvasState {
  [nodeId: string]: NodeStatus;
}

interface CanvasNodeVisualizationProps {
  architecture: any;
  canvasState: CanvasState;
  simulationActive: boolean;
  onNodeClick?: (nodeId: string) => void;
}

export const CanvasNodeVisualization: React.FC<CanvasNodeVisualizationProps> = ({
  architecture,
  canvasState,
  simulationActive,
  onNodeClick
}) => {
  const [animatedNodes, setAnimatedNodes] = useState<Set<string>>(new Set());
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  useEffect(() => {
    // Animate nodes when their status changes
    Object.entries(canvasState).forEach(([nodeId, status]) => {
      if (status.status === 'under_attack' || status.status === 'compromised') {
        setAnimatedNodes(prev => new Set(prev).add(nodeId));
        
        // Remove animation after 2 seconds
        setTimeout(() => {
          setAnimatedNodes(prev => {
            const newSet = new Set(prev);
            newSet.delete(nodeId);
            return newSet;
          });
        }, 2000);
      }
    });
  }, [canvasState]);

  const getNodeStatusColor = (status: string, compromise_level: number) => {
    switch (status) {
      case 'safe':
        return 'border-green-500 bg-green-50';
      case 'under_attack':
        return 'border-yellow-500 bg-yellow-50 animate-pulse';
      case 'compromised':
        const intensity = compromise_level > 70 ? 'border-red-600 bg-red-100' : 
                         compromise_level > 40 ? 'border-red-500 bg-red-50' :
                         'border-orange-500 bg-orange-50';
        return intensity;
      default:
        return 'border-gray-300 bg-gray-50';
    }
  };

  const getNodeIcon = (status: string, compromise_level: number) => {
    switch (status) {
      case 'safe':
        return <Shield className="h-5 w-5 text-green-600" />;
      case 'under_attack':
        return <ShieldAlert className="h-5 w-5 text-yellow-600 animate-pulse" />;
      case 'compromised':
        return compromise_level > 70 ? 
               <ShieldX className="h-5 w-5 text-red-600" /> :
               <AlertTriangle className="h-5 w-5 text-orange-600" />;
      default:
        return <Shield className="h-5 w-5 text-gray-400" />;
    }
  };

  const getStatusBadge = (status: string, compromise_level: number) => {
    switch (status) {
      case 'safe':
        return <Badge className="bg-green-100 text-green-800">SECURE</Badge>;
      case 'under_attack':
        return <Badge className="bg-yellow-100 text-yellow-800 animate-pulse">UNDER ATTACK</Badge>;
      case 'compromised':
        const severity = compromise_level > 70 ? 'CRITICAL' : 
                        compromise_level > 40 ? 'HIGH' : 'MEDIUM';
        const bgColor = compromise_level > 70 ? 'bg-red-100 text-red-800' :
                       compromise_level > 40 ? 'bg-red-100 text-red-700' :
                       'bg-orange-100 text-orange-800';
        return <Badge className={bgColor}>{severity} COMPROMISE</Badge>;
      default:
        return <Badge className="bg-gray-100 text-gray-800">UNKNOWN</Badge>;
    }
  };

  const handleNodeClick = (nodeId: string) => {
    setSelectedNode(selectedNode === nodeId ? null : nodeId);
    if (onNodeClick) {
      onNodeClick(nodeId);
    }
  };

  const getTimeSince = (timestamp: string) => {
    const now = new Date();
    const then = new Date(timestamp);
    const diffMs = now.getTime() - then.getTime();
    const diffSecs = Math.floor(diffMs / 1000);
    
    if (diffSecs < 60) return `${diffSecs}s ago`;
    if (diffSecs < 3600) return `${Math.floor(diffSecs / 60)}m ago`;
    return `${Math.floor(diffSecs / 3600)}h ago`;
  };

  const nodes = architecture?.nodes || [];

  return (
    <div className="space-y-4">
      {/* Simulation Status Header */}
      {simulationActive && (
        <Card className="bg-blue-50 border-blue-200">
          <CardContent className="p-4">
            <div className="flex items-center space-x-3">
              <Activity className="h-5 w-5 text-blue-600 animate-pulse" />
              <div>
                <h3 className="font-medium text-blue-900">VM Attack Simulation Active</h3>
                <p className="text-sm text-blue-700">
                  Real-time monitoring of attack impact on architecture components
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Node Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {nodes.map((node) => {
          const nodeId = node.id;
          const status = canvasState[nodeId] || { 
            status: 'safe', 
            compromise_level: 0, 
            last_updated: new Date().toISOString(),
            attack_indicators: [],
            security_events: []
          };
          const isAnimated = animatedNodes.has(nodeId);
          const isSelected = selectedNode === nodeId;

          return (
            <Card
              key={nodeId}
              className={`cursor-pointer transition-all duration-200 hover:shadow-md ${
                getNodeStatusColor(status.status, status.compromise_level)
              } ${isAnimated ? 'ring-2 ring-blue-400' : ''} ${
                isSelected ? 'ring-2 ring-purple-400' : ''
              }`}
              onClick={() => handleNodeClick(nodeId)}
            >
              <CardContent className="p-4">
                {/* Node Header */}
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-2">
                    {getNodeIcon(status.status, status.compromise_level)}
                    <h4 className="font-medium text-sm truncate">
                      {node.name || node.label || nodeId}
                    </h4>
                  </div>
                  {status.status !== 'safe' && (
                    <Zap className="h-4 w-4 text-yellow-600" />
                  )}
                </div>

                {/* Status Badge */}
                <div className="mb-3">
                  {getStatusBadge(status.status, status.compromise_level)}
                </div>

                {/* Node Type */}
                <div className="text-xs text-gray-600 mb-2">
                  Type: {node.type || 'Unknown'}
                </div>

                {/* Compromise Level Bar */}
                {status.status === 'compromised' && (
                  <div className="mb-3">
                    <div className="flex justify-between text-xs mb-1">
                      <span>Compromise Level</span>
                      <span>{status.compromise_level}%</span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div 
                        className={`h-2 rounded-full transition-all duration-500 ${
                          status.compromise_level > 70 ? 'bg-red-600' :
                          status.compromise_level > 40 ? 'bg-red-500' : 'bg-orange-500'
                        }`}
                        style={{ width: `${status.compromise_level}%` }}
                      />
                    </div>
                  </div>
                )}

                {/* Last Updated */}
                <div className="flex items-center text-xs text-gray-500">
                  <Clock className="h-3 w-3 mr-1" />
                  Updated {getTimeSince(status.last_updated)}
                </div>

                {/* Attack Indicators Count */}
                {status.attack_indicators.length > 0 && (
                  <div className="mt-2 text-xs">
                    <Badge variant="outline" className="text-red-700 border-red-300">
                      {status.attack_indicators.length} attack indicator{status.attack_indicators.length !== 1 ? 's' : ''}
                    </Badge>
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Selected Node Details */}
      {selectedNode && canvasState[selectedNode] && (
        <Card className="mt-6">
          <CardContent className="p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold flex items-center space-x-2">
                <Eye className="h-5 w-5" />
                <span>Node Details: {nodes.find(n => n.id === selectedNode)?.name || selectedNode}</span>
              </h3>
              <button 
                onClick={() => setSelectedNode(null)}
                className="text-gray-500 hover:text-gray-700"
              >
                ✕
              </button>
            </div>

            {(() => {
              const nodeStatus = canvasState[selectedNode];
              const node = nodes.find(n => n.id === selectedNode);
              
              return (
                <div className="space-y-4">
                  {/* Basic Info */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div>
                      <span className="font-medium">Status:</span>
                      <div className="mt-1">
                        {getStatusBadge(nodeStatus.status, nodeStatus.compromise_level)}
                      </div>
                    </div>
                    <div>
                      <span className="font-medium">Type:</span>
                      <div className="mt-1 text-gray-600">{node?.type || 'Unknown'}</div>
                    </div>
                    <div>
                      <span className="font-medium">Compromise Level:</span>
                      <div className="mt-1 text-gray-600">{nodeStatus.compromise_level}%</div>
                    </div>
                    <div>
                      <span className="font-medium">Last Updated:</span>
                      <div className="mt-1 text-gray-600">{getTimeSince(nodeStatus.last_updated)}</div>
                    </div>
                  </div>

                  {/* Attack Indicators */}
                  {nodeStatus.attack_indicators.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2">Attack Indicators</h4>
                      <div className="space-y-2 max-h-32 overflow-y-auto">
                        {nodeStatus.attack_indicators.map((indicator, idx) => (
                          <div key={idx} className="flex items-center justify-between p-2 bg-red-50 rounded border border-red-200">
                            <div className="flex items-center space-x-2">
                              <AlertTriangle className="h-4 w-4 text-red-600" />
                              <span className="text-sm font-medium">{indicator.type}</span>
                            </div>
                            <div className="text-xs text-gray-600">
                              <Badge className={`mr-2 ${
                                indicator.severity === 'HIGH' ? 'bg-red-100 text-red-800' :
                                indicator.severity === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800' :
                                'bg-gray-100 text-gray-800'
                              }`}>
                                {indicator.severity}
                              </Badge>
                              {getTimeSince(indicator.timestamp)}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Security Events */}
                  {nodeStatus.security_events.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2">Security Events</h4>
                      <div className="space-y-2 max-h-32 overflow-y-auto">
                        {nodeStatus.security_events.map((event, idx) => (
                          <div key={idx} className="flex items-start justify-between p-2 bg-blue-50 rounded border border-blue-200">
                            <div className="flex items-start space-x-2">
                              <Activity className="h-4 w-4 text-blue-600 mt-0.5" />
                              <div>
                                <div className="text-sm font-medium">{event.event_type}</div>
                                <div className="text-xs text-gray-600">{event.description}</div>
                              </div>
                            </div>
                            <div className="text-xs text-gray-500">
                              {getTimeSince(event.timestamp)}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Safe Status Message */}
                  {nodeStatus.status === 'safe' && nodeStatus.attack_indicators.length === 0 && (
                    <div className="text-center py-4 text-green-600">
                      <Shield className="h-8 w-8 mx-auto mb-2" />
                      <p className="text-sm font-medium">This component is secure</p>
                      <p className="text-xs text-gray-600">No attack indicators or security events detected</p>
                    </div>
                  )}
                </div>
              );
            })()}
          </CardContent>
        </Card>
      )}

      {/* Legend */}
      <Card className="mt-6">
        <CardContent className="p-4">
          <h4 className="font-medium mb-3">Status Legend</h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
            <div className="flex items-center space-x-2">
              <Shield className="h-4 w-4 text-green-600" />
              <span>Secure</span>
            </div>
            <div className="flex items-center space-x-2">
              <ShieldAlert className="h-4 w-4 text-yellow-600" />
              <span>Under Attack</span>
            </div>
            <div className="flex items-center space-x-2">
              <ShieldX className="h-4 w-4 text-red-600" />
              <span>Compromised</span>
            </div>
            <div className="flex items-center space-x-2">
              <Zap className="h-4 w-4 text-yellow-600" />
              <span>Active Threat</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default CanvasNodeVisualization;