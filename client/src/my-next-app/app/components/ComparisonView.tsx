/**
 * Architecture Comparison View
 * Side-by-side comparison of original vs corrected architecture
 */

'use client';

import React, { useState } from 'react';
import { Node, Edge } from 'reactflow';
import { FlowCanvasWrapper } from './flow/FlowCanvas';
import { CustomNodeData, CustomEdgeData } from '../types';
import { SuggestedArchitecture } from '../types/attack';

interface ComparisonViewProps {
  isOpen: boolean;
  onClose: () => void;
  originalNodes: Node<CustomNodeData>[];
  originalEdges: Edge<CustomEdgeData>[];
  suggestedArchitecture: SuggestedArchitecture;
  onAccept: () => void;
  onReject: () => void;
}

export const ComparisonView: React.FC<ComparisonViewProps> = ({
  isOpen,
  onClose,
  originalNodes,
  originalEdges,
  suggestedArchitecture,
  onAccept,
  onReject,
}) => {
  const [selectedTab, setSelectedTab] = useState<'comparison' | 'changes' | 'recommendations'>('comparison');

  if (!isOpen) return null;

  // Convert suggested architecture to React Flow format
  const correctedNodes: Node<CustomNodeData>[] = suggestedArchitecture.new_architecture.components.map((comp: any, index) => {
    // Get component icon based on type
    const getComponentIcon = (type: string): string => {
      const icons: Record<string, string> = {
        waf: '🛡️', firewall: '🔥', ids_ips: '🚨', vpn_gateway: '🔐',
        load_balancer: '⚖️', web_server: '🌐', database: '🗄️', siem: '🔍',
        user_device: '💻', application_server: '💼', api_gateway: '🚪',
        cache_server: '📦', file_storage: '📁', backup_server: '💿'
      };
      return icons[type] || '🔧';
    };

    return {
      id: comp.id || `node-${index}`,
      type: 'custom',
      position: comp.position || { x: (index % 3) * 250 + 100, y: Math.floor(index / 3) * 150 + 100 },
      data: {
        id: comp.id || `node-${index}`,
        type: comp.type || 'server',
        component_type: comp.type || comp.component_type || 'server',
        name: comp.name || comp.label || comp.component_type || `${comp.type || 'Server'} ${index + 1}`,
        icon: getComponentIcon(comp.type || comp.component_type || 'server'),
        description: comp.description || `Secured ${comp.type || 'component'}`,
        category: comp.category || 'security',
        properties: comp.properties || {},
        configured: true
      } as CustomNodeData,
    };
  });

  const correctedEdges: Edge<CustomEdgeData>[] = suggestedArchitecture.new_architecture.connections.map((conn: any, index) => ({
    id: conn.id || `edge-${index}`,
    source: conn.source,
    target: conn.target,
    type: 'default',
    animated: true,
    style: {
      stroke: 'url(#edge-gradient)',
      strokeWidth: 2
    },
    data: {
      id: conn.id || `edge-${index}`,
      type: conn.type || 'network',
      properties: conn.properties || {}
    } as CustomEdgeData,
  }));

  const changeSummary = suggestedArchitecture.change_summary;

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl w-full h-full max-w-[95vw] max-h-[95vh] flex flex-col overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-700 bg-gradient-to-r from-blue-900/20 to-purple-900/20">
          <div>
            <h2 className="text-2xl font-bold text-white flex items-center gap-3">
              <span className="text-3xl">🔄</span>
              Architecture Comparison
            </h2>
            <p className="text-gray-400 text-sm mt-1">
              Review the security improvements suggested for your architecture
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors text-2xl w-10 h-10 flex items-center justify-center rounded-lg hover:bg-gray-800"
          >
            ✕
          </button>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-gray-700 bg-gray-800/50">
          <button
            onClick={() => setSelectedTab('comparison')}
            className={`px-6 py-3 font-medium transition-colors ${
              selectedTab === 'comparison'
                ? 'text-white border-b-2 border-blue-500 bg-gray-800'
                : 'text-gray-400 hover:text-white hover:bg-gray-800/50'
            }`}
          >
            Side-by-Side Comparison
          </button>
          <button
            onClick={() => setSelectedTab('changes')}
            className={`px-6 py-3 font-medium transition-colors ${
              selectedTab === 'changes'
                ? 'text-white border-b-2 border-blue-500 bg-gray-800'
                : 'text-gray-400 hover:text-white hover:bg-gray-800/50'
            }`}
          >
            Changes Summary ({changeSummary.total_changes})
          </button>
          <button
            onClick={() => setSelectedTab('recommendations')}
            className={`px-6 py-3 font-medium transition-colors ${
              selectedTab === 'recommendations'
                ? 'text-white border-b-2 border-blue-500 bg-gray-800'
                : 'text-gray-400 hover:text-white hover:bg-gray-800/50'
            }`}
          >
            Security Improvements
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-hidden">
          {selectedTab === 'comparison' && (
            <div className="h-full grid grid-cols-2 gap-0 divide-x divide-gray-700">
              {/* Original Architecture */}
              <div className="flex flex-col">
                <div className="p-4 bg-red-900/20 border-b border-gray-700">
                  <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    <span className="text-red-400">📍</span>
                    Original Architecture
                  </h3>
                  <p className="text-sm text-gray-400 mt-1">Current vulnerable state</p>
                </div>
                <div className="flex-1 relative bg-gray-800/30">
                  <FlowCanvasWrapper
                    nodes={originalNodes}
                    edges={originalEdges}
                    onNodeSelect={() => {}}
                    onEdgeSelect={() => {}}
                    onArchitectureChange={() => {}}
                    updateNodeRef={{ current: null }}
                    updateEdgeRef={{ current: null }}
                  />
                </div>
              </div>

              {/* Corrected Architecture */}
              <div className="flex flex-col">
                <div className="p-4 bg-green-900/20 border-b border-gray-700">
                  <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    <span className="text-green-400">✅</span>
                    Improved Architecture
                  </h3>
                  <p className="text-sm text-gray-400 mt-1">
                    Secured with {changeSummary.added_components.length} new security components
                  </p>
                </div>
                <div className="flex-1 relative bg-gray-800/30">
                  <FlowCanvasWrapper
                    nodes={correctedNodes}
                    edges={correctedEdges}
                    onNodeSelect={() => {}}
                    onEdgeSelect={() => {}}
                    onArchitectureChange={() => {}}
                    updateNodeRef={{ current: null }}
                    updateEdgeRef={{ current: null }}
                  />
                </div>
              </div>
            </div>
          )}

          {selectedTab === 'changes' && (
            <div className="h-full overflow-y-auto p-6 space-y-6">
              {/* Added Components */}
              {changeSummary.added_components.length > 0 && (
                <div className="space-y-3">
                  <h3 className="text-lg font-bold text-green-400 flex items-center gap-2">
                    <span>➕</span>
                    Added Components ({changeSummary.added_components.length})
                  </h3>
                  <div className="space-y-2">
                    {changeSummary.added_components.map((component, index) => (
                      <div
                        key={index}
                        className="p-4 bg-green-900/10 border border-green-700/30 rounded-lg"
                      >
                        <div className="flex items-start justify-between">
                          <div>
                            <div className="font-medium text-white">
                              {component.label || component.type}
                            </div>
                            <div className="text-sm text-gray-400 mt-1">{component.reason}</div>
                          </div>
                          <span className="px-2 py-1 bg-green-600 text-white text-xs rounded">
                            {component.type}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Modified Components */}
              {changeSummary.modified_components.length > 0 && (
                <div className="space-y-3">
                  <h3 className="text-lg font-bold text-yellow-400 flex items-center gap-2">
                    <span>🔄</span>
                    Modified Components ({changeSummary.modified_components.length})
                  </h3>
                  <div className="space-y-2">
                    {changeSummary.modified_components.map((component, index) => (
                      <div
                        key={index}
                        className="p-4 bg-yellow-900/10 border border-yellow-700/30 rounded-lg"
                      >
                        <div className="font-medium text-white mb-2">{component.id}</div>
                        <ul className="text-sm text-gray-400 space-y-1 list-disc list-inside">
                          {component.changes.map((change, idx) => (
                            <li key={idx}>{change}</li>
                          ))}
                        </ul>
                        <div className="text-xs text-yellow-400 mt-2">{component.reason}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Added Connections */}
              {changeSummary.added_connections.length > 0 && (
                <div className="space-y-3">
                  <h3 className="text-lg font-bold text-blue-400 flex items-center gap-2">
                    <span>🔗</span>
                    New Connections ({changeSummary.added_connections.length})
                  </h3>
                  <div className="space-y-2">
                    {changeSummary.added_connections.map((connection, index) => (
                      <div
                        key={index}
                        className="p-4 bg-blue-900/10 border border-blue-700/30 rounded-lg flex items-center justify-between"
                      >
                        <div className="flex items-center gap-3">
                          <span className="text-white font-mono">{connection.source}</span>
                          <span className="text-blue-400">→</span>
                          <span className="text-white font-mono">{connection.target}</span>
                        </div>
                        <span className="text-sm text-gray-400">{connection.reason}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {selectedTab === 'recommendations' && (
            <div className="h-full overflow-y-auto p-6 space-y-6">
              {/* Security Improvements */}
              <div className="space-y-3">
                <h3 className="text-xl font-bold text-white flex items-center gap-2">
                  <span>🛡️</span>
                  Security Improvements
                </h3>
                <div className="grid gap-3">
                  {changeSummary.security_improvements.map((improvement, index) => (
                    <div
                      key={index}
                      className="p-4 bg-blue-900/10 border border-blue-700/30 rounded-lg flex items-start gap-3"
                    >
                      <span className="text-blue-400 text-xl flex-shrink-0">✓</span>
                      <span className="text-gray-300">{improvement}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Mitigated Vulnerabilities */}
              <div className="space-y-3">
                <h3 className="text-xl font-bold text-white flex items-center gap-2">
                  <span>🎯</span>
                  Mitigated Vulnerabilities
                </h3>
                <div className="grid gap-3">
                  {changeSummary.mitigated_vulnerabilities.map((vulnerability, index) => (
                    <div
                      key={index}
                      className="p-4 bg-green-900/10 border border-green-700/30 rounded-lg flex items-start gap-3"
                    >
                      <span className="text-green-400 text-xl flex-shrink-0">🔒</span>
                      <span className="text-gray-300">{vulnerability}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Attack Mitigation */}
              <div className="p-6 bg-purple-900/10 border border-purple-700/30 rounded-lg">
                <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                  <span>⚡</span>
                  Attack Mitigation: {suggestedArchitecture.attack_mitigation.attack_name}
                </h3>
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="text-gray-400">Status:</span>
                    <span className={`px-3 py-1 rounded text-sm font-medium ${
                      suggestedArchitecture.attack_mitigation.prevented
                        ? 'bg-green-600 text-white'
                        : 'bg-red-600 text-white'
                    }`}>
                      {suggestedArchitecture.attack_mitigation.prevented ? 'Prevented' : 'Not Fully Mitigated'}
                    </span>
                  </div>
                  <div className="mt-4">
                    <div className="text-sm text-gray-400 mb-2">Mitigation Techniques:</div>
                    <div className="space-y-2">
                      {suggestedArchitecture.attack_mitigation.mitigation_techniques.map((technique: any, index) => (
                        <div key={index} className="text-sm text-gray-300 flex items-start gap-2">
                          <span className="text-purple-400">•</span>
                          <span>{typeof technique === 'string' ? technique : technique.action}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer - Action Buttons */}
        <div className="p-6 border-t border-gray-700 bg-gray-800/50 flex items-center justify-between">
          <div className="text-sm text-gray-400">
            {changeSummary.total_changes} changes • {changeSummary.security_improvements.length} improvements
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={onReject}
              className="px-6 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
            >
              Keep Original
            </button>
            <button
              onClick={onAccept}
              className="px-6 py-3 bg-green-600 hover:bg-green-700 text-white font-bold rounded-lg transition-colors flex items-center gap-2"
            >
              <span>✓</span>
              Accept Improved Architecture
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
