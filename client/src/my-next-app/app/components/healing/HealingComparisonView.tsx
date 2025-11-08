"use client";

import React, { useState, useCallback, useMemo } from 'react';
import ReactFlow, {
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  BackgroundVariant
} from 'reactflow';
import 'reactflow/dist/style.css';
import { HealingResult } from './HealingModal';
import { CustomNode } from '../../types';

interface HealingComparisonViewProps {
  healingResult: HealingResult;
  originalArchitecture: {
    nodes: CustomNode[];
    edges: any[];
  };
  onAccept: () => void;
  onReject: () => void;
  onClose: () => void;
}

// Helper functions outside component to avoid hoisting issues
const getComponentIcon = (type: string): string => {
  const icons: Record<string, string> = {
    waf: '🛡️',
    firewall: '🔥',
    ids_ips: '🚨',
    vpn_gateway: '🔐',
    load_balancer: '⚖️',
    web_server: '🌐',
    database: '🗄️',
    siem: '🔍',
    user_device: '💻',
    application_server: '💼',
    api_gateway: '🚪'
  };
  return icons[type] || '📦';
};


const isSecurityComponent = (type: string): boolean => {
  const securityTypes = ['waf', 'firewall', 'ids_ips', 'vpn_gateway', 'siem', 'certificate_authority', 'dlp_system', 'secrets_manager'];
  return securityTypes.includes(type);
};

const getSeverityColor = (severity: string) => {
  const colors: Record<string, string> = {
    CRITICAL: 'bg-red-900/20 text-red-300 border-red-700',
    HIGH: 'bg-orange-900/20 text-orange-300 border-orange-700',
    MEDIUM: 'bg-yellow-900/20 text-yellow-300 border-yellow-700',
    LOW: 'bg-blue-900/20 text-blue-300 border-blue-700'
  };
  return colors[severity] || 'bg-gray-800 text-gray-300 border-gray-600';
};

export const HealingComparisonView: React.FC<HealingComparisonViewProps> = ({
  healingResult,
  originalArchitecture,
  onAccept,
  onReject,
  onClose
}) => {
  const [activeView, setActiveView] = useState<'split' | 'original' | 'healed'>('split');

  // Convert original architecture to ReactFlow format
  const originalNodes: Node[] = useMemo(() => 
    originalArchitecture.nodes.map(node => ({
      id: node.id,
      type: 'default',
      position: node.position,
      data: {
        label: (
          <div className="text-center">
            <div className="text-2xl mb-1">{node.data.icon || '📦'}</div>
            <div className="text-xs font-medium">{node.data.name || node.data.component_type}</div>
          </div>
        )
      },
      style: {
        background: '#1f2937',
        border: '2px solid #ef4444',
        borderRadius: '8px',
        padding: '10px',
        minWidth: '100px',
        color: '#f3f4f6'
      }
    }))
  , [originalArchitecture]);

  const originalEdges: Edge[] = useMemo(() =>
    originalArchitecture.edges.map(edge => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      type: 'smoothstep',
      style: { stroke: '#ef4444', strokeWidth: 2 },
      animated: false
    }))
  , [originalArchitecture]);

  // Convert healed architecture to ReactFlow format
  const healedNodes: Node[] = useMemo(() =>
    healingResult.healed_architecture.nodes.map((node: any, idx: number) => ({
      id: node.id,
      type: 'default',
      position: node.position || { x: (idx % 3) * 200 + 100, y: Math.floor(idx / 3) * 150 + 100 },
      data: {
        label: (
          <div className="text-center">
            <div className="text-2xl mb-1">
              {getComponentIcon(node.component_type)}
            </div>
            <div className="text-xs font-medium">{node.name || node.component_type}</div>
            {isSecurityComponent(node.component_type) && (
              <div className="text-xs text-green-600 mt-1">🛡️ NEW</div>
            )}
          </div>
        )
      },
      style: {
        background: isSecurityComponent(node.component_type) ? '#064e3b' : '#1e3a8a',
        border: isSecurityComponent(node.component_type) ? '2px solid #22c55e' : '2px solid #3b82f6',
        borderRadius: '8px',
        padding: '10px',
        minWidth: '100px',
        color: '#f3f4f6'
      }
    }))
  , [healingResult]);

  const healedEdges: Edge[] = useMemo(() =>
    healingResult.healed_architecture.connections.map((conn: any) => ({
      id: conn.id,
      source: conn.source,
      target: conn.target,
      type: 'smoothstep',
      style: { stroke: '#22c55e', strokeWidth: 2 },
      animated: conn.type === 'encrypted',
      label: conn.type === 'encrypted' ? '🔒' : undefined
    }))
  , [healingResult]);

  return (
    <div className="fixed inset-0 z-50 bg-gray-900/95 backdrop-blur-sm">
      {/* Header */}
      <div className="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold text-white">Architecture Healing - Comparison View</h2>
            <p className="text-sm text-gray-300 mt-1">
              Review vulnerabilities and accept the secured architecture
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-200 text-2xl font-bold"
          >
            ×
          </button>
        </div>

        {/* View Toggles */}
        <div className="flex gap-2 mt-4">
          <button
            onClick={() => setActiveView('split')}
            className={`px-4 py-2 rounded-lg font-medium transition-all ${
              activeView === 'split'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-700 text-gray-200 hover:bg-gray-600'
            }`}
          >
            ⚔️ Split View
          </button>
          <button
            onClick={() => setActiveView('original')}
            className={`px-4 py-2 rounded-lg font-medium transition-all ${
              activeView === 'original'
                ? 'bg-red-600 text-white'
                : 'bg-gray-700 text-gray-200 hover:bg-gray-600'
            }`}
          >
            🔴 Vulnerable
          </button>
          <button
            onClick={() => setActiveView('healed')}
            className={`px-4 py-2 rounded-lg font-medium transition-all ${
              activeView === 'healed'
                ? 'bg-green-600 text-white'
                : 'bg-gray-700 text-gray-200 hover:bg-gray-600'
            }`}
          >
            🛡️ Secured
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex h-[calc(100vh-180px)]">
        {/* Architectures View */}
        <div className="flex-1 flex">
          {/* Original Architecture */}
          {(activeView === 'split' || activeView === 'original') && (
            <div className={`${activeView === 'split' ? 'w-1/2' : 'w-full'} border-r border-gray-700`}>
              <div className="bg-red-900/20 border-b border-red-700 px-4 py-3">
                <h3 className="font-semibold text-red-300">❌ Vulnerable Architecture</h3>
                <p className="text-xs text-red-400 mt-1">
                  {healingResult.vulnerability_analysis.total_vulnerabilities} vulnerabilities detected
                </p>
              </div>
              <div className="h-full bg-gray-900">
                <ReactFlow
                  nodes={originalNodes}
                  edges={originalEdges}
                  fitView
                  attributionPosition="bottom-left"
                >
                  <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="#374151" />
                  <Controls />
                  <MiniMap
                    nodeColor={() => '#ef4444'}
                    maskColor="rgba(31, 41, 55, 0.8)"
                  />
                </ReactFlow>
              </div>
            </div>
          )}

          {/* Healed Architecture */}
          {(activeView === 'split' || activeView === 'healed') && (
            <div className={activeView === 'split' ? 'w-1/2' : 'w-full'}>
              <div className="bg-green-900/20 border-b border-green-700 px-4 py-3">
                <h3 className="font-semibold text-green-300">✅ Secured Architecture</h3>
                <p className="text-xs text-green-400 mt-1">
                  +{healingResult.changes_summary.components_added} security components added
                </p>
              </div>
              <div className="h-full bg-gray-900">
                <ReactFlow
                  nodes={healedNodes}
                  edges={healedEdges}
                  fitView
                  attributionPosition="bottom-left"
                >
                  <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="#374151" />
                  <Controls />
                  <MiniMap
                    nodeColor={(node) => {
                      const nodeData = healingResult.healed_architecture.nodes.find((n: any) => n.id === node.id);
                      return nodeData && isSecurityComponent(nodeData.component_type) ? '#22c55e' : '#3b82f6';
                    }}
                    maskColor="rgba(31, 41, 55, 0.8)"
                  />
                </ReactFlow>
              </div>
            </div>
          )}
        </div>

        {/* Analysis Panel */}
        <div className="w-96 bg-gray-800 border-l border-gray-700 overflow-y-auto">
          <div className="p-6 space-y-6">
            {/* Risk Summary */}
            <div>
              <h4 className="font-semibold text-lg mb-3 text-white">📊 Risk Assessment</h4>
              <div className="space-y-3">
                <div className="bg-gray-900 p-3 rounded-lg border border-gray-700">
                  <div className="text-sm text-gray-400">Overall Risk Score</div>
                  <div className="flex items-baseline gap-2">
                    <span className="text-3xl font-bold text-red-600">
                      {healingResult.vulnerability_analysis.overall_risk_score}
                    </span>
                    <span className="text-sm text-green-600">
                      → {100 - parseInt(healingResult.recommendations.risk_reduction.replace('%', ''))}
                    </span>
                  </div>
                  <div className="text-xs text-gray-500 mt-1">
                    {healingResult.recommendations.risk_reduction} reduction after remediation
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div className={`p-2 rounded border ${getSeverityColor('CRITICAL')}`}>
                    <div className="text-xs">Critical</div>
                    <div className="text-xl font-bold">
                      {healingResult.vulnerability_analysis.severity_breakdown.critical}
                    </div>
                  </div>
                  <div className={`p-2 rounded border ${getSeverityColor('HIGH')}`}>
                    <div className="text-xs">High</div>
                    <div className="text-xl font-bold">
                      {healingResult.vulnerability_analysis.severity_breakdown.high}
                    </div>
                  </div>
                  <div className={`p-2 rounded border ${getSeverityColor('MEDIUM')}`}>
                    <div className="text-xs">Medium</div>
                    <div className="text-xl font-bold">
                      {healingResult.vulnerability_analysis.severity_breakdown.medium}
                    </div>
                  </div>
                  <div className={`p-2 rounded border ${getSeverityColor('LOW')}`}>
                    <div className="text-xs">Low</div>
                    <div className="text-xl font-bold">
                      {healingResult.vulnerability_analysis.severity_breakdown.low}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Key Vulnerabilities */}
            <div>
              <h4 className="font-semibold text-lg mb-3 text-white">🎯 Top Vulnerabilities</h4>
              <div className="space-y-2">
                {healingResult.vulnerability_analysis.vulnerable_attacks
                  .filter(attack => attack.vulnerable)
                  .slice(0, 5)
                  .map((attack, idx) => (
                    <div key={idx} className="bg-red-900/20 p-3 rounded border border-red-700 text-sm">
                      <div className="font-medium text-red-300">{attack.attack_name}</div>
                      <div className="text-xs text-red-400 mt-1">{attack.impact}</div>
                    </div>
                  ))}
              </div>
            </div>

            {/* Security Improvements */}
            <div>
              <h4 className="font-semibold text-lg mb-3 text-white">🛡️ Security Enhancements</h4>
              <div className="space-y-2">
                {healingResult.changes_summary.security_controls_added.slice(0, 5).map((control, idx) => (
                  <div key={idx} className="bg-green-900/20 p-2 rounded border border-green-700 flex items-center gap-2">
                    <span className="text-lg">{getComponentIcon(control)}</span>
                    <span className="text-sm text-green-300">{control.replace(/_/g, ' ').toUpperCase()}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Implementation Cost */}
            <div className="bg-blue-900/20 p-4 rounded-lg border border-blue-700">
              <h4 className="font-semibold text-blue-300 mb-2">💰 Implementation</h4>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-blue-400">Timeline:</span>
                  <span className="font-medium text-blue-200">
                    {healingResult.recommendations.implementation_timeline}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-blue-400">Est. Cost:</span>
                  <span className="font-medium text-blue-200">
                    {healingResult.recommendations.estimated_total_cost}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Footer Actions */}
      <div className="bg-gray-800 border-t border-gray-700 px-6 py-4 flex items-center justify-between">
        <button
          onClick={() => {
            alert('PDF download will be implemented next!');
          }}
          className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg font-medium transition-colors"
        >
          📄 Download Full Report (PDF)
        </button>

        <div className="flex gap-3">
          <button
            onClick={onReject}
            className="bg-gray-600 hover:bg-gray-700 text-white px-6 py-2 rounded-lg font-medium transition-colors"
          >
            ❌ Reject
          </button>
          <button
            onClick={onAccept}
            className="bg-green-600 hover:bg-green-700 text-white px-8 py-2 rounded-lg font-medium shadow-lg transition-colors"
          >
            ✅ Accept Secured Architecture
          </button>
        </div>
      </div>
    </div>
  );
};
