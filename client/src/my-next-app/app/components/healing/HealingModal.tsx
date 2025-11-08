"use client";

import React, { useState } from 'react';
import { CustomNode, CustomEdge } from '../../types';

interface HealingModalProps {
  isOpen: boolean;
  onClose: () => void;
  architecture: {
    nodes: CustomNode[];
    edges: CustomEdge[];
  };
  onHealingComplete: (result: HealingResult) => void;
}


export interface HealingResult {
  healing_summary: {
    original_architecture_id: string;
    analysis_timestamp: string;
    total_vulnerabilities_found: number;
    overall_risk_score: number;
    security_posture: string;
    mitigations_applied: number;
  };
  vulnerability_analysis: {
    overall_risk_score: number;
    security_posture: string;
    total_vulnerabilities: number;
    severity_breakdown: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
    vulnerable_attacks: Array<{
      attack_id: string;
      attack_name: string;
      vulnerable: boolean;
      severity: string;
      affected_components: string[];
      vulnerabilities: string[];
      exploit_path: string;
      impact: string;
    }>;
    architecture_weaknesses: string[];
    compliance_violations: string[];
  };
  healed_architecture: {
    id: string;
    metadata: any;
    nodes: any[];
    connections: any[];
  };
  recommendations: {
    immediate_actions: Array<{
      action: string;
      priority: string;
      effort: string;
      cost: string;
      impact: string;
    }>;
    short_term_improvements: any[];
    long_term_initiatives: any[];
    monitoring_guidelines: any[];
    compliance_requirements: any[];
    estimated_total_cost: string;
    implementation_timeline: string;
    risk_reduction: string;
  };
  changes_summary: {
    components_added: number;
    connections_modified: number;
    security_controls_added: string[];
  };
}

type HealingStage = 'idle' | 'analyzing' | 'generating' | 'complete' | 'error';



export const HealingModal: React.FC<HealingModalProps> = ({
  isOpen,
  onClose,
  architecture,
  onHealingComplete
}) => {
  const [stage, setStage] = useState<HealingStage>('idle');
  const [progress, setProgress] = useState(0);
  const [statusMessage, setStatusMessage] = useState('');
  const [healingResult, setHealingResult] = useState<HealingResult | null>(null);
  const [error, setError] = useState<string>('');

  if (!isOpen) return null;

  const startHealing = async () => {
    try {
      setStage('analyzing');
      setProgress(10);
      setStatusMessage('🔍 Scanning architecture for vulnerabilities...');
      setError('');

      // Prepare architecture data
      const architectureData = {
        metadata: {
          company_name: "Current Architecture",
          version: "1.0",
          created_at: new Date().toISOString()
        },
        nodes: architecture.nodes.map(node => ({
          id: node.id,
          component_type: node.data.component_type,
          name: node.data.name || node.data.component_type,
          position: node.position,
          properties: node.data.properties || {}
        })),
        connections: architecture.edges.map(edge => ({
          id: edge.id,
          source: edge.source,
          target: edge.target,
          type: edge.type || 'default',
          properties: edge.data?.properties || {}
        }))
      };

      setProgress(30);
      setStatusMessage('🧪 Running all attack simulations...');

      // Call backend healing endpoint
      const response = await fetch('http://localhost:5000/api/heal', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          architecture: architectureData
        })
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error('Backend error:', errorText);
        throw new Error(`Healing failed: ${response.statusText} - ${errorText}`);
      }

      setProgress(60);
      setStatusMessage('🛡️ Generating secure architecture...');

      const result: HealingResult = await response.json();
      console.log('Healing result received:', result);

      setProgress(90);
      setStatusMessage('📊 Preparing vulnerability report...');

      await new Promise(resolve => setTimeout(resolve, 100));

      setProgress(100);
      setStatusMessage('✅ Healing complete!');
      setStage('complete');
      setHealingResult(result);
      onHealingComplete(result);

    } catch (err: any) {
      console.error('Healing error:', err);
      setStage('error');
      setError(err.message || 'Failed to heal architecture');
      setStatusMessage('❌ Healing failed');
    }
  };



  //get the pdf data from the healing function itself...do not call the whole process again

  const downloadPdfReport = async () => {
    try {
      setStatusMessage('📄 Generating PDF report...');
      
      const response = await fetch('http://localhost:5000/api/healing-report/pdf', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          architecture: {
            nodes: architecture.nodes.map(node => ({
              id: node.id,
              component_type: node.data.type,
              name: node.data.name,
              properties: node.data.properties || {}
            })),
            connections: architecture.edges.map(edge => ({
              source: edge.source,
              target: edge.target,
              connection_type: edge.data?.type || 'network',
              properties: edge.data?.properties || {}
            })),
            metadata: {
              id: 'architecture_1',
              company_name: 'Current Architecture'
            }
          }
        })
      });

      if (!response.ok) {
        throw new Error('Failed to generate PDF');
      }

      // Get the PDF blob
      const blob = await response.blob();
      
      // Create download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `insightx_healing_report_${new Date().toISOString().split('T')[0]}.pdf`;
      document.body.appendChild(a);
      a.click();
      
      // Cleanup
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      setStatusMessage('✅ PDF downloaded successfully!');
      
    } catch (err: any) {
      console.error('PDF download error:', err);
      alert('Failed to download PDF report: ' + err.message);
    }
  };

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      CRITICAL: 'text-red-600 bg-red-100',
      HIGH: 'text-orange-600 bg-orange-100',
      MEDIUM: 'text-yellow-600 bg-yellow-100',
      LOW: 'text-blue-600 bg-blue-100'
    };
    return colors[severity] || 'text-gray-600 bg-gray-100';
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 80) return 'text-red-600';
    if (score >= 60) return 'text-orange-600';
    if (score >= 40) return 'text-yellow-600';
    return 'text-green-600';
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-white rounded-lg shadow-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="bg-gradient-to-r from-green-600 to-emerald-600 text-white px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-3xl">🩹</span>
            <div>
              <h2 className="text-2xl font-bold">Architecture Healing</h2>
              <p className="text-green-100 text-sm">Comprehensive Security Analysis & Remediation</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-white hover:text-green-100 text-2xl font-bold"
          >
            ×
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-180px)]">
          {stage === 'idle' && (
            <div className="text-center py-8">
              <div className="text-6xl mb-4">🩹</div>
              <h3 className="text-xl font-semibold mb-3">Ready to Heal Your Architecture</h3>
              <p className="text-gray-600 mb-6 max-w-2xl mx-auto">
                The healing agent will:
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8 text-left max-w-3xl mx-auto">
                <div className="bg-blue-50 p-4 rounded-lg border border-blue-200">
                  <div className="text-2xl mb-2">🔍</div>
                  <h4 className="font-semibold text-blue-900">Scan for Vulnerabilities</h4>
                  <p className="text-sm text-blue-700">Run all 20 attack simulations to identify weaknesses</p>
                </div>
                <div className="bg-purple-50 p-4 rounded-lg border border-purple-200">
                  <div className="text-2xl mb-2">🎯</div>
                  <h4 className="font-semibold text-purple-900">Detailed Analysis</h4>
                  <p className="text-sm text-purple-700">Analyze severity, impact, and exploit paths</p>
                </div>
                <div className="bg-green-50 p-4 rounded-lg border border-green-200">
                  <div className="text-2xl mb-2">🛡️</div>
                  <h4 className="font-semibold text-green-900">Generate Secure Design</h4>
                  <p className="text-sm text-green-700">Create hardened architecture with security controls</p>
                </div>
                <div className="bg-orange-50 p-4 rounded-lg border border-orange-200">
                  <div className="text-2xl mb-2">📋</div>
                  <h4 className="font-semibold text-orange-900">Actionable Report</h4>
                  <p className="text-sm text-orange-700">Get prioritized recommendations with cost estimates</p>
                </div>
              </div>
              <button
                onClick={startHealing}
                className="bg-green-600 hover:bg-green-700 text-white px-8 py-3 rounded-lg font-semibold text-lg shadow-lg transition-all"
              >
                🩹 Start Healing Process
              </button>
            </div>
          )}

          {(stage === 'analyzing' || stage === 'generating') && (
            <div className="py-8">
              <div className="text-center mb-6">
                <div className="text-5xl mb-4 animate-pulse">
                  {stage === 'analyzing' ? '🔍' : '🛡️'}
                </div>
                <h3 className="text-xl font-semibold mb-2">{statusMessage}</h3>
                <p className="text-gray-600">This may take 30-60 seconds...</p>
              </div>

              <div className="max-w-2xl mx-auto">
                <div className="bg-gray-200 rounded-full h-4 mb-2 overflow-hidden">
                  <div
                    className="bg-gradient-to-r from-green-600 to-emerald-600 h-full transition-all duration-500"
                    style={{ width: `${progress}%` }}
                  />
                </div>
                <div className="text-center text-sm text-gray-600">{progress}%</div>

                <div className="mt-6 space-y-2">
                  <div className={`flex items-center gap-2 ${progress >= 10 ? 'text-green-600' : 'text-gray-400'}`}>
                    <span>{progress >= 10 ? '✅' : '⏳'}</span>
                    <span>Architecture scan initiated</span>
                  </div>
                  <div className={`flex items-center gap-2 ${progress >= 30 ? 'text-green-600' : 'text-gray-400'}`}>
                    <span>{progress >= 30 ? '✅' : '⏳'}</span>
                    <span>Running attack simulations (20 attacks)</span>
                  </div>
                  <div className={`flex items-center gap-2 ${progress >= 60 ? 'text-green-600' : 'text-gray-400'}`}>
                    <span>{progress >= 60 ? '✅' : '⏳'}</span>
                    <span>Generating secure architecture design</span>
                  </div>
                  <div className={`flex items-center gap-2 ${progress >= 90 ? 'text-green-600' : 'text-gray-400'}`}>
                    <span>{progress >= 90 ? '✅' : '⏳'}</span>
                    <span>Compiling vulnerability report</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {stage === 'complete' && healingResult && (
            <div className="space-y-6">
              {/* Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-gradient-to-br from-red-50 to-red-100 p-4 rounded-lg border border-red-200">
                  <div className="text-sm text-red-600 font-medium mb-1">Risk Score</div>
                  <div className={`text-3xl font-bold ${getRiskScoreColor(healingResult.vulnerability_analysis.overall_risk_score)}`}>
                    {healingResult.vulnerability_analysis.overall_risk_score}/100
                  </div>
                  <div className="text-xs text-red-700 mt-1">
                    {healingResult.vulnerability_analysis.security_posture}
                  </div>
                </div>

                <div className="bg-gradient-to-br from-orange-50 to-orange-100 p-4 rounded-lg border border-orange-200">
                  <div className="text-sm text-orange-600 font-medium mb-1">Vulnerabilities Found</div>
                  <div className="text-3xl font-bold text-orange-600">
                    {healingResult.vulnerability_analysis.total_vulnerabilities}
                  </div>
                  <div className="text-xs text-orange-700 mt-1 space-x-2">
                    <span>🔴 {healingResult.vulnerability_analysis.severity_breakdown.critical}</span>
                    <span>🟠 {healingResult.vulnerability_analysis.severity_breakdown.high}</span>
                    <span>🟡 {healingResult.vulnerability_analysis.severity_breakdown.medium}</span>
                  </div>
                </div>

                <div className="bg-gradient-to-br from-green-50 to-green-100 p-4 rounded-lg border border-green-200">
                  <div className="text-sm text-green-600 font-medium mb-1">Risk Reduction</div>
                  <div className="text-3xl font-bold text-green-600">
                    {healingResult.recommendations.risk_reduction}
                  </div>
                  <div className="text-xs text-green-700 mt-1">
                    After remediation
                  </div>
                </div>
              </div>

              {/* Vulnerable Attacks */}
              <div>
                <h4 className="font-semibold text-lg mb-3">🎯 Vulnerable Attack Vectors</h4>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {healingResult.vulnerability_analysis.vulnerable_attacks
                    .filter(attack => attack.vulnerable)
                    .slice(0, 10)
                    .map((attack, idx) => (
                      <div key={idx} className="bg-gray-50 p-3 rounded border border-gray-200">
                        <div className="flex items-center justify-between mb-2">
                          <div className="font-medium">{attack.attack_name}</div>
                          <span className={`text-xs px-2 py-1 rounded ${getSeverityColor(attack.severity)}`}>
                            {attack.severity}
                          </span>
                        </div>
                        <div className="text-sm text-gray-700 mb-1">
                          <strong>Impact:</strong> {attack.impact}
                        </div>
                        <div className="text-xs text-gray-600">
                          <strong>Affected:</strong> {attack.affected_components.join(', ')}
                        </div>
                      </div>
                    ))}
                </div>
              </div>

              {/* Immediate Actions */}
              <div>
                <h4 className="font-semibold text-lg mb-3">⚡ Immediate Actions Required</h4>
                <div className="space-y-2">
                  {healingResult.recommendations.immediate_actions.slice(0, 5).map((action, idx) => (
                    <div key={idx} className="bg-red-50 p-3 rounded border border-red-200">
                      <div className="flex items-start gap-3">
                        <span className="text-xl">🔥</span>
                        <div className="flex-1">
                          <div className="font-medium text-red-900">{action.action}</div>
                          <div className="text-sm text-red-700 mt-1">{action.impact}</div>
                          <div className="flex gap-4 mt-2 text-xs text-red-600">
                            <span>⏱️ {action.effort}</span>
                            <span>💰 {action.cost}</span>
                            <span>🎯 {action.priority}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Changes Summary */}
              <div className="bg-blue-50 p-4 rounded-lg border border-blue-200">
                <h4 className="font-semibold text-blue-900 mb-2">📊 Remediation Summary</h4>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <div className="text-blue-700">Components Added</div>
                    <div className="text-xl font-bold text-blue-900">
                      +{healingResult.changes_summary.components_added}
                    </div>
                  </div>
                  <div>
                    <div className="text-blue-700">Security Controls</div>
                    <div className="text-sm text-blue-800 mt-1">
                      {healingResult.changes_summary.security_controls_added.slice(0, 3).join(', ')}
                    </div>
                  </div>
                </div>
                <div className="mt-3 pt-3 border-t border-blue-200 text-sm text-blue-700">
                  <div>⏱️ Timeline: {healingResult.recommendations.implementation_timeline}</div>
                  <div>💰 Estimated Cost: {healingResult.recommendations.estimated_total_cost}</div>
                </div>
              </div>
            </div>
          )}

          {stage === 'error' && (
            <div className="text-center py-8">
              <div className="text-5xl mb-4">❌</div>
              <h3 className="text-xl font-semibold text-red-600 mb-2">Healing Failed</h3>
              <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-4 max-w-2xl mx-auto">
                <p className="text-sm text-red-800 font-mono text-left break-words">{error}</p>
              </div>
              <div className="text-sm text-gray-600 mb-4 max-w-xl mx-auto">
                <p className="mb-2">Common issues:</p>
                <ul className="text-left space-y-1">
                  <li>• Backend server not running (run: <code className="bg-gray-100 px-1">python security_agent.py</code>)</li>
                  <li>• Backend not accessible at <code className="bg-gray-100 px-1">http://localhost:5000</code></li>
                  <li>• Check browser console (F12) for detailed error</li>
                  <li>• Check backend terminal for Python errors</li>
                </ul>
              </div>
              <button
                onClick={() => setStage('idle')}
                className="bg-gray-600 hover:bg-gray-700 text-white px-6 py-2 rounded-lg"
              >
                Try Again
              </button>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="bg-gray-50 px-6 py-4 border-t border-gray-200 flex justify-end gap-3">
          {stage === 'complete' && (
            <>
              <button
                onClick={downloadPdfReport}
                className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg font-medium"
              >
                📄 Download Report
              </button>
              <button
                onClick={onClose}
                className="bg-green-600 hover:bg-green-700 text-white px-6 py-2 rounded-lg font-medium"
              >
                View Comparison →
              </button>
            </>
          )}
          {stage !== 'complete' && stage !== 'analyzing' && stage !== 'generating' && (
            <button
              onClick={onClose}
              className="bg-gray-600 hover:bg-gray-700 text-white px-6 py-2 rounded-lg"
            >
              Close
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

