/**
 * Security Dashboard Component
 * Displays rule-based security analysis, scores, and metrics
 */

'use client';

import React, { useState, useEffect } from 'react';
import { Architecture } from '../types';

interface SecurityDashboardProps {
  architecture: Architecture;
  isOpen: boolean;
  onClose: () => void;
}

interface SecurityAnalysis {
  architecture_id: string;
  timestamp: string;
  risk_assessment: {
    total_score: number;
    risk_level: string;
    severity_breakdown: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
    owasp_violations: number;
    stride_threats: number;
    mitre_techniques: number;
  };
  owasp_findings: OWASPFinding[];
  stride_threats: STRIDEThreat[];
  mitre_attack_techniques: MITRETechnique[];
  recommendations: Recommendation[];
  compliance_status: any;
}

interface OWASPFinding {
  rule_id: string;
  title: string;
  description: string;
  severity: string;
  owasp_category: string;
  affected_components: string[];
  cvss_score: number;
  cwe_id?: string;
  mitigation: string;
  confidence: number;
}

interface STRIDEThreat {
  threat_id: string;
  category: string;
  title: string;
  description: string;
  affected_asset: string;
  likelihood: string;
  impact: string;
  attack_vector: string;
  mitigations: string[];
}

interface MITRETechnique {
  technique_id: string;
  name: string;
  tactic: string;
  description: string;
  possible: boolean;
  affected_components: string[];
  attack_path: string | string[];  // Can be string or array
  detection_methods: string[];
  mitigations: string[];
}

interface Recommendation {
  title: string;
  description: string;
  priority: string;
  cvss_score?: number;
  estimated_effort?: string;
}

export const SecurityDashboard: React.FC<SecurityDashboardProps> = ({
  architecture,
  isOpen,
  onClose,
}) => {
  const [analysis, setAnalysis] = useState<SecurityAnalysis | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'owasp' | 'stride' | 'mitre' | 'recommendations'>('overview');

  useEffect(() => {
    if (isOpen && architecture) {
      analyzeArchitecture();
    }
  }, [isOpen, architecture]);

  const analyzeArchitecture = async () => {
    setLoading(true);
    try {
      const apiUrl = process.env.NEXT_PUBLIC_AGENT_API_URL || 'http://localhost:5000/api';
      const response = await fetch(`${apiUrl}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ architecture }),
      });

      if (!response.ok) throw new Error('Analysis failed');

      const data = await response.json();
      setAnalysis(data);
    } catch (error) {
      console.error('Error analyzing architecture:', error);
      alert('Failed to analyze architecture. Make sure the backend server is running.');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  const getRiskColor = (level: string) => {
    switch (level.toUpperCase()) {
      case 'CRITICAL': return 'text-red-500 bg-red-500/10 border-red-500';
      case 'HIGH': return 'text-orange-500 bg-orange-500/10 border-orange-500';
      case 'MEDIUM': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500';
      case 'LOW': return 'text-green-500 bg-green-500/10 border-green-500';
      default: return 'text-gray-500 bg-gray-500/10 border-gray-500';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL': return 'bg-red-600';
      case 'HIGH': return 'bg-orange-500';
      case 'MEDIUM': return 'bg-yellow-500';
      case 'LOW': return 'bg-green-500';
      default: return 'bg-gray-500';
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl w-full max-w-[95vw] max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-700 bg-gradient-to-r from-blue-900/20 to-gray-900">
          <div>
            <h2 className="text-2xl font-bold text-white flex items-center gap-3">
              <span className="text-3xl">🔒</span>
              Security Analysis Dashboard
            </h2>
            <p className="text-gray-400 text-sm mt-1">
              Rule-based security analysis using OWASP, STRIDE, and MITRE ATT&CK frameworks
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors text-2xl w-10 h-10 flex items-center justify-center rounded-lg hover:bg-gray-800"
          >
            ✕
          </button>
        </div>

        {loading ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <div className="animate-spin text-6xl mb-4">⚙️</div>
              <div className="text-xl text-white">Analyzing security...</div>
              <div className="text-sm text-gray-400 mt-2">Running OWASP, STRIDE, and MITRE checks</div>
            </div>
          </div>
        ) : analysis ? (
          <>
            {/* Tabs */}
            <div className="flex border-b border-gray-700 bg-gray-800/50">
              {[
                { id: 'overview', label: '📊 Overview', count: null },
                { id: 'owasp', label: '🛡️ OWASP', count: analysis.owasp_findings.length },
                { id: 'stride', label: '⚠️ STRIDE', count: analysis.stride_threats.length },
                { id: 'mitre', label: '🎯 MITRE', count: analysis.mitre_attack_techniques.length },
                { id: 'recommendations', label: '💡 Recommendations', count: analysis.recommendations.length },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`px-6 py-3 font-semibold transition-colors ${
                    activeTab === tab.id
                      ? 'text-blue-400 border-b-2 border-blue-400 bg-gray-800'
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  {tab.label}
                  {tab.count !== null && (
                    <span className="ml-2 px-2 py-0.5 bg-gray-700 rounded-full text-xs">
                      {tab.count}
                    </span>
                  )}
                </button>
              ))}
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto p-6">
              {/* Overview Tab */}
              {activeTab === 'overview' && (
                <div className="space-y-6">
                  {/* Risk Score Card */}
                  <div className="bg-gradient-to-br from-gray-800 to-gray-900 rounded-xl p-6 border border-gray-700">
                    <h3 className="text-xl font-bold text-white mb-6">Overall Risk Assessment</h3>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                      {/* Total Score */}
                      <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                        <div className="text-gray-400 text-sm mb-2">Risk Score</div>
                        <div className="flex items-end gap-2">
                          <div className="text-4xl font-bold text-white">
                            {analysis.risk_assessment.total_score}
                          </div>
                          <div className="text-gray-400 mb-1">/100</div>
                        </div>
                        <div className={`mt-2 px-3 py-1 rounded-full text-xs font-bold inline-block ${getRiskColor(analysis.risk_assessment.risk_level)}`}>
                          {analysis.risk_assessment.risk_level}
                        </div>
                      </div>

                      {/* OWASP Violations */}
                      <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                        <div className="text-gray-400 text-sm mb-2">OWASP Violations</div>
                        <div className="text-4xl font-bold text-red-400">
                          {analysis.risk_assessment.owasp_violations}
                        </div>
                        <div className="text-xs text-gray-500 mt-2">Vulnerability findings</div>
                      </div>

                      {/* STRIDE Threats */}
                      <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                        <div className="text-gray-400 text-sm mb-2">STRIDE Threats</div>
                        <div className="text-4xl font-bold text-orange-400">
                          {analysis.risk_assessment.stride_threats}
                        </div>
                        <div className="text-xs text-gray-500 mt-2">Threat model issues</div>
                      </div>

                      {/* MITRE Techniques */}
                      <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700">
                        <div className="text-gray-400 text-sm mb-2">MITRE Techniques</div>
                        <div className="text-4xl font-bold text-yellow-400">
                          {analysis.risk_assessment.mitre_techniques}
                        </div>
                        <div className="text-xs text-gray-500 mt-2">Possible attack vectors</div>
                      </div>
                    </div>

                    {/* Severity Breakdown */}
                    <div className="mt-6">
                      <div className="text-sm text-gray-400 mb-3">Severity Breakdown</div>
                      <div className="flex gap-2">
                        {Object.entries(analysis.risk_assessment.severity_breakdown).map(([severity, count]) => (
                          <div key={severity} className="flex-1">
                            <div className="flex justify-between text-xs text-gray-400 mb-1">
                              <span className="capitalize">{severity}</span>
                              <span>{count}</span>
                            </div>
                            <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                              <div
                                className={`h-full ${getSeverityColor(severity)}`}
                                style={{
                                  width: `${(count / Math.max(...Object.values(analysis.risk_assessment.severity_breakdown), 1)) * 100}%`
                                }}
                              />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Quick Stats */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                      <div className="flex items-center gap-3">
                        <div className="text-3xl">🎯</div>
                        <div>
                          <div className="text-2xl font-bold text-white">
                            {analysis.owasp_findings.length}
                          </div>
                          <div className="text-sm text-gray-400">Total OWASP Findings</div>
                        </div>
                      </div>
                    </div>

                    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                      <div className="flex items-center gap-3">
                        <div className="text-3xl">⚠️</div>
                        <div>
                          <div className="text-2xl font-bold text-white">
                            {analysis.stride_threats.length}
                          </div>
                          <div className="text-sm text-gray-400">STRIDE Threats Identified</div>
                        </div>
                      </div>
                    </div>

                    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                      <div className="flex items-center gap-3">
                        <div className="text-3xl">💡</div>
                        <div>
                          <div className="text-2xl font-bold text-white">
                            {analysis.recommendations.length}
                          </div>
                          <div className="text-sm text-gray-400">Security Recommendations</div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* OWASP Tab */}
              {activeTab === 'owasp' && (
                <div className="space-y-4">
                  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <h3 className="text-lg font-bold text-white mb-2">OWASP Top 10 2021 Analysis</h3>
                    <p className="text-sm text-gray-400">
                      {analysis.owasp_findings.length} vulnerabilities detected using rule-based OWASP scanning
                    </p>
                  </div>

                  {analysis.owasp_findings.map((finding, index) => (
                    <div key={index} className="bg-gray-800 rounded-lg p-5 border border-gray-700 hover:border-gray-600 transition-colors">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <span className={`px-3 py-1 rounded-full text-xs font-bold ${getRiskColor(finding.severity)}`}>
                              {finding.severity}
                            </span>
                            <span className="text-xs text-gray-400">{finding.owasp_category}</span>
                            <span className="text-xs text-blue-400">CVSS: {finding.cvss_score}</span>
                            <span className="text-xs text-gray-500">Confidence: {(finding.confidence * 100).toFixed(0)}%</span>
                          </div>
                          <h4 className="text-white font-bold text-lg">{finding.title}</h4>
                        </div>
                        <div className="text-2xl">🛡️</div>
                      </div>

                      <p className="text-gray-300 text-sm mb-3">{finding.description}</p>

                      {finding.affected_components.length > 0 && (
                        <div className="mb-3">
                          <div className="text-xs text-gray-400 mb-1">Affected Components:</div>
                          <div className="flex flex-wrap gap-2">
                            {finding.affected_components.map((comp, i) => (
                              <span key={i} className="px-2 py-1 bg-gray-700 rounded text-xs text-gray-300">
                                {comp}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      <div className="bg-gray-900 rounded p-3 border border-gray-700">
                        <div className="text-xs text-green-400 mb-1">✓ Mitigation:</div>
                        <div className="text-sm text-gray-300">{finding.mitigation}</div>
                      </div>

                      {finding.cwe_id && (
                        <div className="mt-2 text-xs text-gray-500">CWE: {finding.cwe_id}</div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* STRIDE Tab */}
              {activeTab === 'stride' && (
                <div className="space-y-4">
                  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <h3 className="text-lg font-bold text-white mb-2">STRIDE Threat Modeling</h3>
                    <p className="text-sm text-gray-400">
                      {analysis.stride_threats.length} threats identified across 6 STRIDE categories
                    </p>
                  </div>

                  {analysis.stride_threats.map((threat, index) => (
                    <div key={index} className="bg-gray-800 rounded-lg p-5 border border-gray-700 hover:border-gray-600 transition-colors">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <span className="px-3 py-1 bg-purple-500/20 text-purple-400 rounded-full text-xs font-bold border border-purple-500">
                              {threat.category}
                            </span>
                            <span className="text-xs text-yellow-400">Likelihood: {threat.likelihood}</span>
                            <span className="text-xs text-red-400">Impact: {threat.impact}</span>
                          </div>
                          <h4 className="text-white font-bold text-lg">{threat.title}</h4>
                        </div>
                        <div className="text-2xl">⚠️</div>
                      </div>

                      <p className="text-gray-300 text-sm mb-3">{threat.description}</p>

                      <div className="mb-3">
                        <div className="text-xs text-gray-400 mb-1">Affected Asset:</div>
                        <span className="px-2 py-1 bg-gray-700 rounded text-sm text-gray-300">
                          {threat.affected_asset}
                        </span>
                      </div>

                      <div className="mb-3">
                        <div className="text-xs text-gray-400 mb-1">Attack Vector:</div>
                        <div className="text-sm text-gray-300">{threat.attack_vector}</div>
                      </div>

                      <div className="bg-gray-900 rounded p-3 border border-gray-700">
                        <div className="text-xs text-green-400 mb-2">✓ Mitigations:</div>
                        <ul className="space-y-1">
                          {threat.mitigations.map((mitigation, i) => (
                            <li key={i} className="text-sm text-gray-300 flex items-start gap-2">
                              <span className="text-green-400">•</span>
                              <span>{mitigation}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* MITRE Tab */}
              {activeTab === 'mitre' && (
                <div className="space-y-4">
                  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <h3 className="text-lg font-bold text-white mb-2">MITRE ATT&CK Framework</h3>
                    <p className="text-sm text-gray-400">
                      {analysis.mitre_attack_techniques.length} possible attack techniques mapped to your architecture
                    </p>
                  </div>

                  {analysis.mitre_attack_techniques.map((technique, index) => (
                    <div key={index} className="bg-gray-800 rounded-lg p-5 border border-gray-700 hover:border-gray-600 transition-colors">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <span className="px-3 py-1 bg-red-500/20 text-red-400 rounded-full text-xs font-bold border border-red-500">
                              {technique.technique_id}
                            </span>
                            <span className="px-3 py-1 bg-blue-500/20 text-blue-400 rounded-full text-xs font-bold border border-blue-500">
                              {technique.tactic}
                            </span>
                          </div>
                          <h4 className="text-white font-bold text-lg">{technique.name}</h4>
                        </div>
                        <div className="text-2xl">🎯</div>
                      </div>

                      <p className="text-gray-300 text-sm mb-3">{technique.description}</p>

                      {technique.affected_components.length > 0 && (
                        <div className="mb-3">
                          <div className="text-xs text-gray-400 mb-1">Affected Components:</div>
                          <div className="flex flex-wrap gap-2">
                            {technique.affected_components.map((comp, i) => (
                              <span key={i} className="px-2 py-1 bg-gray-700 rounded text-xs text-gray-300">
                                {comp}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {technique.attack_path && (() => {
                        const attackPathArray = typeof technique.attack_path === 'string' 
                          ? technique.attack_path.split('→').map((s: string) => s.trim())
                          : technique.attack_path;
                        
                        return attackPathArray.length > 0 && (
                          <div className="mb-3">
                            <div className="text-xs text-red-400 mb-2">🔗 Attack Path:</div>
                            <div className="space-y-1">
                              {attackPathArray.map((step: string, i: number) => (
                                <div key={i} className="text-sm text-gray-300 flex items-start gap-2">
                                  <span className="text-red-400">{i + 1}.</span>
                                  <span>{step}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        );
                      })()}

                      <div className="grid md:grid-cols-2 gap-3">
                        <div className="bg-gray-900 rounded p-3 border border-gray-700">
                          <div className="text-xs text-blue-400 mb-2">🔍 Detection Methods:</div>
                          <ul className="space-y-1">
                            {technique.detection_methods.map((method, i) => (
                              <li key={i} className="text-xs text-gray-300">• {method}</li>
                            ))}
                          </ul>
                        </div>

                        <div className="bg-gray-900 rounded p-3 border border-gray-700">
                          <div className="text-xs text-green-400 mb-2">✓ Mitigations:</div>
                          <ul className="space-y-1">
                            {technique.mitigations.map((mitigation, i) => (
                              <li key={i} className="text-xs text-gray-300">• {mitigation}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Recommendations Tab */}
              {activeTab === 'recommendations' && (
                <div className="space-y-4">
                  <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                    <h3 className="text-lg font-bold text-white mb-2">Security Recommendations</h3>
                    <p className="text-sm text-gray-400">
                      {analysis.recommendations.length} prioritized actions to improve your security posture
                    </p>
                  </div>

                  {analysis.recommendations.map((rec, index) => (
                    <div key={index} className="bg-gray-800 rounded-lg p-5 border border-gray-700 hover:border-gray-600 transition-colors">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-2">
                            <span className={`px-3 py-1 rounded-full text-xs font-bold ${getRiskColor(rec.priority)}`}>
                              {rec.priority}
                            </span>
                            {rec.cvss_score && (
                              <span className="text-xs text-blue-400">CVSS: {rec.cvss_score}</span>
                            )}
                            {rec.estimated_effort && (
                              <span className="text-xs text-gray-400">Effort: {rec.estimated_effort}</span>
                            )}
                          </div>
                          <h4 className="text-white font-bold text-lg">{rec.title}</h4>
                        </div>
                        <div className="text-2xl">💡</div>
                      </div>

                      <p className="text-gray-300 text-sm">{rec.description}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center text-gray-400">
            <div className="text-center">
              <div className="text-6xl mb-4">🔒</div>
              <div className="text-xl">No analysis available</div>
              <button
                onClick={analyzeArchitecture}
                className="mt-4 px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg"
              >
                Run Analysis
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
