/**
 * Case Study Analysis Modal Component
 * Analyzes current architecture against historical cybersecurity incidents from VCDB
 */

'use client';
import React, { useState, useEffect } from 'react';
import { Node, Edge } from 'reactflow';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '../ui/dialog';
import { Button } from '../ui/button';
import { CustomNodeData, CustomEdgeData } from '../../types';
import './case-study-modal.css';

interface CaseStudyAnalysisModalProps {
  isOpen: boolean;
  onClose: () => void;
  nodes: Node<CustomNodeData>[];
  edges: Edge<CustomEdgeData>[];
  architectureName: string;
}

interface CaseStudyResult {
  similar_cases: Array<{
    incident_id: string;
    industry: string;
    country: string;
    actor: string;
    action: string;
    asset: string;
    impact_overall_rating: string;
    summary: string;
    distance: number;
    year: string;
  }>;
  analysis: {
    risk_patterns: string[];
    recommendations: string[];
    confidence_score: number;
  };
  meta: {
    total_cases_analyzed: number;
    search_strategy: string;
    vcdb_available: boolean;
  };
}

const CaseStudyAnalysisModal: React.FC<CaseStudyAnalysisModalProps> = ({
  isOpen,
  onClose,
  nodes,
  edges,
  architectureName
}) => {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<CaseStudyResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<string | null>(null);

  const handleAnalyze = async () => {
    if (!nodes.length) {
      setError('No architecture components to analyze');
      return;
    }

    setIsAnalyzing(true);
    setError(null);

    try {
      const architecture = {
        metadata: {
          company_name: architectureName,
          architecture_type: "custom",
          security_level: "medium",
          description: `Architecture analysis for ${architectureName}`
        },
        nodes: nodes.map(node => ({
          id: node.id,
          type: node.type,
          category: node.data?.category || 'compute',
          name: node.data?.name || node.id,
          properties: node.data || {}
        })),
        connections: edges.map(edge => ({
          id: edge.id,
          source: edge.source,
          target: edge.target,
          type: edge.data?.type || 'connection',
          properties: edge.data || {}
        }))
      };

      const response = await fetch('http://localhost:8082/api/analyze-case-studies', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          architecture,
          attack: null // Can be extended to include specific attack context
        })
      });

      if (!response.ok) {
        throw new Error(`Analysis failed: ${response.statusText}`);
      }

      const result = await response.json();
      // Handle both old and new response formats
      const caseStudyData = result.case_study_results || result;
      
      // If the data has the old format, convert it to new format
      if (caseStudyData.suggestions && caseStudyData.analysis_summary) {
        setAnalysisResult({
          similar_cases: caseStudyData.similar_cases || [],
          analysis: {
            risk_patterns: [
              `Found ${caseStudyData.analysis_summary?.total_cases_found || 0} similar historical incidents`,
              "Analysis based on historical incident patterns",
              ...(caseStudyData.analysis_summary?.common_vulnerabilities || []).slice(0, 2)
            ],
            recommendations: caseStudyData.suggestions || [],
            confidence_score: 0.8
          },
          meta: {
            total_cases_analyzed: caseStudyData.analysis_summary?.total_cases_found || 0,
            search_strategy: "Historical incident analysis",
            vcdb_available: false
          }
        });
      } else {
        // New format
        setAnalysisResult(caseStudyData);
      }
    } catch (err) {
      console.error('Case study analysis error:', err);
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getRiskLevelColor = (rating: string) => {
    switch (rating.toLowerCase()) {
      case 'severe':
      case 'critical':
        return 'text-red-500 bg-red-500/10';
      case 'major':
      case 'high':
        return 'text-orange-500 bg-orange-500/10';
      case 'moderate':
      case 'medium':
        return 'text-yellow-500 bg-yellow-500/10';
      case 'minor':
      case 'low':
        return 'text-green-500 bg-green-500/10';
      default:
        return 'text-gray-500 bg-gray-500/10';
    }
  };

  const getConfidenceColor = (score: number) => {
    if (score >= 0.8) return 'text-green-500';
    if (score >= 0.6) return 'text-yellow-500';
    return 'text-red-500';
  };

  // Auto-analyze when modal opens
  useEffect(() => {
    if (isOpen && nodes.length > 0 && !analysisResult) {
      handleAnalyze();
    }
  }, [isOpen, nodes.length]);

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent 
        className="case-study-modal-content fixed left-[50%] top-[50%] z-50 grid translate-x-[-50%] translate-y-[-50%] gap-4 border shadow-lg duration-200 data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[state=closed]:slide-out-to-left-1/2 data-[state=closed]:slide-out-to-top-[48%] data-[state=open]:slide-in-from-left-1/2 data-[state=open]:slide-in-from-top-[48%] rounded-3xl bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 border-2 border-blue-500/30 text-white overflow-hidden shadow-2xl backdrop-blur-sm dialog-glow"
        style={{ 
          width: '98vw', 
          height: '98vh', 
          maxWidth: 'none', 
          maxHeight: 'none',
          margin: 0,
          padding: 0
        }}
      >
        <div className="flex flex-col h-full w-full p-6">
        <DialogHeader className="pb-8 border-b border-gray-700/50">
          <DialogTitle className="flex items-center justify-center gap-4 text-3xl font-bold bg-gradient-to-r from-blue-400 via-purple-400 to-cyan-400 bg-clip-text text-transparent">
            <span className="text-4xl">💾</span>
            Case Study Analysis - Historical Incident Comparison
            <span className="text-4xl">🔍</span>
          </DialogTitle>
          <Button
            variant="ghost"
            size="lg"
            className="absolute right-8 top-8 text-gray-400 hover:text-white text-2xl hover:bg-red-500/20 rounded-full w-12 h-12 transition-all"
            onClick={onClose}
          >
            ✕
          </Button>
        </DialogHeader>

        <div className="flex flex-col gap-8 overflow-hidden h-full flex-1">
          {/* Analysis Overview */}
          <div className="bg-gradient-to-r from-gray-800/70 via-gray-700/70 to-gray-800/70 rounded-2xl p-8 border border-gray-600/50 shadow-xl">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-3xl font-bold flex items-center gap-4">
                <span className="text-4xl">🔍</span>
                <span className="bg-gradient-to-r from-green-400 to-blue-400 bg-clip-text text-transparent">
                  Architecture: {architectureName}
                </span>
              </h3>
              <Button
                onClick={handleAnalyze}
                disabled={isAnalyzing || !nodes.length}
                size="lg"
                className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 px-8 py-4 text-lg font-semibold rounded-xl shadow-lg transition-all transform hover:scale-105"
              >
                {isAnalyzing ? (
                  <div className="flex items-center gap-2">
                    <div className="animate-spin rounded-full h-5 w-5 border-2 border-white border-t-transparent"></div>
                    Analyzing...
                  </div>
                ) : (
                  'Re-analyze'
                )}
              </Button>
            </div>
            
            {analysisResult?.meta && (
              <div className="grid grid-cols-3 gap-8 text-lg">
                <div className="flex items-center gap-4 bg-gradient-to-br from-blue-600/20 to-purple-600/20 rounded-2xl p-6 border border-blue-500/30 hover:shadow-lg transition-all">
                  <span className="text-5xl">💾</span>
                  <div>
                    <div className="font-bold text-xl text-blue-300">Cases Analyzed</div>
                    <div className="text-2xl font-mono text-white">{analysisResult.meta.total_cases_analyzed}</div>
                  </div>
                </div>
                <div className="flex items-center gap-4 bg-gradient-to-br from-green-600/20 to-teal-600/20 rounded-2xl p-6 border border-green-500/30 hover:shadow-lg transition-all">
                  <span className="text-5xl">🛡️</span>
                  <div>
                    <div className="font-bold text-xl text-green-300">Data Source</div>
                    <div className="text-lg text-white">{analysisResult.meta.vcdb_available ? '✅ VCDB Live' : '⚠️ Mock Data'}</div>
                  </div>
                </div>
                <div className="flex items-center gap-4 bg-gradient-to-br from-yellow-600/20 to-orange-600/20 rounded-2xl p-6 border border-yellow-500/30 hover:shadow-lg transition-all">
                  <span className="text-5xl">📈</span>
                  <div>
                    <div className="font-bold text-xl text-yellow-300">Confidence</div>
                    <div className={`text-2xl font-bold ${getConfidenceColor(analysisResult.analysis?.confidence_score || 0)}`}>
                      {Math.round((analysisResult.analysis?.confidence_score || 0) * 100)}%
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Loading State */}
          {isAnalyzing && (
            <div className="flex items-center justify-center py-32 h-full bg-gradient-to-r from-blue-900/20 via-purple-900/20 to-cyan-900/20 rounded-2xl">
              <div className="flex flex-col items-center gap-8">
                <div className="relative">
                  <div className="animate-spin rounded-full h-24 w-24 border-8 border-blue-400/30"></div>
                  <div className="animate-spin rounded-full h-24 w-24 border-t-8 border-blue-400 absolute top-0 left-0"></div>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-3xl">🔍</span>
                  </div>
                </div>
                <div className="text-center space-y-4">
                  <h3 className="text-3xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
                    Analyzing Architecture
                  </h3>
                  <p className="text-gray-400 text-xl max-w-md">
                    Scanning through thousands of historical cybersecurity incidents to find patterns matching your architecture...
                  </p>
                  <div className="flex items-center justify-center gap-2 text-lg text-blue-400">
                    <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse"></div>
                    <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse" style={{animationDelay: '0.2s'}}></div>
                    <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse" style={{animationDelay: '0.4s'}}></div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Error State */}
          {error && (
            <div className="bg-gradient-to-r from-red-500/20 via-red-600/20 to-red-500/20 border-2 border-red-500/30 rounded-2xl p-8 shadow-xl">
              <div className="flex items-center gap-4 text-red-400 mb-6">
                <span className="text-4xl animate-bounce">⚠️</span>
                <span className="font-bold text-2xl">Analysis Error</span>
              </div>
              <p className="text-red-300 text-xl mb-6 leading-relaxed">{error}</p>
              <Button 
                onClick={handleAnalyze} 
                className="bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 px-8 py-4 text-lg font-semibold rounded-xl shadow-lg transition-all transform hover:scale-105"
                size="lg"
              >
                <span className="flex items-center gap-2">
                  🔄 Try Again
                </span>
              </Button>
            </div>
          )}

          {/* Results */}
          {analysisResult && !isAnalyzing && (
            <div className="flex-1 overflow-hidden h-full">
              <div className="grid grid-cols-1 xl:grid-cols-2 gap-10 h-full">
                
                {/* Similar Cases */}
                <div className="bg-gradient-to-br from-gray-800/80 via-gray-700/80 to-gray-800/80 rounded-2xl p-8 overflow-hidden border border-gray-600/50 shadow-2xl backdrop-blur-sm">
                  <h3 className="text-2xl font-bold mb-8 flex items-center gap-4">
                    <span className="text-4xl">⚠️</span>
                    <span className="bg-gradient-to-r from-orange-400 to-red-400 bg-clip-text text-transparent">
                      Similar Historical Incidents ({analysisResult.similar_cases.length})
                    </span>
                  </h3>
                  
                  <div className="space-y-6 overflow-y-auto max-h-[700px] pr-4 case-study-scroll">
                    {analysisResult.similar_cases.map((incident, index) => (
                      <div
                        key={incident.incident_id}
                        className={`incident-card border-2 rounded-2xl p-6 cursor-pointer transition-all hover:shadow-2xl transform hover:scale-[1.02] ${
                          selectedIncident === incident.incident_id
                            ? 'border-blue-500 bg-gradient-to-br from-blue-500/20 to-purple-500/20 shadow-xl shadow-blue-500/20'
                            : 'border-gray-600 hover:border-gray-500 bg-gradient-to-br from-gray-800/50 to-gray-700/50'
                        }`}
                        onClick={() => setSelectedIncident(
                          selectedIncident === incident.incident_id ? null : incident.incident_id
                        )}
                      >
                        <div className="flex items-start justify-between mb-6">
                          <div className="flex items-center gap-4">
                            <span className="text-lg font-mono text-gray-300 bg-gray-700/70 px-4 py-2 rounded-xl border border-gray-600">
                              {incident.incident_id}
                            </span>
                            <span className={`px-4 py-2 rounded-full text-base font-bold border ${getRiskLevelColor(incident.impact_overall_rating)}`}>
                              {incident.impact_overall_rating}
                            </span>
                          </div>
                          <div className="text-right">
                            <div className="text-base text-blue-400 font-bold bg-blue-500/10 px-3 py-1 rounded-full">
                              {Math.round((1 - incident.distance) * 100)}% match
                            </div>
                            <div className="text-sm text-gray-400 mt-1">Similarity Score</div>
                          </div>
                        </div>
                        
                        <div className="grid grid-cols-2 gap-4 text-lg mb-6">
                          <div className="flex items-center gap-3 bg-gradient-to-r from-blue-600/20 to-blue-500/20 rounded-xl p-4 border border-blue-500/30">
                            <span className="text-2xl">🏢</span>
                            <div>
                              <div className="text-sm text-blue-300 font-semibold">Industry</div>
                              <div className="text-white font-bold">{incident.industry}</div>
                            </div>
                          </div>
                          <div className="flex items-center gap-3 bg-gradient-to-r from-green-600/20 to-green-500/20 rounded-xl p-4 border border-green-500/30">
                            <span className="text-2xl">📍</span>
                            <div>
                              <div className="text-sm text-green-300 font-semibold">Location</div>
                              <div className="text-white font-bold">{incident.country}</div>
                            </div>
                          </div>
                          <div className="flex items-center gap-3 bg-gradient-to-r from-yellow-600/20 to-yellow-500/20 rounded-xl p-4 border border-yellow-500/30">
                            <span className="text-2xl">🕒</span>
                            <div>
                              <div className="text-sm text-yellow-300 font-semibold">Year</div>
                              <div className="text-white font-bold">{incident.year}</div>
                            </div>
                          </div>
                          <div className="flex items-center gap-3 bg-gradient-to-r from-purple-600/20 to-purple-500/20 rounded-xl p-4 border border-purple-500/30">
                            <span className="text-2xl">👤</span>
                            <div>
                              <div className="text-sm text-purple-300 font-semibold">Actor</div>
                              <div className="text-white font-bold">{incident.actor}</div>
                            </div>
                          </div>
                        </div>
                        
                        <div className="space-y-4">
                          <div className="bg-gradient-to-r from-orange-500/20 to-red-500/20 border border-orange-500/30 rounded-xl p-4">
                            <div className="text-sm text-orange-300 font-bold mb-2 flex items-center gap-2">
                              <span>⚔️</span>
                              Attack Method
                            </div>
                            <div className="text-lg text-orange-100 font-semibold">{incident.action}</div>
                          </div>
                          
                          <div className="bg-gradient-to-r from-blue-500/20 to-cyan-500/20 border border-blue-500/30 rounded-xl p-4">
                            <div className="text-sm text-blue-300 font-bold mb-2 flex items-center gap-2">
                              <span>🎯</span>
                              Targeted Assets
                            </div>
                            <div className="text-lg text-blue-100 font-semibold">{incident.asset}</div>
                          </div>
                        </div>
                        
                        {selectedIncident === incident.incident_id && (
                          <div className="mt-6 pt-6 border-t border-gray-500/50 bg-gradient-to-r from-gray-600/20 to-gray-500/20 rounded-xl p-4">
                            <div className="text-sm text-gray-300 font-bold mb-3 flex items-center gap-2">
                              <span>📋</span>
                              Incident Summary
                            </div>
                            <p className="text-lg text-gray-200 leading-relaxed">{incident.summary}</p>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Analysis & Recommendations */}
                <div className="bg-gradient-to-br from-gray-800/80 via-gray-700/80 to-gray-800/80 rounded-2xl p-8 overflow-hidden border border-gray-600/50 shadow-2xl backdrop-blur-sm">
                  <h3 className="text-2xl font-bold mb-8 flex items-center gap-4">
                    <span className="text-4xl">🛡️</span>
                    <span className="bg-gradient-to-r from-green-400 to-blue-400 bg-clip-text text-transparent">
                      Risk Analysis & Recommendations
                    </span>
                  </h3>
                  
                  <div className="space-y-8 overflow-y-auto max-h-[700px] pr-4 case-study-scroll">
                    {/* Risk Patterns */}
                    <div>
                      <h4 className="font-bold text-orange-400 mb-6 flex items-center gap-3 text-xl">
                        <span className="text-2xl">⚠️</span>
                        <span>Identified Risk Patterns</span>
                      </h4>
                      <div className="space-y-4">
                        {analysisResult.analysis?.risk_patterns?.map((pattern, index) => (
                          <div key={index} className="recommendation-card bg-gradient-to-r from-orange-500/20 to-red-500/20 border border-orange-500/30 rounded-2xl p-6 hover:from-orange-500/30 hover:to-red-500/30 transition-all shadow-lg">
                            <div className="flex items-start gap-4">
                              <span className="text-orange-400 text-3xl mt-1 flex-shrink-0">🔍</span>
                              <div className="flex-1 min-w-0">
                                <p className="text-lg text-orange-100 leading-relaxed break-words font-medium">{pattern}</p>
                                <div className="mt-3 flex items-center gap-2 text-sm text-orange-300">
                                  <span className="bg-orange-500/30 px-3 py-1 rounded-full">⚡ High Priority</span>
                                </div>
                              </div>
                            </div>
                          </div>
                        )) || (
                          <div className="bg-gray-700/50 rounded-2xl p-6 border border-gray-600">
                            <p className="text-gray-400 text-lg">No specific risk patterns identified.</p>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Recommendations */}
                    <div>
                      <h4 className="font-bold text-green-400 mb-6 flex items-center gap-3 text-xl">
                        <span className="text-2xl">🛡️</span>
                        <span>Security Recommendations</span>
                      </h4>
                      <div className="space-y-4">
                        {analysisResult.analysis?.recommendations?.map((recommendation, index) => (
                          <div key={index} className="recommendation-card bg-gradient-to-r from-green-500/20 to-teal-500/20 border border-green-500/30 rounded-2xl p-6 hover:from-green-500/30 hover:to-teal-500/30 transition-all shadow-lg">
                            <div className="flex items-start gap-4">
                              <span className="text-green-400 text-3xl mt-1 flex-shrink-0">✅</span>
                              <div className="flex-1 min-w-0">
                                <p className="text-lg text-green-100 leading-relaxed break-words font-medium mb-4">{recommendation}</p>
                                <div className="flex flex-wrap items-center gap-3 text-sm text-green-300">
                                  <span className="bg-green-500/30 px-4 py-2 rounded-full whitespace-nowrap font-semibold flex items-center gap-1">
                                    🔥 Priority: High
                                  </span>
                                  <span className="bg-teal-500/30 px-4 py-2 rounded-full whitespace-nowrap font-semibold flex items-center gap-1">
                                    📊 Impact: Medium
                                  </span>
                                  <span className="bg-blue-500/30 px-4 py-2 rounded-full whitespace-nowrap font-semibold flex items-center gap-1">
                                    ⚡ Effort: Low
                                  </span>
                                </div>
                              </div>
                            </div>
                          </div>
                        )) || (
                          <div className="bg-gray-700/50 rounded-2xl p-6 border border-gray-600">
                            <p className="text-gray-400 text-lg">No specific recommendations available.</p>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Quick Actions */}
                    <div className="bg-gradient-to-r from-blue-600/20 via-purple-600/20 to-cyan-600/20 border border-blue-500/30 rounded-2xl p-6 shadow-xl">
                      <h4 className="font-bold text-blue-400 mb-6 flex items-center gap-3 text-xl">
                        <span className="text-2xl">⚡</span>
                        <span>Quick Actions</span>
                      </h4>
                      <div className="grid gap-4">
                        <Button className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-left justify-start p-6 h-auto rounded-xl shadow-lg transition-all transform hover:scale-105">
                          <div className="flex items-center gap-4">
                            <span className="text-2xl">📊</span>
                            <div>
                              <div className="font-bold text-lg">Export Analysis Report</div>
                              <div className="text-sm text-blue-200">Download comprehensive PDF with all findings</div>
                            </div>
                          </div>
                        </Button>
                        <Button variant="outline" className="border-2 border-blue-500/50 text-blue-300 hover:bg-blue-500/20 text-left justify-start p-6 h-auto rounded-xl transition-all transform hover:scale-105">
                          <div className="flex items-center gap-4">
                            <span className="text-2xl">📅</span>
                            <div>
                              <div className="font-bold text-lg">Schedule Follow-up</div>
                              <div className="text-sm text-blue-200">Set automated security review reminders</div>
                            </div>
                          </div>
                        </Button>
                        <Button variant="outline" className="border-2 border-green-500/50 text-green-300 hover:bg-green-500/20 text-left justify-start p-6 h-auto rounded-xl transition-all transform hover:scale-105">
                          <div className="flex items-center gap-4">
                            <span className="text-2xl">🚀</span>
                            <div>
                              <div className="font-bold text-lg">Start Implementation</div>
                              <div className="text-sm text-green-200">Begin applying security recommendations</div>
                            </div>
                          </div>
                        </Button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default CaseStudyAnalysisModal;