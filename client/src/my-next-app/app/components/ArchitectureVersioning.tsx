/**
 * Architecture Versioning UI
 * Timeline view showing history of architecture improvements
 */

'use client';

import React, { useState, useEffect } from 'react';
import { Node, Edge } from 'reactflow';
import { CustomNodeData, CustomEdgeData, Architecture } from '../types';

interface ArchitectureVersion {
  id: string;
  version: number;
  timestamp: string;
  name: string;
  description: string;
  attack_mitigated?: string;
  changes_count: number;
  security_improvements: string[];
  nodes: Node<CustomNodeData>[];
  edges: Edge<CustomEdgeData>[];
}

interface ArchitectureVersioningProps {
  isOpen: boolean;
  onClose: () => void;
  currentNodes: Node<CustomNodeData>[];
  currentEdges: Edge<CustomEdgeData>[];
  onLoadVersion: (version: ArchitectureVersion) => void;
}

export const ArchitectureVersioning: React.FC<ArchitectureVersioningProps> = ({
  isOpen,
  onClose,
  currentNodes,
  currentEdges,
  onLoadVersion,
}) => {
  const [versions, setVersions] = useState<ArchitectureVersion[]>([]);
  const [selectedVersion, setSelectedVersion] = useState<ArchitectureVersion | null>(null);

  // Load versions from localStorage
  useEffect(() => {
    if (isOpen) {
      const storedVersions = localStorage.getItem('architecture_versions');
      if (storedVersions) {
        setVersions(JSON.parse(storedVersions));
      }
    }
  }, [isOpen]);

  // Save current architecture as a new version
  const handleSaveVersion = () => {
    const versionName = prompt('Enter version name:', `Version ${versions.length + 1}`);
    if (!versionName) return;

    const description = prompt('Enter version description (optional):');
    
    const newVersion: ArchitectureVersion = {
      id: `v${Date.now()}`,
      version: versions.length + 1,
      timestamp: new Date().toISOString(),
      name: versionName,
      description: description || 'Architecture snapshot',
      changes_count: 0,
      security_improvements: [],
      nodes: currentNodes,
      edges: currentEdges,
    };

    const updatedVersions = [...versions, newVersion];
    setVersions(updatedVersions);
    localStorage.setItem('architecture_versions', JSON.stringify(updatedVersions));
    
    alert('✅ Version saved successfully!');
  };

  // Delete a version
  const handleDeleteVersion = (versionId: string) => {
    if (confirm('Are you sure you want to delete this version?')) {
      const updatedVersions = versions.filter(v => v.id !== versionId);
      setVersions(updatedVersions);
      localStorage.setItem('architecture_versions', JSON.stringify(updatedVersions));
    }
  };

  // Compare two versions
  const handleCompareVersions = (version1: ArchitectureVersion, version2: ArchitectureVersion) => {
    alert(`Comparing ${version1.name} with ${version2.name}\n\nThis feature is coming soon!`);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl w-full h-full max-w-[90vw] max-h-[90vh] flex flex-col overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-700 bg-gradient-to-r from-indigo-900/20 to-purple-900/20">
          <div>
            <h2 className="text-2xl font-bold text-white flex items-center gap-3">
              <span className="text-3xl">📚</span>
              Architecture Version History
            </h2>
            <p className="text-gray-400 text-sm mt-1">
              Track and manage different versions of your architecture
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors text-2xl w-10 h-10 flex items-center justify-center rounded-lg hover:bg-gray-800"
          >
            ✕
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-hidden flex">
          {/* Timeline List */}
          <div className="w-1/3 border-r border-gray-700 overflow-y-auto bg-gray-800/30">
            <div className="p-4 border-b border-gray-700">
              <button
                onClick={handleSaveVersion}
                className="w-full px-4 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
              >
                <span>💾</span>
                Save Current as New Version
              </button>
            </div>

            {versions.length === 0 ? (
              <div className="p-8 text-center">
                <div className="text-6xl mb-4">📭</div>
                <div className="text-gray-400 text-lg">No versions saved yet</div>
                <div className="text-gray-500 text-sm mt-2">
                  Click "Save Current as New Version" to create your first version
                </div>
              </div>
            ) : (
              <div className="p-4 space-y-2">
                {versions.map((version, index) => (
                  <div
                    key={version.id}
                    onClick={() => setSelectedVersion(version)}
                    className={`p-4 rounded-lg cursor-pointer transition-colors ${
                      selectedVersion?.id === version.id
                        ? 'bg-blue-600 border border-blue-500'
                        : 'bg-gray-800 border border-gray-700 hover:bg-gray-750'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-1 rounded text-xs font-bold ${
                            selectedVersion?.id === version.id
                              ? 'bg-blue-500 text-white'
                              : 'bg-blue-600 text-white'
                          }`}>
                            v{version.version}
                          </span>
                          <span className="font-bold text-white">{version.name}</span>
                        </div>
                        <div className="text-xs text-gray-400 mt-1">
                          {new Date(version.timestamp).toLocaleString()}
                        </div>
                        <div className="text-sm text-gray-300 mt-2">
                          {version.description}
                        </div>
                        {version.attack_mitigated && (
                          <div className="mt-2 text-xs text-green-400 flex items-center gap-1">
                            <span>🛡️</span>
                            Mitigated: {version.attack_mitigated}
                          </div>
                        )}
                        <div className="mt-2 flex items-center gap-3 text-xs text-gray-400">
                          <span>{version.nodes.length} nodes</span>
                          <span>•</span>
                          <span>{version.edges.length} connections</span>
                          {version.changes_count > 0 && (
                            <>
                              <span>•</span>
                              <span>{version.changes_count} changes</span>
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Version Details */}
          <div className="flex-1 overflow-y-auto">
            {selectedVersion ? (
              <div className="p-6 space-y-6">
                {/* Version Info */}
                <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <div className="flex items-center gap-3 mb-2">
                        <span className="px-3 py-1 bg-blue-600 text-white text-sm font-bold rounded">
                          Version {selectedVersion.version}
                        </span>
                        <h3 className="text-2xl font-bold text-white">{selectedVersion.name}</h3>
                      </div>
                      <p className="text-gray-400">{selectedVersion.description}</p>
                      <div className="text-sm text-gray-500 mt-2">
                        Created: {new Date(selectedVersion.timestamp).toLocaleString()}
                      </div>
                    </div>
                    <button
                      onClick={() => handleDeleteVersion(selectedVersion.id)}
                      className="px-3 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-lg transition-colors"
                    >
                      🗑️ Delete
                    </button>
                  </div>

                  {/* Stats */}
                  <div className="grid grid-cols-3 gap-4 mt-4">
                    <div className="bg-gray-700/50 rounded-lg p-4">
                      <div className="text-3xl font-bold text-blue-400">{selectedVersion.nodes.length}</div>
                      <div className="text-sm text-gray-400 mt-1">Components</div>
                    </div>
                    <div className="bg-gray-700/50 rounded-lg p-4">
                      <div className="text-3xl font-bold text-green-400">{selectedVersion.edges.length}</div>
                      <div className="text-sm text-gray-400 mt-1">Connections</div>
                    </div>
                    <div className="bg-gray-700/50 rounded-lg p-4">
                      <div className="text-3xl font-bold text-purple-400">{selectedVersion.security_improvements.length}</div>
                      <div className="text-sm text-gray-400 mt-1">Security Features</div>
                    </div>
                  </div>
                </div>

                {/* Security Improvements */}
                {selectedVersion.security_improvements.length > 0 && (
                  <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-6">
                    <h4 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                      <span>🛡️</span>
                      Security Improvements
                    </h4>
                    <div className="space-y-2">
                      {selectedVersion.security_improvements.map((improvement, index) => (
                        <div key={index} className="flex items-start gap-3 text-gray-300">
                          <span className="text-green-400 flex-shrink-0">✓</span>
                          <span>{improvement}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Components List */}
                <div className="bg-gray-800/50 border border-gray-700 rounded-lg p-6">
                  <h4 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                    <span>📦</span>
                    Components ({selectedVersion.nodes.length})
                  </h4>
                  <div className="grid grid-cols-2 gap-3">
                    {selectedVersion.nodes.map((node) => (
                      <div key={node.id} className="bg-gray-700/50 rounded-lg p-3">
                        <div className="flex items-center gap-2">
                          <span className="text-2xl">{node.data.icon || '📦'}</span>
                          <div className="flex-1 min-w-0">
                            <div className="font-medium text-white truncate">
                              {node.data.name || node.id}
                            </div>
                            <div className="text-xs text-gray-400">{node.data.type}</div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => onLoadVersion(selectedVersion)}
                    className="flex-1 px-6 py-3 bg-green-600 hover:bg-green-700 text-white font-bold rounded-lg transition-colors flex items-center justify-center gap-2"
                  >
                    <span>📂</span>
                    Load This Version
                  </button>
                  <button
                    onClick={() => {
                      const otherVersion = versions.find(v => v.id !== selectedVersion.id);
                      if (otherVersion) {
                        handleCompareVersions(selectedVersion, otherVersion);
                      } else {
                        alert('Need at least 2 versions to compare');
                      }
                    }}
                    className="px-6 py-3 bg-purple-600 hover:bg-purple-700 text-white font-medium rounded-lg transition-colors flex items-center gap-2"
                  >
                    <span>🔍</span>
                    Compare
                  </button>
                </div>
              </div>
            ) : (
              <div className="h-full flex items-center justify-center">
                <div className="text-center">
                  <div className="text-6xl mb-4">👈</div>
                  <div className="text-gray-400 text-lg">Select a version to view details</div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
