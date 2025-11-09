/**
 * Architecture Builder Application
 * Main component that brings together the sidebar, canvas, and controls
 */

'use client';
import React, { useState, useCallback } from 'react';
import { Node, Edge } from 'reactflow';
import { ComponentSidebar } from './components/flow/ComponentSidebar';
import { FlowCanvasWrapper } from './components/flow/FlowCanvas';
import { AttackSimulationModal } from './components/AttackSimulationModal';
import { ComparisonView } from './components/ComparisonView';
import { ArchitectureVersioning } from './components/ArchitectureVersioning';
import { HealingModal, HealingResult } from './components/healing/HealingModal';
import { HealingComparisonView } from './components/healing/HealingComparisonView';
import { AISuggestionModal } from './components/ai-suggestion/AISuggestionModal';
import { TemplateGalleryModal } from './components/templates/TemplateGalleryModal';
import { SecurityDashboard } from './components/SecurityDashboard';
import DatabaseTestPanel from './components/DatabaseTestPanel';
import EnhancedConnectionModal from './components/flow/EnhancedConnectionModal';
import { ArchitectureTemplate } from './utils/architectureTemplates';
import { Button } from './components/ui/button';
import { CustomNodeData, CustomEdgeData, Architecture, ArchitectureMetadata } from './types';
import { ConfiguredAttack, SuggestedArchitecture } from './types/attack';
import { useArchitectureStorage } from './utils/architectureStorage';
import { attackStorage } from './utils/attackStorage';
import { agentService } from './utils/agentService';
import { getComponentByType } from './utils/componentRegistry';
import VirtualSandboxModal from './components/virtual-sandbox/VirtualSandboxModal';
import CaseStudyAnalysisModal from './components/case-study/CaseStudyAnalysisModal';


/**
 * Main application toolbar
 */
interface ToolbarProps {
  onSave: () => void;
  onLoad: () => void;
  onExport: () => void;
  onClear: () => void;
  onAttackSimulation: () => void;
  onHeal: () => void;
  onAISuggestion: () => void;
  onTemplates: () => void;
  onVersionHistory: () => void;
  onSecurityDashboard: () => void;
  onVirtualSandbox: () => void;
  onCaseStudyAnalysis: () => void;
  hasNodes: boolean;
  architectureName: string;
  onArchitectureNameChange: (name: string) => void;
}

const Toolbar: React.FC<ToolbarProps> = ({
  onSave,
  onLoad,
  onExport,
  onClear,
  onAttackSimulation,
  onHeal,
  onAISuggestion,
  onTemplates,
  onVersionHistory,
  onSecurityDashboard,
  onVirtualSandbox,
  onCaseStudyAnalysis,
  hasNodes,
  architectureName,
  onArchitectureNameChange
}) => {
  return (
    <div className="h-16 bg-gray-900/95 backdrop-blur-sm border-b border-gray-700 flex items-center justify-between px-6 shadow-lg">
      <div className="flex items-center gap-4">
        <h1 className="text-xl font-bold text-white">InsightX Architecture Builder</h1>
        <div className="h-6 w-px bg-gray-600"></div>
        <input
          type="text"
          value={architectureName}
          onChange={(e) => onArchitectureNameChange(e.target.value)}
          placeholder="Architecture Name"
          className="px-3 py-1 bg-gray-800 border border-gray-600 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent text-white placeholder-gray-400"
        />
      </div>
      
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={onLoad}
          className="border-gray-600 text-gray-300 hover:bg-gray-800 hover:text-white"
        >
          📂 Load
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={onSave}
          disabled={!hasNodes}
          className="border-gray-600 text-gray-300 hover:bg-gray-800 hover:text-white disabled:opacity-50"
        >
          💾 Save
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={onExport}
          disabled={!hasNodes}
          className="border-gray-600 text-gray-300 hover:bg-gray-800 hover:text-white disabled:opacity-50"
        >
          📄 Export
        </Button>
        <div className="h-6 w-px bg-gray-600 mx-2"></div>
        <Button
          variant="outline"
          size="sm"
          onClick={onVersionHistory}
          className="border-purple-600 bg-purple-600/10 text-purple-400 hover:bg-purple-600 hover:text-white"
        >
          📚 Versions
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={onAISuggestion}
          className="border-purple-600 bg-purple-600/10 text-purple-400 hover:bg-purple-600 hover:text-white"
        >
          🤖 AI Suggestion
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={onTemplates}
          className="border-cyan-600 bg-cyan-600/10 text-cyan-400 hover:bg-cyan-600 hover:text-white"
        >
          📐 Templates
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={onSecurityDashboard}
          disabled={!hasNodes}
          className="border-blue-600 bg-blue-600/10 text-blue-400 hover:bg-blue-600 hover:text-white disabled:opacity-50"
        >
          🔒 Security Analysis
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={onAttackSimulation}
          className="border-red-600 bg-red-600/10 text-red-400 hover:bg-red-600 hover:text-white"
        >
          ⚡ Cyber Attacks
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={onHeal}
          disabled={!hasNodes}
          className="border-green-600 bg-green-600/10 text-green-400 hover:bg-green-600 hover:text-white disabled:opacity-50"
        >
          🩹 Heal Architecture
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={onVirtualSandbox}
          disabled={!hasNodes}
          className="border-purple-600 bg-purple-600/10 text-purple-400 hover:bg-purple-600 hover:text-white disabled:opacity-50"
        >
          🚀 Virtual Sandbox
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={onCaseStudyAnalysis}
          disabled={!hasNodes}
          className="border-orange-600 bg-orange-600/10 text-orange-400 hover:bg-orange-600 hover:text-white disabled:opacity-50"
        >
          📊 Case Studies
        </Button>
        <div className="h-6 w-px bg-gray-600 mx-2"></div>
        <Button
          variant="destructive"
          size="sm"
          onClick={onClear}
          disabled={!hasNodes}
          className="bg-red-600 hover:bg-red-700 text-white disabled:opacity-50"
        >
          🗑️ Clear
        </Button>
      </div>
    </div>
  );
};

/**
 * Property field component for rendering different input types
 */
interface PropertyFieldProps {
  label: string;
  value: any;
  type: any;
  onChange: (value: any) => void;
}

const PropertyField: React.FC<PropertyFieldProps> = ({ label, value, type, onChange }) => {
  // Handle different value types
  if (typeof type === 'string') {
    if (type === 'Boolean') {
      return (
        <div>
          <label className="flex items-center">
            <input
              type="checkbox"
              checked={Boolean(value)}
              onChange={(e) => onChange(e.target.checked)}
              className="mr-2 text-blue-500 bg-gray-700 border-gray-600 rounded focus:ring-blue-500"
            />
            <span className="text-sm text-gray-300">{label}</span>
          </label>
        </div>
      );
    }
    
    if (type === 'Integer') {
      return (
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">
            {label}
          </label>
          <input
            type="number"
            value={value || ''}
            onChange={(e) => onChange(parseInt(e.target.value) || '')}
            className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent text-white placeholder-gray-400"
          />
        </div>
      );
    }
    
    // Default to string input
    return (
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">
          {label}
        </label>
        <input
          type="text"
          value={value || ''}
          onChange={(e) => onChange(e.target.value)}
          className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent text-white placeholder-gray-400"
        />
      </div>
    );
  }
  
  // Handle array options (dropdown)
  if (Array.isArray(type)) {
    return (
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">
          {label}
        </label>
        <select
          value={value || ''}
          onChange={(e) => onChange(e.target.value)}
          className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent text-white"
        >
          <option value="">Select {label}</option>
          {type.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </div>
    );
  }
  
  // Handle object types (render as JSON for now)
  if (typeof type === 'object') {
    return (
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-1">
          {label} (Complex Object)
        </label>
        <textarea
          value={typeof value === 'object' ? JSON.stringify(value, null, 2) : value || ''}
          onChange={(e) => {
            try {
              const parsed = JSON.parse(e.target.value);
              onChange(parsed);
            } catch {
              onChange(e.target.value);
            }
          }}
          rows={3}
          className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-xs text-white placeholder-gray-400"
        />
      </div>
    );
  }
  
  return null;
};

/**
 * Properties panel for selected nodes/edges
 */
interface PropertiesPanelProps {
  selectedNode: Node<CustomNodeData> | null;
  selectedEdge: Edge<CustomEdgeData> | null;
  onPropertyUpdate: (id: string, updates: Record<string, any>) => void;
}

const PropertiesPanel: React.FC<PropertiesPanelProps> = ({
  selectedNode,
  selectedEdge,
  onPropertyUpdate
}) => {
  // Local form state for node properties
  const [formData, setFormData] = useState<Record<string, any>>({});
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false);

  // Local form state for edge properties
  const [edgeFormData, setEdgeFormData] = useState<Record<string, any>>({});
  const [edgeHasUnsavedChanges, setEdgeHasUnsavedChanges] = useState(false);

  // Initialize form data when selectedNode changes
  React.useEffect(() => {
    if (selectedNode) {
      setFormData(selectedNode.data.properties || {});
      setHasUnsavedChanges(false);
    }
  }, [selectedNode?.id]); // Only reset when node ID changes

  // Initialize edge form data when selectedEdge changes
  React.useEffect(() => {
    if (selectedEdge) {
      setEdgeFormData(selectedEdge.data || {});
      setEdgeHasUnsavedChanges(false);
    }
  }, [selectedEdge?.id]);

  // Handle form field changes
  const handleFormChange = (key: string, value: any) => {
    setFormData(prev => ({
      ...prev,
      [key]: value
    }));
    setHasUnsavedChanges(true);
  };

  // Save configuration to node
  const handleSaveConfiguration = () => {
    if (selectedNode) {
      onPropertyUpdate(selectedNode.id, {
        properties: formData
      });
      setHasUnsavedChanges(false);
    }
  };

  // Reset form to current node properties
  const handleResetForm = () => {
    if (selectedNode) {
      setFormData(selectedNode.data.properties || {});
      setHasUnsavedChanges(false);
    }
  };
  if (!selectedNode && !selectedEdge) {
    return (
      <div className="w-80 bg-gray-900/95 backdrop-blur-sm border-l border-gray-700 p-4">
        <h3 className="text-lg font-semibold text-white mb-4">Properties</h3>
        <div className="text-center py-8 text-gray-400">
          <div className="text-3xl mb-2">⚙️</div>
          <p>Select a component or connection to view its properties</p>
        </div>
      </div>
    );
  }

  if (selectedNode) {
    const component = getComponentByType(selectedNode.data.component_type);
    if (!component) {
      return (
        <div className="w-80 bg-gray-900/95 backdrop-blur-sm border-l border-gray-700 p-4">
          <h3 className="text-lg font-semibold text-white mb-4">Properties</h3>
          <div className="text-red-400">Component configuration not found for: {selectedNode.data.component_type}</div>
        </div>
      );
    }

    return (
      <div className="w-80 bg-gray-900/95 backdrop-blur-sm border-l border-gray-700 p-4 overflow-y-auto max-h-full">
        <h3 className="text-lg font-semibold text-white mb-4">
          {selectedNode.data.component_type.replace(/_/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase())} Properties
        </h3>
        
        <div className="space-y-6">
          {/* Component Icon and Type */}
          <div className="flex items-center gap-3 p-3 bg-gray-800/50 rounded-lg border border-gray-700">
            <div className="text-2xl">{component.icon}</div>
            <div>
              <div className="font-medium text-white">{selectedNode.data.name || selectedNode.data.component_type}</div>
              <div className="text-sm text-gray-400">{component.description}</div>
              <div className="text-xs text-gray-500 mt-1">Category: {component.category}</div>
            </div>
          </div>

          {/* Dynamic Configuration Sections */}
          {Object.entries(component.configurations).map(([sectionName, sectionConfig]) => (
            <div key={sectionName} className="border-t border-gray-700 pt-4">
              <h4 className="font-medium text-white mb-3 flex items-center">
                <span className="text-sm bg-blue-600/80 text-blue-100 px-2 py-1 rounded mr-2">
                  {sectionName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                </span>
              </h4>
              <div className="space-y-3 pl-2">
                {Object.entries(sectionConfig as Record<string, any>).map(([propertyKey, propertyType]) => {
                  const formFieldKey = `${sectionName}.${propertyKey}`;
                  const currentValue = formData[formFieldKey] || formData[propertyKey] || '';
                  
                  return (
                    <PropertyField
                      key={formFieldKey}
                      label={propertyKey.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                      value={currentValue}
                      type={propertyType}
                      onChange={(value) => handleFormChange(formFieldKey, value)}
                    />
                  );
                })}
              </div>
            </div>
          ))}

          {/* Node Status */}
          <div className="border-t pt-4">
            <h4 className="font-medium text-gray-900 mb-3">Node Status</h4>
            <div>
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={formData.configured || false}
                  onChange={(e) => handleFormChange('configured', e.target.checked)}
                  className="mr-2"
                />
                <span className="text-sm text-gray-700">Mark as Configured</span>
              </label>
            </div>
          </div>

          {/* Save/Reset Configuration Buttons */}
          <div className="border-t pt-4 space-y-3">
            <div className="flex gap-2">
              <Button
                onClick={handleSaveConfiguration}
                disabled={!hasUnsavedChanges}
                className={`flex-1 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                  hasUnsavedChanges 
                    ? 'bg-blue-600 hover:bg-blue-700 text-white' 
                    : 'bg-gray-100 text-gray-400 cursor-not-allowed'
                }`}
              >
                💾 Save Configuration
              </Button>
              <Button
                onClick={handleResetForm}
                disabled={!hasUnsavedChanges}
                variant="outline"
                className={`px-3 py-2 rounded-md text-sm transition-colors ${
                  hasUnsavedChanges 
                    ? 'border-gray-300 text-gray-700 hover:bg-gray-50' 
                    : 'border-gray-200 text-gray-400 cursor-not-allowed'
                }`}
              >
                ↺
              </Button>
            </div>
            
            {hasUnsavedChanges && (
              <div className="text-xs text-amber-600 bg-amber-50 p-2 rounded border border-amber-200">
                ⚠️ You have unsaved changes. Click "Save Configuration" to apply them.
              </div>
            )}
            
            {!hasUnsavedChanges && selectedNode?.data.properties && Object.keys(selectedNode.data.properties).length > 0 && (
              <div className="text-xs text-green-600 bg-green-50 p-2 rounded border border-green-200">
                ✅ Configuration saved successfully!
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  if (selectedEdge) {
    // Handle edge form changes
    const handleEdgeFormChange = (key: string, value: any) => {
      setEdgeFormData(prev => ({
        ...prev,
        [key]: value
      }));
      setEdgeHasUnsavedChanges(true);
    };

    // Save edge configuration
    const handleSaveEdgeConfiguration = () => {
      if (selectedEdge) {
        onPropertyUpdate(selectedEdge.id, edgeFormData);
        setEdgeHasUnsavedChanges(false);
      }
    };

    return (
      <div className="w-80 bg-white border-l border-gray-200 p-4">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">
          Connection Properties
        </h3>
        
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Connection Type
            </label>
            <select
              value={edgeFormData.type || 'network'}
              onChange={(e) => handleEdgeFormChange('type', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="network">Network</option>
              <option value="database_connection">Database Connection</option>
              <option value="api_call">API Call</option>
              <option value="data_flow">Data Flow</option>
              <option value="authentication">Authentication</option>
            </select>
          </div>

          <div>
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={edgeFormData.encrypted || false}
                onChange={(e) => handleEdgeFormChange('encrypted', e.target.checked)}
                className="mr-2"
              />
              <span className="text-sm text-gray-700">Encrypted</span>
            </label>
          </div>

          {/* Save Edge Configuration Button */}
          <div className="border-t pt-4 space-y-3">
            <Button
              onClick={handleSaveEdgeConfiguration}
              disabled={!edgeHasUnsavedChanges}
              className={`w-full px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                edgeHasUnsavedChanges 
                  ? 'bg-blue-600 hover:bg-blue-700 text-white' 
                  : 'bg-gray-100 text-gray-400 cursor-not-allowed'
              }`}
            >
              💾 Save Connection
            </Button>
            
            {edgeHasUnsavedChanges && (
              <div className="text-xs text-amber-600 bg-amber-50 p-2 rounded border border-amber-200">
                ⚠️ You have unsaved changes. Click "Save Connection" to apply them.
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  return null;
};

/**
 * Architecture Selection Modal
 */
interface ArchitectureModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectArchitecture: (architectureId: string) => void;
  onReturnToCurrent: () => void;
  architectures: Array<{ id: string; metadata: ArchitectureMetadata }>;
  hasCurrentWork: boolean;
}

const ArchitectureModal: React.FC<ArchitectureModalProps> = ({
  isOpen,
  onClose,
  onSelectArchitecture,
  onReturnToCurrent,
  architectures,
  hasCurrentWork
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-gray-900 border border-gray-700 rounded-lg shadow-2xl w-full max-w-2xl mx-4 max-h-[80vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-700">
          <h2 className="text-xl font-bold text-white">Load Architecture</h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            ✕
          </button>
        </div>

        {/* Content */}
        <div className="p-6 max-h-96 overflow-y-auto">
          {/* Current Work Option */}
          {hasCurrentWork && (
            <div className="mb-6">
              <h3 className="text-lg font-semibold text-white mb-3">Current Session</h3>
              <button
                onClick={onReturnToCurrent}
                className="w-full p-4 bg-blue-600 hover:bg-blue-700 rounded-lg border border-blue-500 transition-all duration-200 text-left group"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-white font-medium">Current Canvas Work</div>
                    <div className="text-blue-200 text-sm">Return to your current unsaved work</div>
                  </div>
                  <div className="text-blue-200 group-hover:text-white">
                    🔄
                  </div>
                </div>
              </button>
            </div>
          )}

          {/* Saved Architectures */}
          <div>
            <h3 className="text-lg font-semibold text-white mb-3">
              Saved Architectures ({architectures.length})
            </h3>
            
            {architectures.length === 0 ? (
              <div className="text-center py-8 text-gray-400">
                <div className="text-4xl mb-2">📁</div>
                <div>No saved architectures found</div>
                <div className="text-sm mt-1">Create and save an architecture to see it here</div>
              </div>
            ) : (
              <div className="space-y-3">
                {architectures.map((arch) => (
                  <button
                    key={arch.id}
                    onClick={() => onSelectArchitecture(arch.id)}
                    className="w-full p-4 bg-gray-800 hover:bg-gray-700 rounded-lg border border-gray-600 hover:border-gray-500 transition-all duration-200 text-left group"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="text-white font-medium mb-1">
                          {arch.metadata.company_name}
                        </div>
                        <div className="text-gray-300 text-sm mb-2">
                          {arch.metadata.architecture_type}
                        </div>
                        <div className="flex items-center gap-4 text-xs text-gray-400">
                          <span>Created: {new Date(arch.metadata.created_at).toLocaleDateString()}</span>
                          <span className="flex items-center gap-1">
                            <div className={`w-2 h-2 rounded-full ${
                              arch.metadata.security_level === 'high' ? 'bg-red-400' :
                              arch.metadata.security_level === 'medium' ? 'bg-yellow-400' : 'bg-green-400'
                            }`} />
                            {arch.metadata.security_level}
                          </span>
                        </div>
                      </div>
                      <div className="text-gray-400 group-hover:text-white ml-4">
                        📊
                      </div>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="p-6 border-t border-gray-700 bg-gray-800/50">
          <button
            onClick={onClose}
            className="w-full px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
};
export default function ArchitectureBuilder() {
  const [nodes, setNodes] = useState<Node<CustomNodeData>[]>([]);
  const [edges, setEdges] = useState<Edge<CustomEdgeData>[]>([]);
  const [selectedNode, setSelectedNode] = useState<Node<CustomNodeData> | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<Edge<CustomEdgeData> | null>(null);
  const [architectureName, setArchitectureName] = useState('New Architecture');
  
  // Modal state for architecture selection
  const [isLoadModalOpen, setIsLoadModalOpen] = useState(false);
  
  // Attack simulation modal state
  const [isAttackModalOpen, setIsAttackModalOpen] = useState(false);
  const [isComparisonViewOpen, setIsComparisonViewOpen] = useState(false);
  const [isAttackLoading, setIsAttackLoading] = useState(false);
  const [attackLoadingMessage, setAttackLoadingMessage] = useState('');
  const [suggestedArchitecture, setSuggestedArchitecture] = useState<SuggestedArchitecture | null>(null);
  const [originalArchitecture, setOriginalArchitecture] = useState<{nodes: Node<CustomNodeData>[], edges: Edge<CustomEdgeData>[]} | null>(null);
  
  // Healing modal state
  const [isHealingModalOpen, setIsHealingModalOpen] = useState(false);
  const [isHealingComparisonOpen, setIsHealingComparisonOpen] = useState(false);
  const [healingResult, setHealingResult] = useState<HealingResult | null>(null);
  
  // AI Suggestion modal state
  const [isAISuggestionModalOpen, setIsAISuggestionModalOpen] = useState(false);
  
  // Template Gallery modal state
  const [isTemplateGalleryOpen, setIsTemplateGalleryOpen] = useState(false);
  const [loadedTemplateName, setLoadedTemplateName] = useState<string | null>(null);
  const [showTemplateBadge, setShowTemplateBadge] = useState(false);
  
  // Versioning modal state
  const [isVersioningModalOpen, setIsVersioningModalOpen] = useState(false);
  
  // Security Dashboard state
  const [isSecurityDashboardOpen, setIsSecurityDashboardOpen] = useState(false);
  
  // Virtual Sandbox modal state
  const [isVirtualSandboxOpen, setIsVirtualSandboxOpen] = useState(false);
  
  // Case Study Analysis modal state
  const [isCaseStudyAnalysisOpen, setIsCaseStudyAnalysisOpen] = useState(false);
  
  // Enhanced Connection Modal state
  const [isEnhancedConnectionModalOpen, setIsEnhancedConnectionModalOpen] = useState(false);
  const [selectedConnectionEdge, setSelectedConnectionEdge] = useState<Edge<CustomEdgeData> | null>(null);
  
  // Track current work vs loaded architecture
  const [currentWork, setCurrentWork] = useState<{nodes: Node<CustomNodeData>[], edges: Edge<CustomEdgeData>[]} | null>(null);
  const [isShowingLoadedArchitecture, setIsShowingLoadedArchitecture] = useState(false);
  
  // Saved architectures list (client-only)
  const [savedArchitectures, setSavedArchitectures] = useState<Array<{ id: string; metadata: ArchitectureMetadata }>>([]);
  
  // Client-side hydration state
  const [isClient, setIsClient] = useState(false);
  
  React.useEffect(() => {
    setIsClient(true);
  }, []);
  
  const storage = useArchitectureStorage();

  // Handle architecture changes from canvas
  const handleArchitectureChange = useCallback((
    newNodes: Node<CustomNodeData>[], 
    newEdges: Edge<CustomEdgeData>[]
  ) => {
    setNodes(newNodes);
    setEdges(newEdges);
    
    // If we're showing a loaded architecture and user makes changes, save current work
    if (isShowingLoadedArchitecture && (newNodes.length > 0 || newEdges.length > 0)) {
      setCurrentWork({ nodes: newNodes, edges: newEdges });
      setIsShowingLoadedArchitecture(false);
    }
  }, [isShowingLoadedArchitecture]);

  // Handle node updates
  const handleNodeUpdate = useCallback((nodeId: string, data: Partial<CustomNodeData>) => {
    setNodes(prevNodes => 
      prevNodes.map(node => 
        node.id === nodeId 
          ? { ...node, data: { ...node.data, ...data } }
          : node
      )
    );
  }, []);

  // Handle edge updates
  const handleEdgeUpdate = useCallback((edgeId: string, newData: Partial<CustomEdgeData>) => {
    setEdges(prevEdges => 
      prevEdges.map(edge => 
        edge.id === edgeId 
          ? { ...edge, data: { ...edge.data, ...newData } as CustomEdgeData }
          : edge
      )
    );
  }, []);

  // Refs for updating nodes/edges from properties panel
  const updateNodeRef = React.useRef<((nodeId: string, data: Partial<CustomNodeData>) => void) | null>(null);
  const updateEdgeRef = React.useRef<((edgeId: string, data: Partial<CustomEdgeData>) => void) | null>(null);

  // Handle property updates from properties panel
  const handlePropertyUpdate = useCallback((id: string, updates: Record<string, any>) => {
    if (selectedNode && selectedNode.id === id && updateNodeRef.current) {
      updateNodeRef.current(id, updates);
    }
    if (selectedEdge && selectedEdge.id === id && updateEdgeRef.current) {
      updateEdgeRef.current(id, updates);
    }
  }, [selectedNode, selectedEdge]);

  // Save architecture
  const handleSave = useCallback(async() => {
    try {


      const architecture = await storage.convertFlowToArchitecture(
        nodes as any, 
        edges as any, 
        { company_name: architectureName }
      );
 
      

      const id = storage.save(architecture);

      alert(`Architecture saved successfully! ID: ${id}`);
    } catch (error) {
      alert('Failed to save architecture: ' + (error as Error).message);
    }
  }, [nodes, edges, architectureName, storage]);

  // Export architecture
  const handleExport = useCallback(() => {
    try {
      const architecture = storage.convertFlowToArchitecture(
        nodes as any, 
        edges as any, 
        { company_name: architectureName }
      );
      storage.exportToFile(architecture);
    } catch (error) {
      alert('Failed to export architecture: ' + (error as Error).message);
    }
  }, [nodes, edges, architectureName, storage]);

  // Load architecture - Open modal for selection
  const handleLoad = useCallback(() => {
    // Save current work before opening modal
    if (nodes.length > 0 || edges.length > 0) {
      setCurrentWork({ nodes, edges });
    }
    // Refresh saved list on open (client-only)
    if (typeof window !== 'undefined') {
      setSavedArchitectures(storage.list());
    }
    setIsLoadModalOpen(true);
  }, [nodes, edges]);

  // Handle architecture selection from modal - improved with proper state management
  const handleSelectArchitecture = useCallback((architectureId: string) => {
    console.log('🎯 Loading architecture with ID:', architectureId);
    const architecture = storage.load(architectureId);
    
    if (architecture) {
      console.log('✅ Architecture loaded:', architecture);
      const { nodes: loadedNodes, edges: loadedEdges } = storage.convertArchitectureToFlow(architecture);
      console.log('🔄 Converted to flow - nodes:', loadedNodes.length, 'edges:', loadedEdges.length);
      
      // Set state with proper batching
      setArchitectureName(architecture.metadata.company_name);
      setIsShowingLoadedArchitecture(true);
      
      // Update nodes and edges - this will trigger the FlowCanvas to update
      setNodes(loadedNodes);
      setEdges(loadedEdges);
      
      // Close modal after state updates
      setIsLoadModalOpen(false);
      
      console.log('✅ State updated successfully');
      
      // Refresh saved list in case metadata changed
      if (typeof window !== 'undefined') {
        setSavedArchitectures(storage.list());
      }
    } else {
      console.error('❌ Failed to load architecture with ID:', architectureId);
      alert('Failed to load architecture');
    }
  }, [storage]);

  // Return to current work
  const handleReturnToCurrent = useCallback(() => {
    if (currentWork) {
      setNodes(currentWork.nodes);
      setEdges(currentWork.edges);
      setArchitectureName('New Architecture');
      setIsShowingLoadedArchitecture(false);
      setIsLoadModalOpen(false);
    }
  }, [currentWork]);

  // Handle attack simulation
  const handleRunAttack = useCallback(async (attack: ConfiguredAttack) => {
    console.log('🎯 Running attack simulation:', attack.attack_id);
    
    // Start loading state
    setIsAttackLoading(true);
    setAttackLoadingMessage('Configuring attack simulation...');
    
    // Save attack to storage
    attackStorage.saveCurrentAttack(attack);
    
    // Close modal
    setIsAttackModalOpen(false);
    
    try {
      setAttackLoadingMessage('Converting architecture format...');
      
      // Convert React Flow format to Architecture format
      const currentArchitecture: Architecture = {
        metadata: {
          company_name: architectureName,
          architecture_type: 'custom',
          created_at: new Date().toISOString(),
          security_level: 'medium',
        },
        nodes: nodes.map(node => ({
          id: node.id,
          type: node.data.type,
          name: node.data.name || node.id,
          properties: node.data.properties || {},
          position: {
            x: node.position.x,
            y: node.position.y,
          },
        })),
        connections: edges.map(edge => ({
          id: edge.id,
          source: edge.source,
          target: edge.target,
          type: edge.data?.type || 'network',
          properties: edge.data?.properties || {},
        })),
        network_zones: [],
      };
      
      // Step 1: Validate if attack is possible
      setAttackLoadingMessage('Validating attack feasibility...');
      console.log('📋 Step 1: Validating attack...');
      const validationResult = await agentService.validateAttack(
        attack,
        currentArchitecture
      );
      
      console.log('✅ Validation result:', validationResult);
      
      if (!validationResult.is_valid) {
        setIsAttackLoading(false);
        const reason = validationResult.missing_components?.join(', ') || 'Attack is not possible on current architecture';
        alert(`Attack validation completed!\n\n${reason}\n\nNo architecture changes needed.`);
        return;
      }
      
      // Step 2: Get corrected architecture
      setAttackLoadingMessage('Generating security improvements...');
      console.log('🔧 Step 2: Getting corrected architecture...');
      const correctedArchitecture = await agentService.getCorrectedArchitecture(
        attack,
        currentArchitecture
      );
      
      console.log('✅ Corrected architecture received:', correctedArchitecture);
      
      // Step 3: Show comparison view
      setAttackLoadingMessage('Preparing comparison view...');
      setOriginalArchitecture({ nodes, edges });
      setSuggestedArchitecture(correctedArchitecture);
      
      // End loading and show comparison
      setIsAttackLoading(false);
      setIsComparisonViewOpen(true);
      
    } catch (error) {
      console.error('❌ Error during attack simulation:', error);
      setIsAttackLoading(false);
      alert(`Error during attack simulation: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }, [nodes, edges, architectureName]);
  
  // Accept suggested architecture
  const handleAcceptSuggestion = useCallback(() => {
    if (suggestedArchitecture) {
      // Helper function to get component icon
      const getComponentIcon = (type: string): string => {
        const icons: Record<string, string> = {
          waf: '🛡️', firewall: '🔥', ids_ips: '🚨', vpn_gateway: '🔐',
          load_balancer: '⚖️', web_server: '🌐', database: '🗄️', siem: '🔍',
          user_device: '💻', application_server: '💼', api_gateway: '🚪',
          cache_server: '📦', file_storage: '📁', backup_server: '💿'
        };
        return icons[type] || '🔧';
      };

      // Convert suggested architecture to React Flow format with proper node data
      const newNodes: Node<CustomNodeData>[] = suggestedArchitecture.new_architecture.components.map((comp: any, index) => ({
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
      }));
      
      const newEdges: Edge<CustomEdgeData>[] = suggestedArchitecture.new_architecture.connections.map((conn: any, index) => ({
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
      
      setNodes(newNodes);
      setEdges(newEdges);
      setIsComparisonViewOpen(false);
      
      alert('✅ Architecture updated successfully with security improvements!');
    }
  }, [suggestedArchitecture]);
  
  // Reject suggested architecture
  const handleRejectSuggestion = useCallback(() => {
    setIsComparisonViewOpen(false);
    setSuggestedArchitecture(null);
    setOriginalArchitecture(null);
  }, []);
  
  // Load architecture version
  const handleLoadVersion = useCallback((version: any) => {
    setNodes(version.nodes);
    setEdges(version.edges);
    setArchitectureName(version.name);
    setIsVersioningModalOpen(false);
    alert(`✅ Loaded version: ${version.name}`);
  }, []);
  
  // Handle AI-generated architecture
  const handleAIArchitectureGenerated = useCallback((architecture: any) => {
    console.log('AI Generated Architecture:', architecture);
    
    // Convert AI architecture to React Flow format
    const newNodes: Node<CustomNodeData>[] = architecture.nodes.map((node: any) => {
      const componentType = node.properties?.component_type || node.type || 'server';
      const componentConfig = getComponentByType(componentType);
      
      return {
        id: node.id,
        type: 'custom',
        position: node.position || { x: Math.random() * 500, y: Math.random() * 400 },
        data: {
          id: node.id,
          type: 'custom',
          component_type: componentType,
          name: node.name,
          icon: componentConfig?.icon || '📦',
          description: node.properties?.description || componentConfig?.description || '',
          properties: node.properties || {},
          category: node.properties?.tier || 'infrastructure',
          configured: true
        } as CustomNodeData
      };
    });
    
    const newEdges: Edge<CustomEdgeData>[] = architecture.connections.map((conn: any) => ({
      id: conn.id,
      source: conn.source,
      target: conn.target,
      type: 'custom',
      data: {
        id: conn.id,
        type: conn.type || 'connection',
        properties: conn.properties || {},
        protocol: conn.properties?.protocol || 'TCP',
        encrypted: conn.properties?.encrypted || false
      } as CustomEdgeData
    }));
    
    // Update canvas
    setNodes(newNodes);
    setEdges(newEdges);
    
    // Update architecture name
    setArchitectureName(architecture.metadata?.company_name || 'AI Generated Architecture');
    
    // Auto-save after generation
    setTimeout(() => {
      handleSave();
    }, 500);
    
    alert(`✅ Generated ${newNodes.length} components and ${newEdges.length} connections!`);
  }, [handleSave]);
  
  // Handle template selection
  const handleTemplateSelect = useCallback((template: ArchitectureTemplate) => {
    console.log('Template Selected:', template);
    
    // Convert template to React Flow format
    const newNodes: Node<CustomNodeData>[] = template.nodes.map((node) => {
      const componentConfig = getComponentByType(node.component_type);
      
      return {
        id: node.id,
        type: 'custom',
        position: node.position,
        data: {
          id: node.id,
          type: 'custom',
          component_type: node.component_type,
          name: node.name,
          icon: componentConfig?.icon || '📦',
          description: componentConfig?.description || '',
          properties: node.properties || {},
          category: node.tier || 'infrastructure',
          configured: true
        } as CustomNodeData
      };
    });
    
    const newEdges: Edge<CustomEdgeData>[] = template.connections.map((conn) => ({
      id: conn.id,
      source: conn.source,
      target: conn.target,
      type: 'custom',
      data: {
        id: conn.id,
        type: 'connection',
        properties: {},
        protocol: conn.protocol || 'TCP',
        encrypted: conn.encrypted || false
      } as CustomEdgeData
    }));
    
    // Update canvas
    setNodes(newNodes);
    setEdges(newEdges);
    
    // Update architecture name with template name
    setArchitectureName(template.name);
    
    // Show template badge with animation
    setLoadedTemplateName(template.name);
    setShowTemplateBadge(true);
    
    // Auto-hide badge after 5 seconds
    setTimeout(() => {
      setShowTemplateBadge(false);
    }, 5000);
    
    // Close modal
    setIsTemplateGalleryOpen(false);
    
    // Auto-save after loading template
    setTimeout(() => {
      handleSave();
    }, 500);
    
    alert(`✅ Loaded ${template.name} template with ${newNodes.length} components!`);
  }, [handleSave]);


  // Clear canvas
  const handleClear = useCallback(() => {
    if (confirm('Are you sure you want to clear the canvas? This action cannot be undone.')) {
      setNodes([]);
      setEdges([]);
      setSelectedNode(null);
      setSelectedEdge(null);
    }
  }, []);

  // Custom edge selection handler to open Enhanced Connection Modal
  const handleEdgeSelect = useCallback((edge: Edge<CustomEdgeData> | null) => {
    if (edge) {
      setSelectedConnectionEdge(edge);
      setIsEnhancedConnectionModalOpen(true);
    }
    setSelectedEdge(edge);
  }, []);

  // Handle Enhanced Connection Configuration Save
  const handleEnhancedConnectionSave = useCallback((config: any) => {
    if (selectedConnectionEdge) {
      // Update the edge with enhanced configuration
      setEdges(edges => 
        edges.map(edge => 
          edge.id === selectedConnectionEdge.id 
            ? { ...edge, data: { ...edge.data, enhanced_config: config } }
            : edge
        )
      );
      
      // Mark as configured
      console.log('Enhanced Connection Configuration Saved:', config);
    }
  }, [selectedConnectionEdge]);

  return (
    <div className="h-screen flex flex-col" style={{
      background: 'linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%)'
    }}>
      {/* Toolbar */}
      <Toolbar
        onSave={handleSave}
        onLoad={handleLoad}
        onExport={handleExport}
        onClear={handleClear}
        onAttackSimulation={() => setIsAttackModalOpen(true)}
        onHeal={() => setIsHealingModalOpen(true)}
        onAISuggestion={() => setIsAISuggestionModalOpen(true)}
        onTemplates={() => setIsTemplateGalleryOpen(true)}
        onVersionHistory={() => setIsVersioningModalOpen(true)}
        onSecurityDashboard={() => setIsSecurityDashboardOpen(true)}
        onVirtualSandbox={() => setIsVirtualSandboxOpen(true)}
        onCaseStudyAnalysis={() => setIsCaseStudyAnalysisOpen(true)}
        hasNodes={nodes.length > 0}
        architectureName={architectureName}
        onArchitectureNameChange={setArchitectureName}
      />

      {/* Main content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar */}
        <ComponentSidebar />

        {/* Canvas */}
        <div className="flex-1 relative">
          <FlowCanvasWrapper
            className="absolute inset-0"
            nodes={nodes}
            edges={edges}
            onNodeSelect={setSelectedNode}
            onEdgeSelect={handleEdgeSelect}
            onArchitectureChange={handleArchitectureChange}
            updateNodeRef={updateNodeRef}
            updateEdgeRef={updateEdgeRef}
          />
          
          {/* Template Loaded Badge - Floating overlay */}
          {showTemplateBadge && loadedTemplateName && (
            <div 
              className="absolute top-8 left-1/2 transform -translate-x-1/2 z-50 pointer-events-none animate-in fade-in slide-in-from-top-4 duration-500"
            >
              <div className="relative group">
                <div className="absolute inset-0 bg-gradient-to-r from-cyan-500 via-blue-500 to-purple-500 rounded-lg blur opacity-75"></div>
                <div className="relative px-8 py-4 bg-gray-900 rounded-lg border-2 border-cyan-500 shadow-2xl">
                  <div className="flex items-center gap-3">
                    <span className="text-4xl">📐</span>
                    <div>
                      <div className="text-xs text-cyan-400 font-semibold tracking-wider uppercase">Template Loaded</div>
                      <div className="text-lg font-bold text-white">{loadedTemplateName}</div>
                    </div>
                  </div>
                  <button
                    onClick={() => setShowTemplateBadge(false)}
                    className="absolute -top-2 -right-2 w-6 h-6 bg-red-500 hover:bg-red-600 text-white rounded-full flex items-center justify-center text-xs font-bold shadow-lg pointer-events-auto transition-transform hover:scale-110"
                  >
                    ✕
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Properties panel */}
        <PropertiesPanel
          selectedNode={selectedNode}
          selectedEdge={selectedEdge}
          onPropertyUpdate={handlePropertyUpdate}
        />
      </div>

      {/* Architecture Selection Modal - Client only */}
      {isClient && (
        <ArchitectureModal
          isOpen={isLoadModalOpen}
          onClose={() => setIsLoadModalOpen(false)}
          onSelectArchitecture={handleSelectArchitecture}
          onReturnToCurrent={handleReturnToCurrent}
          architectures={savedArchitectures}
          hasCurrentWork={currentWork !== null}
        />
      )}

      {/* Attack Simulation Modal - Client only */}
      {isClient && (
        <AttackSimulationModal
          isOpen={isAttackModalOpen}
          onClose={() => setIsAttackModalOpen(false)}
          nodes={nodes}
          onRunAttack={handleRunAttack}
        />
      )}

      {/* Attack Loading Modal */}
      {isAttackLoading && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center">
          <div className="bg-gray-900 border border-gray-700 rounded-xl p-8 max-w-md mx-4 text-center">
            <div className="text-6xl mb-4 animate-bounce">⚡</div>
            <h3 className="text-xl font-bold text-white mb-2">Running Attack Simulation</h3>
            <p className="text-gray-400 mb-6">{attackLoadingMessage}</p>
            <div className="flex justify-center">
              <div className="w-8 h-8 border-4 border-red-500 border-t-transparent rounded-full animate-spin"></div>
            </div>
          </div>
        </div>
      )}
      
      {/* Comparison View - Client only */}
      {isClient && originalArchitecture && suggestedArchitecture && (
        <ComparisonView
          isOpen={isComparisonViewOpen}
          onClose={() => setIsComparisonViewOpen(false)}
          originalNodes={originalArchitecture.nodes}
          originalEdges={originalArchitecture.edges}
          suggestedArchitecture={suggestedArchitecture}
          onAccept={handleAcceptSuggestion}
          onReject={handleRejectSuggestion}
        />
      )}
      
      {/* Architecture Versioning - Client only */}
      {isClient && (
        <ArchitectureVersioning
          isOpen={isVersioningModalOpen}
          onClose={() => setIsVersioningModalOpen(false)}
          currentNodes={nodes}
          currentEdges={edges}
          onLoadVersion={handleLoadVersion}
        />
      )}

      {/* Healing Modal - Client only */}
      {isClient && (
        <HealingModal
          isOpen={isHealingModalOpen}
          onClose={() => setIsHealingModalOpen(false)}
          architecture={{ nodes, edges }}
          onHealingComplete={(result) => {
            setHealingResult(result);
            setIsHealingModalOpen(false);
            setIsHealingComparisonOpen(true);
          }}
        />
      )}

      {/* AI Suggestion Modal - Client only */}
      {isClient && (
        <AISuggestionModal
          isOpen={isAISuggestionModalOpen}
          onClose={() => setIsAISuggestionModalOpen(false)}
          onArchitectureGenerated={handleAIArchitectureGenerated}
        />
      )}
      
      {/* Template Gallery Modal - Client only */}
      {isClient && (
        <TemplateGalleryModal
          isOpen={isTemplateGalleryOpen}
          onClose={() => setIsTemplateGalleryOpen(false)}
          onTemplateSelect={handleTemplateSelect}
        />
      )}

      {/* Healing Comparison View - Client only */}
      {isClient && isHealingComparisonOpen && healingResult && (
        <HealingComparisonView
          healingResult={healingResult}
          originalArchitecture={{ nodes, edges }}
          onAccept={() => {
            // Convert healed architecture to nodes/edges format
            const getComponentIcon = (type: string): string => {
              const icons: Record<string, string> = {
                waf: '🛡️', firewall: '🔥', ids_ips: '🚨', vpn_gateway: '🔐',
                load_balancer: '⚖️', web_server: '🌐', database: '🗄️', siem: '🔍',
                user_device: '💻', application_server: '💼', api_gateway: '🚪'
              };
              return icons[type] || '📦';
            };

            const healedNodes: Node<CustomNodeData>[] = healingResult.healed_architecture.nodes.map((node: any, idx: number) => ({
              id: node.id,
              type: 'custom',
              position: node.position || { x: (idx % 3) * 200 + 100, y: Math.floor(idx / 3) * 150 + 100 },
              data: {
                id: node.id,
                type: node.component_type,
                component_type: node.component_type,
                name: node.name || node.component_type,
                icon: getComponentIcon(node.component_type),
                category: node.category || 'security',
                description: `Secured ${node.component_type}`,
                properties: node.properties || {}
              }
            }));

            const healedEdges: Edge<CustomEdgeData>[] = healingResult.healed_architecture.connections.map((conn: any) => ({
              id: conn.id,
              source: conn.source,
              target: conn.target,
              type: conn.type || 'default',
              data: {
                id: conn.id,
                type: conn.type || 'default'
              }
            }));

            setNodes(healedNodes);
            setEdges(healedEdges);
            setIsHealingComparisonOpen(false);
            
            // Save as new version
            handleSave();
          }}
          onReject={() => {
            setIsHealingComparisonOpen(false);
            setHealingResult(null);
          }}
          onClose={() => {
            setIsHealingComparisonOpen(false);
          }}
        />
      )}

      {/* Security Dashboard */}
      {isSecurityDashboardOpen && (
        <SecurityDashboard
          architecture={{
            metadata: {
              company_name: architectureName,
              architecture_type: 'cloud',
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
              security_level: 'medium',
              description: 'Current architecture analysis'
            },
            nodes: nodes.map(node => ({
              id: node.id,
              type: node.data.component_type || node.data.type,
              category: node.data.category || 'general',
              name: node.data.name,
              properties: node.data.properties || {},
              position: node.position
            })),
            connections: edges.map(edge => ({
              id: edge.id,
              source: edge.source,
              target: edge.target,
              type: edge.type || 'default',
              properties: edge.data?.properties || {}
            })),
            network_zones: []
          }}
          isOpen={isSecurityDashboardOpen}
          onClose={() => setIsSecurityDashboardOpen(false)}
        />
      )}

      {/* Virtual Cybersecurity Sandbox Modal */}
      <VirtualSandboxModal
        isOpen={isVirtualSandboxOpen}
        onClose={() => setIsVirtualSandboxOpen(false)}
        architecture={{
          metadata: {
            company_name: architectureName || 'Current Architecture',
            architecture_type: 'web_application',
            security_level: 'medium',
            description: 'Current architecture for sandbox testing'
          },
          nodes: nodes.map(node => ({
            id: node.id,
            type: node.data.component_type || node.data.type,
            category: node.data.category || 'general',
            name: node.data.name,
            properties: node.data.properties || {},
            position: node.position
          })),
          connections: edges.map(edge => ({
            id: edge.id,
            source: edge.source,
            target: edge.target,
            type: edge.type || 'default',
            properties: edge.data?.properties || {}
          })),
          network_zones: []
        }}
      />

      {/* Case Study Analysis Modal */}
      <CaseStudyAnalysisModal
        isOpen={isCaseStudyAnalysisOpen}
        onClose={() => setIsCaseStudyAnalysisOpen(false)}
        nodes={nodes}
        edges={edges}
        architectureName={architectureName}
      />

      {/* Enhanced Connection Configuration Modal */}
      <EnhancedConnectionModal
        isOpen={isEnhancedConnectionModalOpen}
        onClose={() => {
          setIsEnhancedConnectionModalOpen(false);
          setSelectedConnectionEdge(null);
        }}
        onSave={handleEnhancedConnectionSave}
        connection={selectedConnectionEdge}
      />

      {/* Database Test Panel - Development Only */}
      {process.env.NODE_ENV === 'development' && <DatabaseTestPanel />}
    </div>
  );
}

