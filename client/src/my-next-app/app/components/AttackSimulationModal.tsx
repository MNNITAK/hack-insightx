/**
 * Cyber Attack Simulation Component
 * Dark-themed modal for configuring and running attack simulations
 */

'use client';

import React, { useState, useEffect } from 'react';
import {
  AttackData,
  AttackDefinition,
  ConfiguredAttack,
  AttackParameter,
  AttackCategory,
} from '../types/attack';
import { attackStorage } from '../utils/attackStorage';
import { Node } from 'reactflow';
import { CustomNodeData } from '../types';

interface AttackSimulationModalProps {
  isOpen: boolean;
  onClose: () => void;
  nodes: Node<CustomNodeData>[]; // Available nodes for selection
  onRunAttack: (attack: ConfiguredAttack) => void;
}

export const AttackSimulationModal: React.FC<AttackSimulationModalProps> = ({
  isOpen,
  onClose,
  nodes,
  onRunAttack,
}) => {
  const [attackCatalog, setAttackCatalog] = useState<AttackData | null>(null);
  const [selectedAttack, setSelectedAttack] = useState<AttackDefinition | null>(null);
  const [attackParameters, setAttackParameters] = useState<{ [key: string]: any }>({});
  const [selectedCategory, setSelectedCategory] = useState<AttackCategory | 'all'>('all');
  const [searchQuery, setSearchQuery] = useState('');

  // Load attack catalog on mount
  useEffect(() => {
    const loadCatalog = async () => {
      const catalog = await attackStorage.loadAttackCatalog();
      setAttackCatalog(catalog);
    };
    if (isOpen) {
      loadCatalog();
    }
  }, [isOpen]);

  // Initialize parameters when attack is selected
  useEffect(() => {
    if (selectedAttack) {
      const defaultParams: { [key: string]: any } = {};
      Object.entries(selectedAttack.user_configurable_parameters).forEach(([key, param]) => {
        if ('default' in param) {
          defaultParams[key] = param.default;
        }
      });
      setAttackParameters(defaultParams);
    }
  }, [selectedAttack]);

  const handleAttackSelect = (attack: AttackDefinition) => {
    setSelectedAttack(attack);
  };

  const handleParameterChange = (paramName: string, value: any) => {
    setAttackParameters((prev) => ({
      ...prev,
      [paramName]: value,
    }));
  };

  const handleRunAttack = () => {
    if (!selectedAttack) return;

    const configuredAttack: ConfiguredAttack = {
      attack_id: selectedAttack.attack_id,
      attack_name: selectedAttack.attack_name,
      category: selectedAttack.category,
      configured_at: new Date().toISOString(),
      parameters: attackParameters,
    };

    // Save to localStorage
    attackStorage.saveCurrentAttack(configuredAttack);

    // Trigger attack validation
    onRunAttack(configuredAttack);
  };

  const filteredAttacks = attackCatalog?.attacks.filter((attack) => {
    const matchesCategory = selectedCategory === 'all' || attack.category === selectedCategory;
    const matchesSearch =
      searchQuery === '' ||
      attack.attack_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      attack.description.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl w-full max-w-7xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-700 bg-gradient-to-r from-red-900/20 to-gray-900">
          <div>
            <h2 className="text-2xl font-bold text-white flex items-center gap-3">
              <span className="text-3xl">🎯</span>
              Cyber Attack Simulation
            </h2>
            <p className="text-gray-400 text-sm mt-1">
              Configure and test security vulnerabilities against your architecture
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
        <div className="flex flex-1 overflow-hidden">
          {/* Left Panel - Attack List */}
          <div className="w-1/3 border-r border-gray-700 flex flex-col">
            {/* Filters */}
            <div className="p-4 border-b border-gray-700 space-y-3">
              <input
                type="text"
                placeholder="🔍 Search attacks..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-blue-500 focus:outline-none"
              />
              
              <select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value as AttackCategory | 'all')}
                className="w-full px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-blue-500 focus:outline-none"
              >
                <option value="all">All Categories</option>
                {attackCatalog?.attack_catalog.categories.map((cat) => (
                  <option key={cat} value={cat}>
                    {cat.replace(/_/g, ' ').toUpperCase()}
                  </option>
                ))}
              </select>
            </div>

            {/* Attack List */}
            <div className="flex-1 overflow-y-auto p-4 space-y-2">
              {filteredAttacks?.map((attack) => (
                <button
                  key={attack.attack_id}
                  onClick={() => handleAttackSelect(attack)}
                  className={`w-full p-4 rounded-lg border text-left transition-all duration-200 ${
                    selectedAttack?.attack_id === attack.attack_id
                      ? 'bg-blue-600 border-blue-500'
                      : 'bg-gray-800 border-gray-700 hover:bg-gray-700 hover:border-gray-600'
                  }`}
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="font-medium text-white">{attack.attack_name}</div>
                    <span
                      className={`px-2 py-1 rounded text-xs ${
                        attack.difficulty === 'easy'
                          ? 'bg-green-600 text-white'
                          : attack.difficulty === 'medium'
                          ? 'bg-yellow-600 text-white'
                          : 'bg-red-600 text-white'
                      }`}
                    >
                      {attack.difficulty}
                    </span>
                  </div>
                  <div className="text-sm text-gray-300 line-clamp-2">{attack.description}</div>
                  <div className="flex items-center gap-2 mt-2 text-xs text-gray-400">
                    <span className="px-2 py-1 bg-gray-700 rounded">{attack.category}</span>
                    <span>{attack.mitre_attack_id}</span>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Right Panel - Attack Configuration */}
          <div className="flex-1 flex flex-col">
            {selectedAttack ? (
              <>
                {/* Attack Details */}
                <div className="p-6 border-b border-gray-700">
                  <h3 className="text-xl font-bold text-white mb-2">{selectedAttack.attack_name}</h3>
                  <p className="text-gray-300 mb-4">{selectedAttack.description}</p>
                  
                  <div className="grid grid-cols-3 gap-4 text-sm">
                    <div className="bg-gray-800 p-3 rounded-lg">
                      <div className="text-gray-400">Category</div>
                      <div className="text-white font-medium capitalize">
                        {selectedAttack.category.replace(/_/g, ' ')}
                      </div>
                    </div>
                    <div className="bg-gray-800 p-3 rounded-lg">
                      <div className="text-gray-400">Duration</div>
                      <div className="text-white font-medium">
                        {selectedAttack.typical_duration_seconds}s
                      </div>
                    </div>
                    <div className="bg-gray-800 p-3 rounded-lg">
                      <div className="text-gray-400">Detection</div>
                      <div className="text-white font-medium capitalize">
                        {selectedAttack.detection_difficulty}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Parameters Configuration */}
                <div className="flex-1 overflow-y-auto p-6 space-y-4">
                  <h4 className="text-lg font-bold text-white mb-4">Configure Attack Parameters</h4>
                  
                  {Object.entries(selectedAttack.user_configurable_parameters).map(
                    ([paramName, param]) => (
                      <div key={paramName} className="space-y-2">
                        <label className="block text-sm font-medium text-white">
                          {param.label}
                          {param.required && <span className="text-red-400 ml-1">*</span>}
                        </label>
                        {param.description && (
                          <p className="text-xs text-gray-400">{param.description}</p>
                        )}
                        
                        <AttackParameterInput
                          parameter={param}
                          value={attackParameters[paramName]}
                          onChange={(value) => handleParameterChange(paramName, value)}
                          nodes={nodes}
                        />
                      </div>
                    )
                  )}
                </div>

                {/* Footer - Run Attack */}
                <div className="p-6 border-t border-gray-700 bg-gray-800/50">
                  <button
                    onClick={handleRunAttack}
                    className="w-full px-6 py-3 bg-red-600 hover:bg-red-700 text-white font-bold rounded-lg transition-colors flex items-center justify-center gap-2"
                  >
                    <span>⚡</span>
                    Run Attack Simulation
                  </button>
                </div>
              </>
            ) : (
              <div className="flex-1 flex items-center justify-center text-gray-400">
                <div className="text-center">
                  <div className="text-6xl mb-4">🎯</div>
                  <div className="text-xl">Select an attack to configure</div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

/**
 * Parameter Input Component
 */
interface AttackParameterInputProps {
  parameter: AttackParameter;
  value: any;
  onChange: (value: any) => void;
  nodes: Node<CustomNodeData>[];
}

const AttackParameterInput: React.FC<AttackParameterInputProps> = ({
  parameter,
  value,
  onChange,
  nodes,
}) => {
  switch (parameter.type) {
    case 'text':
      return (
        <input
          type="text"
          value={value || ''}
          onChange={(e) => onChange(e.target.value)}
          className="w-full px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-blue-500 focus:outline-none"
        />
      );

    case 'textarea':
      return (
        <textarea
          value={value || ''}
          onChange={(e) => onChange(e.target.value)}
          rows={4}
          className="w-full px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-blue-500 focus:outline-none"
        />
      );

    case 'number':
    case 'slider':
      const numParam = parameter as any;
      return (
        <div className="space-y-2">
          <input
            type="range"
            min={numParam.min}
            max={numParam.max}
            value={value || numParam.default}
            onChange={(e) => onChange(Number(e.target.value))}
            className="w-full"
          />
          <input
            type="number"
            min={numParam.min}
            max={numParam.max}
            value={value || numParam.default}
            onChange={(e) => onChange(Number(e.target.value))}
            className="w-full px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-blue-500 focus:outline-none"
          />
        </div>
      );

    case 'select':
      const selectParam = parameter as any;
      return (
        <select
          value={value || selectParam.default}
          onChange={(e) => onChange(e.target.value)}
          className="w-full px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-blue-500 focus:outline-none"
        >
          {selectParam.options.map((option: string) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      );

    case 'multiselect':
      const multiSelectParam = parameter as any;
      return (
        <select
          multiple
          value={value || multiSelectParam.default}
          onChange={(e) => {
            const selected = Array.from(e.target.selectedOptions, (option) => option.value);
            onChange(selected);
          }}
          className="w-full px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-blue-500 focus:outline-none min-h-[100px]"
        >
          {multiSelectParam.options.map((option: string) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      );


    
    case 'boolean':
      const boolParam = parameter as any;
      return (
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={value !== undefined ? value : boolParam.default}
            onChange={(e) => onChange(e.target.checked)}
            className="w-5 h-5 bg-gray-800 border-gray-700 rounded focus:ring-blue-500"
          />
          <span className="text-gray-300">Enable</span>
        </label>
      );

    case 'node_selector':
      const nodeSelectorParam = parameter as any;
      const filteredNodes = nodeSelectorParam.filter
        ? nodes.filter((n) => {
            const [filterType, filterValue] = nodeSelectorParam.filter.split(':');
            if (filterType === 'type') {
              return n.data.type === filterValue;
            }
            return true;
          })
        : nodes;

      return (
        <select
          value={value || ''}
          onChange={(e) => onChange(e.target.value)}
          multiple={nodeSelectorParam.multiple}
          className="w-full px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-blue-500 focus:outline-none"
        >
          <option value="">Select node...</option>
          {filteredNodes.map((node) => (
            <option key={node.id} value={node.id}>
              {(node.data as any).label || node.id} ({node.data.type})
            </option>
          ))}
        </select>
      );

    default:
      return null;
  }
};
