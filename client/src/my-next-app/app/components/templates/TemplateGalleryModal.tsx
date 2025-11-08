"use client";

import React, { useState } from 'react';
import { ArchitectureTemplate, allTemplates } from '../../utils/architectureTemplates';

interface TemplateGalleryModalProps {
  isOpen: boolean;
  onClose: () => void;
  onTemplateSelect: (template: ArchitectureTemplate) => void;
}

export const TemplateGalleryModal: React.FC<TemplateGalleryModalProps> = ({
  isOpen,
  onClose,
  onTemplateSelect
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedComplexity, setSelectedComplexity] = useState<string>('all');

  if (!isOpen) return null;

  const filteredTemplates = allTemplates.filter(template => {
    const matchesSearch = 
      template.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      template.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      template.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()));
    
    const matchesComplexity = 
      selectedComplexity === 'all' || template.complexity === selectedComplexity;
    
    return matchesSearch && matchesComplexity;
  });

  const getComplexityColor = (complexity: string) => {
    const colors = {
      simple: 'bg-green-100 text-green-700 border-green-300',
      medium: 'bg-yellow-100 text-yellow-700 border-yellow-300',
      complex: 'bg-red-100 text-red-700 border-red-300'
    };
    return colors[complexity as keyof typeof colors] || colors.medium;
  };

  const getComplexityBadge = (complexity: string) => {
    const badges = {
      simple: '⚡ Simple',
      medium: '⚙️ Medium',
      complex: '🔥 Complex'
    };
    return badges[complexity as keyof typeof badges] || complexity;
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-md">
      <div className="bg-gradient-to-br from-gray-900 to-gray-800 rounded-2xl shadow-2xl w-full max-w-6xl max-h-[90vh] overflow-hidden border border-cyan-500/30">
        {/* Header */}
        <div className="bg-gradient-to-r from-cyan-600 via-blue-600 to-purple-600 text-white px-8 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <span className="text-5xl">📐</span>
              <div>
                <h2 className="text-3xl font-bold">Architecture Templates</h2>
                <p className="text-cyan-100 text-sm mt-1">Pre-built architectures for common systems • Start building instantly</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="text-white hover:text-cyan-100 text-3xl font-bold transition-colors hover:rotate-90 transform duration-300"
            >
              ×
            </button>
          </div>
        </div>

        {/* Search and Filters */}
        <div className="px-8 py-6 bg-gray-800/50 border-b border-gray-700">
          <div className="flex gap-4 items-center">
            {/* Search */}
            <div className="flex-1 relative">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="🔍 Search templates by name, description, or tags..."
                className="w-full px-5 py-3 pl-12 bg-gray-700/50 border border-gray-600 rounded-xl text-white placeholder-gray-400 focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
              />
              <span className="absolute left-4 top-1/2 transform -translate-y-1/2 text-gray-400 text-xl">
                🔍
              </span>
            </div>

            {/* Complexity Filter */}
            <div className="flex gap-2">
              {['all', 'simple', 'medium', 'complex'].map((complexity) => (
                <button
                  key={complexity}
                  onClick={() => setSelectedComplexity(complexity)}
                  className={`px-4 py-2 rounded-lg font-medium text-sm transition-all ${
                    selectedComplexity === complexity
                      ? 'bg-cyan-600 text-white shadow-lg shadow-cyan-600/50'
                      : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  {complexity === 'all' ? '🌐 All' : getComplexityBadge(complexity)}
                </button>
              ))}
            </div>
          </div>

          {/* Results count */}
          <div className="mt-3 text-gray-400 text-sm">
            Found <span className="text-cyan-400 font-semibold">{filteredTemplates.length}</span> template{filteredTemplates.length !== 1 ? 's' : ''}
          </div>
        </div>

        {/* Template Grid */}
        <div className="p-8 overflow-y-auto max-h-[calc(90vh-280px)]">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredTemplates.map((template) => (
              <div
                key={template.id}
                className="group relative bg-gradient-to-br from-gray-800 to-gray-900 rounded-xl p-6 border border-gray-700 hover:border-cyan-500 transition-all duration-300 cursor-pointer hover:shadow-2xl hover:shadow-cyan-500/20 hover:-translate-y-1"
                onClick={() => onTemplateSelect(template)}
              >
                {/* Template Icon */}
                <div className="absolute -top-4 -right-4 text-6xl opacity-20 group-hover:opacity-40 transition-opacity">
                  {template.icon}
                </div>

                {/* Complexity Badge */}
                <div className="mb-4">
                  <span className={`inline-block px-3 py-1 rounded-full text-xs font-semibold border ${getComplexityColor(template.complexity)}`}>
                    {getComplexityBadge(template.complexity)}
                  </span>
                </div>

                {/* Template Info */}
                <div className="relative z-10">
                  <div className="flex items-start gap-3 mb-3">
                    <span className="text-4xl">{template.icon}</span>
                    <div className="flex-1">
                      <h3 className="text-xl font-bold text-white group-hover:text-cyan-400 transition-colors">
                        {template.name}
                      </h3>
                      <p className="text-gray-400 text-xs mt-1">{template.category}</p>
                    </div>
                  </div>

                  <p className="text-gray-300 text-sm mb-4 line-clamp-3">
                    {template.description}
                  </p>

                  {/* Stats */}
                  <div className="grid grid-cols-2 gap-2 mb-4">
                    <div className="bg-gray-700/50 rounded-lg p-2 text-center">
                      <div className="text-cyan-400 font-bold text-lg">{template.nodes.length}</div>
                      <div className="text-gray-400 text-xs">Components</div>
                    </div>
                    <div className="bg-gray-700/50 rounded-lg p-2 text-center">
                      <div className="text-purple-400 font-bold text-lg">{template.connections.length}</div>
                      <div className="text-gray-400 text-xs">Connections</div>
                    </div>
                  </div>

                  {/* Tags */}
                  <div className="flex flex-wrap gap-2 mb-4">
                    {template.tags.slice(0, 3).map((tag, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-1 bg-gray-700/70 text-gray-300 text-xs rounded-md"
                      >
                        #{tag}
                      </span>
                    ))}
                  </div>

                  {/* Cost */}
                  <div className="flex items-center justify-between pt-4 border-t border-gray-700">
                    <span className="text-gray-400 text-xs">Est. Cost</span>
                    <span className="text-green-400 font-semibold text-sm">{template.estimatedCost}</span>
                  </div>

                  {/* Hover overlay */}
                  <div className="absolute inset-0 bg-gradient-to-t from-cyan-600/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity rounded-xl pointer-events-none"></div>

                  {/* Select button (appears on hover) */}
                  <div className="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity">
                    <button className="px-6 py-3 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded-lg shadow-lg transform hover:scale-105 transition-all">
                      ✨ Use Template
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* No results */}
          {filteredTemplates.length === 0 && (
            <div className="text-center py-16">
              <div className="text-6xl mb-4">🔍</div>
              <h3 className="text-2xl font-bold text-gray-400 mb-2">No templates found</h3>
              <p className="text-gray-500">Try adjusting your search or filters</p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="bg-gray-800/80 px-8 py-4 border-t border-gray-700 flex items-center justify-between">
          <div className="text-gray-400 text-sm">
            💡 <span className="text-gray-300">Tip:</span> Templates are fully customizable after loading
          </div>
          <button
            onClick={onClose}
            className="px-6 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
