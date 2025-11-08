"use client";

import React, { useState } from 'react';

interface AISuggestionModalProps {
  isOpen: boolean;
  onClose: () => void;
  onArchitectureGenerated: (architecture: any) => void;
}

export const AISuggestionModal: React.FC<AISuggestionModalProps> = ({
  isOpen,
  onClose,
  onArchitectureGenerated
}) => {
  const [prompt, setPrompt] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleGenerate = async () => {
    if (!prompt.trim()) {
      setError('Please enter a description for your architecture');
      return;
    }

    setIsGenerating(true);
    setError('');

    try {
      const response = await fetch('http://localhost:5000/api/generate-architecture', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ prompt: prompt.trim() })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to generate architecture');
      }

      const architecture = await response.json();
      console.log('Generated architecture:', architecture);
      
      onArchitectureGenerated(architecture);
      setPrompt('');
      onClose();

    } catch (err: any) {
      console.error('Generation error:', err);
      setError(err.message || 'Failed to generate architecture');
    } finally {
      setIsGenerating(false);
    }
  };

  const examplePrompts = [
    "E-commerce platform with web servers, product database, payment gateway, and user authentication",
    "Healthcare system with patient records database, secure API, HIPAA-compliant storage, and mobile access",
    "SaaS application with multi-tenant architecture, microservices, Redis cache, and monitoring",
    "Financial trading platform with real-time data feeds, high-frequency trading servers, and backup systems"
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-white rounded-lg shadow-2xl w-full max-w-3xl max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="bg-gradient-to-r from-purple-600 to-pink-600 text-white px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-3xl">🤖</span>
            <div>
              <h2 className="text-2xl font-bold">AI Architecture Suggestion</h2>
              <p className="text-purple-100 text-sm">Describe your system and let AI design it for you</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-white hover:text-purple-100 text-2xl font-bold"
            disabled={isGenerating}
          >
            ×
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto max-h-[calc(90vh-180px)]">
          {/* Instructions */}
          <div className="bg-purple-50 border border-purple-200 rounded-lg p-4 mb-6">
            <h3 className="font-semibold text-purple-900 mb-2">💡 How to use:</h3>
            <ul className="text-sm text-purple-800 space-y-1">
              <li>• Describe your company type and what it does</li>
              <li>• Mention key components (databases, APIs, servers, etc.)</li>
              <li>• Include any special requirements (security, performance, compliance)</li>
              <li>• The AI will generate a complete architecture diagram for you</li>
            </ul>
          </div>

          {/* Prompt Input */}
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Describe Your Architecture
            </label>
            <textarea
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              placeholder="Example: I need an e-commerce platform with web servers, product catalog database, Redis cache for sessions, payment gateway integration, and secure user authentication..."
              className="w-full h-40 px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent resize-none"
              disabled={isGenerating}
            />
            <div className="text-sm text-gray-500 mt-1">
              {prompt.length} / 1000 characters
            </div>
          </div>

          {/* Example Prompts */}
          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              💡 Quick Examples (click to use):
            </label>
            <div className="space-y-2">
              {examplePrompts.map((example, idx) => (
                <button
                  key={idx}
                  onClick={() => setPrompt(example)}
                  className="w-full text-left px-4 py-2 bg-gray-50 hover:bg-purple-50 border border-gray-200 hover:border-purple-300 rounded-lg text-sm transition-colors"
                  disabled={isGenerating}
                >
                  {example}
                </button>
              ))}
            </div>
          </div>

          {/* Error Display */}
          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-4">
              <div className="flex items-start gap-2">
                <span className="text-red-600 text-xl">⚠️</span>
                <div>
                  <h4 className="font-semibold text-red-900">Error</h4>
                  <p className="text-sm text-red-800">{error}</p>
                </div>
              </div>
            </div>
          )}

          {/* Generation Status */}
          {isGenerating && (
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-4">
              <div className="flex items-center gap-3">
                <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
                <div>
                  <h4 className="font-semibold text-blue-900">Generating Architecture...</h4>
                  <p className="text-sm text-blue-800">AI is analyzing your requirements and designing the system</p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="bg-gray-50 px-6 py-4 flex justify-end gap-3 border-t">
          <button
            onClick={onClose}
            className="px-6 py-2 text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 font-medium"
            disabled={isGenerating}
          >
            Cancel
          </button>
          <button
            onClick={handleGenerate}
            disabled={!prompt.trim() || isGenerating}
            className="px-6 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {isGenerating ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                Generating...
              </>
            ) : (
              <>
                <span>🤖</span>
                Generate Architecture
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
