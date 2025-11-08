/**
 * Custom Node Component for React Flow - Dark Theme
 * Displays individual components with professional dark styling
 */

'use client';

import React from 'react';
import { Handle, Position, NodeProps } from 'reactflow';
import { CustomNodeData } from '../../types';




/**
 * Custom node component with dark theme styling
 */
export const CustomNode: React.FC<NodeProps<CustomNodeData>> = ({ 
  data, 
  isConnectable, 
  selected 
}) => {
  // Dark theme styles for different categories
  const getDarkNodeStyle = (category: string) => {
    const categoryStyles: Record<string, any> = {
      security: {
        background: 'linear-gradient(135deg, #dc2626 0%, #7f1d1d 100%)',
        borderColor: '#ef4444',
        glowColor: '#ef4444'
      },
      compute: {
        background: 'linear-gradient(135deg, #2563eb 0%, #1e3a8a 100%)',
        borderColor: '#3b82f6',
        glowColor: '#3b82f6'
      },
      network: {
        background: 'linear-gradient(135deg, #059669 0%, #064e3b 100%)',
        borderColor: '#10b981',
        glowColor: '#10b981'
      },
      data: {
        background: 'linear-gradient(135deg, #d97706 0%, #92400e 100%)',
        borderColor: '#f59e0b',
        glowColor: '#f59e0b'
      },
      endpoints: {
        background: 'linear-gradient(135deg, #7c3aed 0%, #581c87 100%)',
        borderColor: '#8b5cf6',
        glowColor: '#8b5cf6'
      },
      infrastructure: {
        background: 'linear-gradient(135deg, #9333ea 0%, #581c87 100%)',
        borderColor: '#a855f7',
        glowColor: '#a855f7'
      },
      default: {
        background: 'linear-gradient(135deg, #374151 0%, #1f2937 100%)',
        borderColor: '#6b7280',
        glowColor: '#6b7280'
      }
    };
    return categoryStyles[category] || categoryStyles.default;
  };

  const style = getDarkNodeStyle(data.category);
  
  return (
    <div className="relative group">
      {/* Gradient border wrapper */}
      <div 
        className={`
          min-w-[220px] rounded-2xl p-[2px] transition-all duration-300 relative
          ${selected ? 'scale-105' : 'hover:scale-102'}
        `}
        style={{ 
          background: `linear-gradient(135deg, ${style.glowColor}, ${style.borderColor})`,
          boxShadow: selected 
            ? `0 0 30px ${style.glowColor}60, 0 10px 25px rgba(0,0,0,0.5)` 
            : `0 0 15px ${style.glowColor}30, 0 5px 15px rgba(0,0,0,0.3)`
        }}
      >
        {/* Inner dark card */}
        <div 
          className="rounded-2xl relative overflow-hidden"
          style={{
            background: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)'
          }}
        >
      {/* Connection handles - Top - Elegant & Visible */}
      <Handle
        type="target"
        position={Position.Top}
        id="top"
        isConnectable={isConnectable}
        className="!w-4 !h-4 !rounded-full transition-all duration-300 hover:!scale-125"
        style={{ 
          left: '50%', 
          transform: 'translateX(-50%)',
          top: '-8px',
          background: `linear-gradient(135deg, ${style.glowColor}, ${style.borderColor})`,
          border: '2px solid rgba(255, 255, 255, 0.9)',
          boxShadow: `0 0 15px ${style.glowColor}AA, 0 0 5px ${style.glowColor}`,
          cursor: 'crosshair',
          zIndex: 50
        }}
      />
      
      {/* Connection handles - Left - Elegant & Visible */}
      <Handle
        type="target"
        position={Position.Left}
        id="left"
        isConnectable={isConnectable}
        className="!w-4 !h-4 !rounded-full transition-all duration-300 hover:!scale-125"
        style={{ 
          top: '50%', 
          transform: 'translateY(-50%)',
          left: '-8px',
          background: `linear-gradient(135deg, ${style.glowColor}, ${style.borderColor})`,
          border: '2px solid rgba(255, 255, 255, 0.9)',
          boxShadow: `0 0 15px ${style.glowColor}AA, 0 0 5px ${style.glowColor}`,
          cursor: 'crosshair',
          zIndex: 50
        }}
      />

      {/* Cloud icon in top right */}
      <div 
        className="absolute top-3 right-3 w-8 h-8 rounded-full flex items-center justify-center opacity-30 group-hover:opacity-50 transition-opacity"
        style={{
          background: `radial-gradient(circle, ${style.glowColor}30, transparent)`,
          border: `1px solid ${style.glowColor}50`
        }}
      >
        <svg 
          className="w-5 h-5" 
          fill="currentColor" 
          viewBox="0 0 20 20"
          style={{ color: style.glowColor }}
        >
          <path d="M5.5 16a3.5 3.5 0 01-.369-6.98 4 4 0 117.753-1.977A4.5 4.5 0 1113.5 16h-8z" />
        </svg>
      </div>
      
      {/* Node content */}
      <div className="p-4 relative">
        {/* Icon and Title section */}
        <div className="flex items-center gap-3 mb-2">
          <div className="text-xl flex-shrink-0">
            {data.icon}
          </div>
          <div className="flex-1 min-w-0">
            <div className="font-semibold text-base text-white truncate">
              {data.name}
            </div>
            <div className="text-xs text-gray-500 truncate">
              {data.type.replace(/_/g, '.').toLowerCase()}
            </div>
          </div>
        </div>
        
        {/* Properties display - remove for cleaner look like reference */}
        {/* Keeping minimal info only */}

        {/* Configured status badge */}
        {data.configured && (
          <div 
            className="absolute top-2 left-2 w-2 h-2 rounded-full animate-pulse"
            style={{ 
              backgroundColor: '#22c55e',
              boxShadow: '0 0 6px #22c55e'
            }}
            title="Configured"
          />
        )}
      </div>
      
      {/* Connection handles - Right - Elegant & Visible */}
      <Handle
        type="source"
        position={Position.Right}
        id="right"
        isConnectable={isConnectable}
        className="!w-4 !h-4 !rounded-full transition-all duration-300 hover:!scale-125"
        style={{ 
          top: '50%', 
          transform: 'translateY(-50%)',
          right: '-8px',
          background: `linear-gradient(135deg, ${style.glowColor}, ${style.borderColor})`,
          border: '2px solid rgba(255, 255, 255, 0.9)',
          boxShadow: `0 0 15px ${style.glowColor}AA, 0 0 5px ${style.glowColor}`,
          cursor: 'crosshair',
          zIndex: 50
        }}
      />
      
      {/* Connection handles - Bottom - Elegant & Visible */}
      <Handle
        type="source"
        position={Position.Bottom}
        id="bottom"
        isConnectable={isConnectable}
        className="!w-4 !h-4 !rounded-full transition-all duration-300 hover:!scale-125"
        style={{ 
          left: '50%', 
          transform: 'translateX(-50%)',
          bottom: '-8px',
          background: `linear-gradient(135deg, ${style.glowColor}, ${style.borderColor})`,
          border: '2px solid rgba(255, 255, 255, 0.9)',
          boxShadow: `0 0 15px ${style.glowColor}AA, 0 0 5px ${style.glowColor}`,
          cursor: 'crosshair',
          zIndex: 50
        }}
      />
        </div>
      </div>
    </div>
  );
};