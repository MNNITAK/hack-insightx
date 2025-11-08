/**
 * Custom Node Component for React Flow
 * Displays individual components with their configuration and styling
 */



'use client';

import React from 'react';
import { Handle, Position, NodeProps } from 'reactflow';
import { CustomNodeData } from '../../types';
import { getNodeStyle } from '../../utils/flowUtils';



/**
 * Custom node component that displays component information
 */

//this fucntion acceppts the data
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


  //we got the required style for the node based on category
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
    
      {/* Connection handles - Top */}
      <Handle
        type="target"
        position={Position.Top}
        id="top"
        isConnectable={isConnectable}
        className="w-5 h-5 !border-3 animate-pulse transition-all duration-300 hover:!scale-150"
        style={{ 
          left: '50%', 
          transform: 'translateX(-50%)',
          top: '-10px',
          background: `radial-gradient(circle, ${style.glowColor}, ${style.borderColor})`,
          borderColor: '#fff',
          boxShadow: `0 0 20px ${style.glowColor}, 0 0 40px ${style.glowColor}80`,
          cursor: 'crosshair',
          zIndex: 100,
          opacity: 1
        }}
      />
      
      {/* Connection handles - Left */}
      <Handle
        type="target"
        position={Position.Left}
        id="left"
        isConnectable={isConnectable}
        className="w-5 h-5 !border-3 animate-pulse transition-all duration-300 hover:!scale-150"
        style={{ 
          top: '50%', 
          transform: 'translateY(-50%)',
          left: '-10px',
          background: `radial-gradient(circle, ${style.glowColor}, ${style.borderColor})`,
          borderColor: '#fff',
          boxShadow: `0 0 20px ${style.glowColor}, 0 0 40px ${style.glowColor}80`,
          cursor: 'crosshair',
          zIndex: 100,
          opacity: 1
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
        <div className="flex items-center gap-3 mb-3">
          <div 
            className="text-2xl flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center"
            style={{
              background: `linear-gradient(135deg, ${style.glowColor}20, ${style.borderColor}10)`,
              border: `1px solid ${style.glowColor}30`
            }}
          >
            {data.icon}
          </div>
          <div className="flex-1 min-w-0">
            <div className="font-bold text-sm text-white truncate mb-0.5">
              {data.name}
            </div>
            <div className="text-xs text-gray-400 truncate">
              {data.type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
            </div>
          </div>
        </div>
        
        {/* Properties display */}
        {data.properties && Object.keys(data.properties).length > 0 && (
          <div className="space-y-1.5 mt-3">
            {Object.entries(data.properties).slice(0, 2).map(([key, value]) => (
              <div 
                key={key} 
                className="flex justify-between items-center text-xs px-2 py-1.5 rounded"
                style={{
                  background: `${style.glowColor}08`,
                  border: `1px solid ${style.glowColor}20`
                }}
              >
                <span className="text-gray-400 truncate flex-1 capitalize text-[10px]">
                  {key.replace(/[._]/g, ' ')}
                </span>
                <span className="text-white font-medium ml-2 truncate text-[10px]">
                  {typeof value === 'boolean' 
                    ? (value ? '✓' : '✗')
                    : String(value).slice(0, 10) + (String(value).length > 10 ? '...' : '')
                  }
                </span>
              </div>
            ))}
          </div>
        )}

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
      
      {/* Connection handles - Right */}
      <Handle
        type="source"
        position={Position.Right}
        id="right"
        isConnectable={isConnectable}
        className="w-5 h-5 !border-3 animate-pulse transition-all duration-300 hover:!scale-150"
        style={{ 
          top: '50%', 
          transform: 'translateY(-50%)',
          right: '-10px',
          background: `radial-gradient(circle, ${style.glowColor}, ${style.borderColor})`,
          borderColor: '#fff',
          boxShadow: `0 0 20px ${style.glowColor}, 0 0 40px ${style.glowColor}80`,
          cursor: 'crosshair',
          zIndex: 100,
          opacity: 1
        }}
      />
      
      {/* Connection handles - Bottom */}
      <Handle
        type="source"
        position={Position.Bottom}
        id="bottom"
        isConnectable={isConnectable}
        className="w-5 h-5 !border-3 animate-pulse transition-all duration-300 hover:!scale-150"
        style={{ 
          left: '50%', 
          transform: 'translateX(-50%)',
          bottom: '-10px',
          background: `radial-gradient(circle, ${style.glowColor}, ${style.borderColor})`,
          borderColor: '#fff',
          boxShadow: `0 0 20px ${style.glowColor}, 0 0 40px ${style.glowColor}80`,
          cursor: 'crosshair',
          zIndex: 100,
          opacity: 1
        }}
      />
        </div>
      </div>
    </div>
  );
};