/**
 * Utility functions for React Flow operations
 * Includes node and edge creation, validation, and management
 */

import { Node, Edge } from 'reactflow';
import { CustomNode, CustomEdge, CustomNodeData, CustomEdgeData, ComponentConfiguration } from '../types';

/**
 * Generate a unique ID for nodes/edges
 */
export const generateId = (): string => {
  return `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
};

/**
 * Create a new custom node from a component configuration
 */
export const createNodeFromComponent = (
  componentConfig: ComponentConfiguration,
  position: { x: number; y: number },
  name?: string
): Node<CustomNodeData> => {
  const id = generateId();
  
  return {
    id,
    type: 'custom',
    position,
    data: {
      id,
      type: componentConfig.component_type,
      component_type: componentConfig.component_type,
      name: name || `${componentConfig.component_type}_${id.slice(-4)}`,
      icon: componentConfig.icon,
      description: componentConfig.description,
      category: componentConfig.category,
      properties: {}, // Initialize empty properties object
      configured: false
    }
  };
};

/**
 * Create a new custom edge between two nodes
 */
export const createEdge = (
  sourceId: string,
  targetId: string,
  edgeType: string = 'network'
): Edge<CustomEdgeData> => {
  const id = generateId();
  
  return {
    id,
    source: sourceId,
    target: targetId,
    type: 'smoothstep',
    data: {
      id,
      type: edgeType,
      properties: {}
    }
  };
};

/**
 * Validate node position to ensure it's within canvas bounds
 */
export const validateNodePosition = (
  position: { x: number; y: number },
  canvasSize: { width: number; height: number }
): { x: number; y: number } => {
  return {
    x: Math.max(0, Math.min(position.x, canvasSize.width - 200)),
    y: Math.max(0, Math.min(position.y, canvasSize.height - 100))
  };
};

/**
 * Get default node style based on category
 */
export const getNodeStyle = (category: string) => {
  const categoryStyles: Record<string, any> = {
    security: {
      backgroundColor: '#fee2e2',
      borderColor: '#ef4444',
      color: '#7f1d1d'
    },
    compute: {
      backgroundColor: '#dbeafe',
      borderColor: '#3b82f6',
      color: '#1e3a8a'
    },
    network: {
      backgroundColor: '#d1fae5',
      borderColor: '#10b981',
      color: '#065f46'
    },
    data: {
      backgroundColor: '#fef3c7',
      borderColor: '#f59e0b',
      color: '#78350f'
    },
    endpoints: {
      backgroundColor: '#e0e7ff',
      borderColor: '#6366f1',
      color: '#3730a3'
    },
    infrastructure: {
      backgroundColor: '#f3e8ff',
      borderColor: '#8b5cf6',
      color: '#581c87'
    },
    default: {
      backgroundColor: '#f3f4f6',
      borderColor: '#6b7280',
      color: '#374151'
    }
  };

  return categoryStyles[category] || categoryStyles.default;
};

/**
 * Calculate optimal position for a new node to avoid overlaps
 */
export const calculateOptimalPosition = (
  existingNodes: Node<CustomNodeData>[],
  basePosition: { x: number; y: number }
): { x: number; y: number } => {
  const nodeWidth = 200;
  const nodeHeight = 100;
  const padding = 20;
  
  let position = { ...basePosition };
  let attempts = 0;
  const maxAttempts = 50;
  
  while (attempts < maxAttempts) {
    const hasOverlap = existingNodes.some(node => {
      const nodeBounds = {
        left: node.position.x,
        right: node.position.x + nodeWidth,
        top: node.position.y,
        bottom: node.position.y + nodeHeight
      };
      
      const newBounds = {
        left: position.x,
        right: position.x + nodeWidth,
        top: position.y,
        bottom: position.y + nodeHeight
      };
      
      return !(
        newBounds.right + padding < nodeBounds.left ||
        newBounds.left - padding > nodeBounds.right ||
        newBounds.bottom + padding < nodeBounds.top ||
        newBounds.top - padding > nodeBounds.bottom
      );
    });
    
    if (!hasOverlap) {
      break;
    }
    
    // Try different positions
    if (attempts % 4 === 0) {
      position.x += nodeWidth + padding;
    } else if (attempts % 4 === 1) {
      position.y += nodeHeight + padding;
      position.x = basePosition.x;
    } else if (attempts % 4 === 2) {
      position.x -= nodeWidth + padding;
      if (position.x < 0) position.x = basePosition.x + (nodeWidth + padding) * 2;
    } else {
      position.y -= nodeHeight + padding;
      if (position.y < 0) position.y = basePosition.y + (nodeHeight + padding) * 2;
    }
    
    attempts++;
  }
  
  return position;
};

/**
 * Get connection points for an edge
 */
export const getConnectionPoints = (
  sourceNode: Node<CustomNodeData>,
  targetNode: Node<CustomNodeData>
) => {
  const sourceCenter = {
    x: sourceNode.position.x + 100, // Assuming node width of 200
    y: sourceNode.position.y + 50   // Assuming node height of 100
  };
  
  const targetCenter = {
    x: targetNode.position.x + 100,
    y: targetNode.position.y + 50
  };
  
  return { sourceCenter, targetCenter };
};

/**
 * Validate if two nodes can be connected
 */
export const canConnectNodes = (
  sourceNode: Node<CustomNodeData>,
  targetNode: Node<CustomNodeData>,
  existingEdges: Edge<CustomEdgeData>[]
): { canConnect: boolean; reason?: string } => {
  // Don't allow self-connections
  if (sourceNode.id === targetNode.id) {
    return { canConnect: false, reason: 'Cannot connect node to itself' };
  }
  
  // Check if connection already exists
  const connectionExists = existingEdges.some(edge => 
    (edge.source === sourceNode.id && edge.target === targetNode.id) ||
    (edge.source === targetNode.id && edge.target === sourceNode.id)
  );
  
  if (connectionExists) {
    return { canConnect: false, reason: 'Connection already exists' };
  }
  
  return { canConnect: true };
};

/**
 * Auto-layout nodes in a grid pattern
 */
export const autoLayoutNodes = (
  nodes: Node<CustomNodeData>[],
  canvasSize: { width: number; height: number }
): Node<CustomNodeData>[] => {
  const nodeWidth = 200;
  const nodeHeight = 100;
  const padding = 50;
  
  const nodesPerRow = Math.floor((canvasSize.width - padding) / (nodeWidth + padding));
  
  return nodes.map((node, index) => {
    const row = Math.floor(index / nodesPerRow);
    const col = index % nodesPerRow;
    
    return {
      ...node,
      position: {
        x: padding + col * (nodeWidth + padding),
        y: padding + row * (nodeHeight + padding)
      }
    };
  });
};