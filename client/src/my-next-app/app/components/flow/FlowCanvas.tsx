/**
 * Main React Flow Canvas Component
 * Handles the drag-and-drop functionality, node management, and connections
 */

'use client';

import React, { useCallback, useMemo, useState, useRef } from 'react';
import ReactFlow, {
  Node,
  Edge,
  addEdge,
  useNodesState,
  useEdgesState,
  Connection,
  ReactFlowProvider,
  Controls,
  Background,
  MiniMap,
  BackgroundVariant,
  SelectionMode,
  OnConnect,
  OnNodesChange,
  OnEdgesChange,
  Panel
} from 'reactflow';
import 'reactflow/dist/style.css';

import { CustomNode as CustomNodeComponent } from './CustomNode';
import { CustomNode, CustomEdge, CustomNodeData, CustomEdgeData, ComponentConfiguration } from '../../types';
import { createNodeFromComponent, createEdge, calculateOptimalPosition, canConnectNodes, generateId } from '../../utils/flowUtils';
import { useComponentRegistry } from '../../utils/componentRegistry';

interface FlowCanvasProps {
  className?: string;
  nodes?: Node<CustomNodeData>[];
  edges?: Edge<CustomEdgeData>[];
  onNodeSelect?: (node: Node<CustomNodeData> | null) => void;
  onEdgeSelect?: (edge: Edge<CustomEdgeData> | null) => void;
  onArchitectureChange?: (nodes: Node<CustomNodeData>[], edges: Edge<CustomEdgeData>[]) => void;
  updateNodeRef?: React.MutableRefObject<((nodeId: string, data: Partial<CustomNodeData>) => void) | null>;
  updateEdgeRef?: React.MutableRefObject<((edgeId: string, data: Partial<CustomEdgeData>) => void) | null>;
}




/**
 * Main Flow Canvas Component
 */
export const FlowCanvas: React.FC<FlowCanvasProps> = ({
  className = '',
  nodes: externalNodes,
  edges: externalEdges,
  onNodeSelect,
  onEdgeSelect,
  onArchitectureChange,
  updateNodeRef,
  updateEdgeRef
}) => {
  const { getComponentByType } = useComponentRegistry();
  const [nodes, setNodes, onNodesChange] = useNodesState<CustomNodeData>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<CustomEdgeData>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const canvasRef = useRef<HTMLDivElement>(null);
  const isLoadingExternal = useRef(false);

  // Sync external nodes and edges with internal state - prevent callback loops
  React.useEffect(() => {
    if (externalNodes !== undefined && externalNodes !== nodes) {
      console.log('FlowCanvas: Received external nodes:', externalNodes.length);
      isLoadingExternal.current = true;
      setNodes(externalNodes);
      // Reset flag after state settles
      requestAnimationFrame(() => {
        setTimeout(() => {
          isLoadingExternal.current = false;
        }, 50);
      });
    }
  }, [externalNodes]);

  React.useEffect(() => {
    if (externalEdges !== undefined && externalEdges !== edges) {
      console.log('FlowCanvas: Received external edges:', externalEdges.length);
      isLoadingExternal.current = true;
      setEdges(externalEdges);
      // Reset flag after state settles
      requestAnimationFrame(() => {
        setTimeout(() => {
          isLoadingExternal.current = false;
        }, 50);
      });
    }
  }, [externalEdges]);




  // Define custom node types
  const nodeTypes = useMemo(() => ({
    custom: CustomNodeComponent
  }), []);

  // Handle node connection
  const onConnect: OnConnect = useCallback((connection: Connection) => {
    console.log('✅ Connection attempt:', connection);
    
    if (!connection.source || !connection.target) {
      console.log('❌ Missing source or target');
      return;
    }

    const sourceNode = nodes.find(n => n.id === connection.source);
    const targetNode = nodes.find(n => n.id === connection.target);

    if (!sourceNode || !targetNode) {
      console.log('❌ Could not find nodes');
      return;
    }

    console.log('🔗 Creating connection between:', sourceNode.data.name, 'and', targetNode.data.name);

    // Create new edge with gradient style and flexible bezier curves
    const newEdge = {
      id: `edge-${connection.source}-${connection.target}-${Date.now()}`,
      source: connection.source,
      target: connection.target,
      sourceHandle: connection.sourceHandle,
      targetHandle: connection.targetHandle,
      type: 'default', // Use default (bezier) for flexible curves
      animated: true,
      style: {
        stroke: 'url(#edge-gradient)',
        strokeWidth: 2.5
      },
      markerEnd: {
        type: 'arrowclosed',
        color: 'url(#edge-gradient)'
      }
    };
    
    console.log('✨ Created edge:', newEdge);
    setEdges(eds => addEdge(newEdge, eds));
  }, [nodes, setEdges]);

  // Handle node selection
  const handleNodeClick = useCallback((event: React.MouseEvent, node: Node) => {
    const customNode = node as Node<CustomNodeData>;
    setSelectedNodeId(customNode.id);
    setSelectedEdgeId(null);
    onNodeSelect?.(customNode);
  }, [onNodeSelect]);

  // Handle edge selection
  const handleEdgeClick = useCallback((event: React.MouseEvent, edge: Edge) => {
    const customEdge = edge as Edge<CustomEdgeData>;
    setSelectedEdgeId(customEdge.id);
    setSelectedNodeId(null);
    onEdgeSelect?.(customEdge);
  }, [onEdgeSelect]);

  // Handle canvas click (deselect)
  const handlePaneClick = useCallback(() => {
    setSelectedNodeId(null);
    setSelectedEdgeId(null);
    onNodeSelect?.(null);
    onEdgeSelect?.(null);
  }, [onNodeSelect, onEdgeSelect]);


  // Handle drag over (required for drop)
  const handleDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault();//without this , drop woudld not working
    event.dataTransfer.dropEffect = 'move';
  }, []);

  // Handle component drop
  const handleDrop = useCallback((event: React.DragEvent) => {
    event.preventDefault();

    // Get the drop data
    const dragData = event.dataTransfer.getData('application/reactflow');
    console.log('Drop data received:', dragData);
    
    if (!dragData) {
      console.log('No drag data found');
      return;
    }

    try {
      const { componentType, componentConfig } = JSON.parse(dragData);
      console.log('Parsed component:', componentType, componentConfig);
      
      const component = getComponentByType(componentType) || componentConfig;
      if (!component) {
        console.log('Component not found:', componentType);
        return;
      }

      // Calculate drop position relative to the canvas
      const canvasRect = canvasRef.current?.getBoundingClientRect();
      if (!canvasRect) {
        console.log('Canvas rect not available');
        return;
      }

      const position = {
        x: event.clientX - canvasRect.left - 100, // Center the node
        y: event.clientY - canvasRect.top - 50
      };

      console.log('Drop position:', position);

      // Calculate optimal position to avoid overlaps
      const optimalPosition = calculateOptimalPosition(nodes, position);
      console.log('Optimal position:', optimalPosition);

      // Create new node
      const newNode = createNodeFromComponent(component, optimalPosition);
      console.log('Created new node:', newNode);

      // Add node to canvas
      setNodes(nds => [...nds, newNode]);

    } catch (error) {
      console.error('Failed to drop component:', error);
    }
  }, [nodes, setNodes, getComponentByType]);

  // Handle node deletion
  const handleDeleteNode = useCallback((nodeId: string) => {
    setNodes(nds => nds.filter(n => n.id !== nodeId));
    setEdges(eds => eds.filter(e => e.source !== nodeId && e.target !== nodeId));
    if (selectedNodeId === nodeId) {
      setSelectedNodeId(null);
      onNodeSelect?.(null);
    }
  }, [setNodes, setEdges, selectedNodeId, onNodeSelect]);

  // Handle edge deletion
  const handleDeleteEdge = useCallback((edgeId: string) => {
    setEdges(eds => eds.filter(e => e.id !== edgeId));
    if (selectedEdgeId === edgeId) {
      setSelectedEdgeId(null);
      onEdgeSelect?.(null);
    }
  }, [setEdges, selectedEdgeId, onEdgeSelect]);

 
  // const handleKeyDown = useCallback((event: KeyboardEvent) => {
  //   if (event.key === 'Delete' ) {
  //     if (selectedNodeId) {
  //       handleDeleteNode(selectedNodeId);
  //     } else if (selectedEdgeId) {
  //       handleDeleteEdge(selectedEdgeId);
  //     }
  //   }
  // }, [selectedNodeId, selectedEdgeId, handleDeleteNode, handleDeleteEdge]);

  // Add event listeners - DISABLED to prevent accidental deletion
  // React.useEffect(() => {
  //   document.addEventListener('keydown', handleKeyDown);
  //   return () => {
  //     document.removeEventListener('keydown', handleKeyDown);
  //   };
  // }, [handleKeyDown]);

  // Handle node updates from properties panel
  const handleNodeUpdate = React.useCallback((nodeId: string, data: Partial<CustomNodeData>) => {
    setNodes(prevNodes => 
      prevNodes.map(node => 
        node.id === nodeId 
          ? { ...node, data: { ...node.data, ...data } }
          : node
      )
    );
  }, []);

  const handleEdgeUpdate = React.useCallback((edgeId: string, data: Partial<CustomEdgeData>) => {
    setEdges(prevEdges => 
      prevEdges.map(edge => 
        edge.id === edgeId 
          ? { ...edge, data: { ...edge.data, ...data } as CustomEdgeData }
          : edge
      )
    );
  }, []);

  // Pass update functions to parent via refs
  React.useEffect(() => {
    if (updateNodeRef) {
      updateNodeRef.current = handleNodeUpdate;
    }
    if (updateEdgeRef) {
      updateEdgeRef.current = handleEdgeUpdate;
    }
  }, [handleNodeUpdate, handleEdgeUpdate, updateNodeRef, updateEdgeRef]);

  // Notify parent of changes (but prevent callback loops during external loads)
  React.useEffect(() => {
    // Only notify if not loading externally and callback exists
    if (!isLoadingExternal.current && onArchitectureChange && nodes.length > 0) {
      console.log('FlowCanvas: Notifying parent of changes - nodes:', nodes.length, 'edges:', edges.length);
      onArchitectureChange(nodes, edges);
    }
  }, [nodes, edges]);

  // Update node selection highlighting
  const nodesWithSelection = useMemo(() => {
    return nodes.map(node => ({
      ...node,
      selected: node.id === selectedNodeId
    }));
  }, [nodes, selectedNodeId]);

  // Update edge selection highlighting with gradient animated styling
  const edgesWithSelection = useMemo(() => {
    return edges.map(edge => ({
      ...edge,
      selected: edge.id === selectedEdgeId,
      type: 'smoothstep', // Use smoothstep for curved edges
      animated: true, // Enable animation
      style: {
        ...edge.style,
        stroke: edge.id === selectedEdgeId 
          ? 'url(#edge-gradient-selected)' 
          : 'url(#edge-gradient)',
        strokeWidth: edge.id === selectedEdgeId ? 2.5 : 2,
        opacity: 0.8
      }
    }));
  }, [edges, selectedEdgeId]);

  return (
    <div 
      ref={canvasRef}
      className={`flex-1 h-full bg-gray-900 ${className}`}
      onDrop={handleDrop}
      onDragOver={handleDragOver}
      style={{
        background: 'linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%)'
      }}
    >
      {/* SVG Gradient Definitions for Edges */}
      <svg style={{ position: 'absolute', width: 0, height: 0 }}>
        <defs>
          <linearGradient id="edge-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" style={{ stopColor: '#ec4899', stopOpacity: 1 }} />
            <stop offset="50%" style={{ stopColor: '#8b5cf6', stopOpacity: 1 }} />
            <stop offset="100%" style={{ stopColor: '#3b82f6', stopOpacity: 1 }} />
          </linearGradient>
          <linearGradient id="edge-gradient-selected" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" style={{ stopColor: '#f472b6', stopOpacity: 1 }} />
            <stop offset="50%" style={{ stopColor: '#a78bfa', stopOpacity: 1 }} />
            <stop offset="100%" style={{ stopColor: '#60a5fa', stopOpacity: 1 }} />
          </linearGradient>
        </defs>
      </svg>

      <ReactFlow
        nodes={nodesWithSelection}
        edges={edgesWithSelection}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onNodeClick={handleNodeClick}
        onEdgeClick={handleEdgeClick}
        onPaneClick={handlePaneClick}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 50 }}
        selectionMode={SelectionMode.Partial}
        multiSelectionKeyCode="shift"
        deleteKeyCode={null}
        snapToGrid
        snapGrid={[20, 20]}
        attributionPosition="bottom-left"
        defaultViewport={{ x: 0, y: 0, zoom: 0.8 }}
        minZoom={0.1}
        maxZoom={2}
        nodesDraggable={true}
        nodesConnectable={true}
        elementsSelectable={true}
        connectOnClick={false}
        edgesUpdatable={true}
        edgesFocusable={true}
        style={{
          background: 'transparent'
        }}
        connectionLineStyle={{
          stroke: 'url(#edge-gradient)',
          strokeWidth: 2.5
        }}
        defaultEdgeOptions={{
          style: {
            stroke: 'url(#edge-gradient)',
            strokeWidth: 2
          },
          type: 'smoothstep',
          animated: true
        }}
      >
        {/* Enhanced Background with grid pattern */}
        <Background 
          variant={BackgroundVariant.Dots}//can select the backrgrund type here
          gap={24}
          size={2}
          color="#2d3748"
          style={{
            backgroundColor: 'transparent'
          }}
        />
        
        {/* Dark themed controls */}
        <Controls 
          showZoom
          showFitView
          showInteractive
          position="top-right"
          style={{
            backgroundColor: '#1a202c',
            border: '1px solid #4a5568',
            borderRadius: '12px',
            padding: '8px'
          }}
        />
        
        {/* Enhanced Mini map */}
        <MiniMap 
          nodeColor={(node) => {
            switch (node.data?.category) {
              case 'security': return '#ef4444'
              case 'compute': return '#3b82f6'
              case 'network': return '#10b981'
              case 'data': return '#f59e0b'
              case 'endpoints': return '#6366f1'
              case 'infrastructure': return '#8b5cf6'
              default: return '#6b7280'
            }
          }}
          maskColor="rgba(26, 32, 44, 0.8)"
          position="bottom-right"
          style={{
            backgroundColor: '#1a202c',
            border: '1px solid #4a5568',
            borderRadius: '12px',
            overflow: 'hidden'
          }}
          pannable
          zoomable
        />

        {/* Professional info panel */}
        <Panel position="top-left" className="text-white">
          <div className="bg-gray-800/90 backdrop-blur-sm border border-gray-600 rounded-xl p-4 shadow-2xl max-w-sm">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
              <span className="text-sm font-medium text-gray-300">Architecture Canvas</span>
            </div>
            <div className="text-xs text-gray-400 space-y-1">
              <div className="flex justify-between">
                <span>Nodes:</span>
                <span className="text-blue-400 font-mono">{nodes.length}</span>
              </div>
              <div className="flex justify-between">
                <span>Connections:</span>
                <span className="text-purple-400 font-mono">{edges.length}</span>
              </div>
              {selectedNodeId && (
                <div className="flex justify-between">
                  <span>Selected:</span>
                  <span className="text-green-400 font-mono">Node</span>
                </div>
              )}
              {selectedEdgeId && (
                <div className="flex justify-between">
                  <span>Selected:</span>
                  <span className="text-yellow-400 font-mono">Edge</span>
                </div>
              )}
            </div>
          </div>
        </Panel>

        {/* Grid overlay for professional look */}
        <Panel position="bottom-left" className="pointer-events-none">
          <div className="text-xs text-gray-500 font-mono bg-gray-800/50 px-2 py-1 rounded">
            Grid: 20px | Zoom: Auto
          </div>
        </Panel>
      </ReactFlow>

      {/* Instructions overlay */}
      {nodes.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <div className="text-center p-8 bg-gray-800/90 backdrop-blur-md rounded-2xl border border-gray-600 shadow-2xl max-w-md">
            <div className="text-6xl mb-6 animate-pulse">🏗️</div>
            <h3 className="text-xl font-bold text-white mb-3">
              Start Building Your Architecture
            </h3>
            <p className="text-gray-300 mb-6 leading-relaxed">
              Drag components from the sidebar to build your system architecture.
            </p>
            <div className="space-y-3 text-sm text-gray-400">
              <div className="flex items-center justify-center gap-2">
                <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                <span>Drag components to add them</span>
              </div>
              <div className="flex items-center justify-center gap-2">
                <div className="w-2 h-2 bg-purple-400 rounded-full"></div>
                <span>Click to select and configure</span>
              </div>
              <div className="flex items-center justify-center gap-2">
                <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                <span>Connect components to show relationships</span>
              </div>
              <div className="flex items-center justify-center gap-2">
                <div className="w-2 h-2 bg-yellow-400 rounded-full"></div>
                <span>Use toolbar buttons to manage components</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

/**
 * Wrapped FlowCanvas with ReactFlowProvider
 */
export const FlowCanvasWrapper: React.FC<FlowCanvasProps> = (props) => {
  return (
    <ReactFlowProvider>
      <FlowCanvas {...props} />
    </ReactFlowProvider>
  );
};

