/**
 * Core type definitions for the Architecture Builder application
 * Defines interfaces for components, nodes, connections, and architecture management
 */

import { Node, Edge } from 'reactflow';

// Base component configuration structure from JSON files
export interface ComponentConfiguration {
  component_type: string;
  icon: string;
  category: string;
  description: string;
  configurations: Record<string, any>;
  common_vulnerabilities?: string[];
}

// Component category for organizing in sidebar
export interface ComponentCategory {
  id: string;
  name: string;
  icon: string;
  components: ComponentConfiguration[];
}

// Custom node data structure
export interface CustomNodeData {
  id: string;
  type: string;
  component_type: string;
  name: string;
  icon: string;
  description: string;
  properties?: Record<string, any>;
  configurations?: Record<string, Record<string, any>>;
  category: string;
  configured?: boolean;
}

// Custom node type for React Flow - using Node as the base type structure
export type CustomNode = Node<CustomNodeData>;

// Enhanced connection configuration types (from the Enhanced Connection Modal)
export interface EnhancedConnectionConfig {
  // Basic Configuration
  name: string;
  description: string;
  direction: 'inbound' | 'outbound' | 'bidirectional';
  
  // Security Configuration
  encryption: boolean;
  authentication_required: boolean;
  authorization_level: 'none' | 'basic' | 'elevated' | 'admin';
  ssl_tls: boolean;
  certificate_validation: boolean;
  
  // Type-specific configurations
  database?: {
    connection_type: 'read' | 'write' | 'read-write';
    database_name: string;
    table_access: string;
    query_type: 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' | 'mixed';
    connection_pooling: boolean;
    timeout_seconds: number;
    max_connections: number;
  };
  
  api?: {
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
    endpoint: string;
    authentication_type: 'none' | 'basic' | 'bearer' | 'oauth' | 'api-key';
    rate_limiting: boolean;
    rate_limit_requests: number;
    rate_limit_window: string;
    response_format: 'json' | 'xml' | 'plain' | 'binary';
    timeout_seconds: number;
  };
  
  file_transfer?: {
    protocol: 'FTP' | 'SFTP' | 'SCP' | 'HTTP' | 'HTTPS';
    file_types: string;
    max_file_size_mb: number;
    compression: boolean;
    virus_scanning: boolean;
    access_control: boolean;
    audit_logging: boolean;
  };
  
  authentication?: {
    auth_method: 'password' | 'mfa' | 'sso' | 'certificate' | 'biometric';
    session_management: boolean;
    session_timeout_minutes: number;
    password_policy: boolean;
    account_lockout: boolean;
    audit_logging: boolean;
  };
  
  // Attack vectors
  attack_vectors: {
    sql_injection: boolean;
    idor: boolean;
    path_traversal: boolean;
    xss: boolean;
    privilege_escalation: boolean;
  };
}

// Custom edge data for connections (enhanced)
export interface CustomEdgeData {
  id: string;
  type: string;
  properties?: Record<string, any>;
  protocol?: string;
  encrypted?: boolean;
  bandwidth?: string;
  // Enhanced configuration
  enhanced_config?: EnhancedConnectionConfig;
}

// Custom edge type for React Flow - using Edge as the base type structure
export type CustomEdge = Edge<CustomEdgeData>;

// Network zone definition
export interface NetworkZone {
  zone_id: string;
  name: string;
  trust_level: 'low' | 'medium' | 'high';
  internet_facing: boolean;
  color?: string;
}

// Architecture metadata
export interface ArchitectureMetadata {
  company_name: string;
  architecture_type: string;
  created_at: string;
  updated_at?: string;
  security_level: 'low' | 'medium' | 'high';
  description?: string;
}

// Complete architecture structure (matching reference architecture.json)
export interface Architecture {
  metadata: ArchitectureMetadata;
  nodes: ArchitectureNode[];
  connections: ArchitectureConnection[];
  network_zones: NetworkZone[];
}

// Architecture node (different from React Flow node - for storage)
export interface ArchitectureNode {
  id: string;
  type: string;
  name: string;
  properties: Record<string, any>;
  position: {
    x: number;
    y: number;
    zone?: string;
  };
}

// Architecture connection (different from React Flow edge - for storage)
export interface ArchitectureConnection {
  id: string;
  source: string;
  target: string;
  type: string;
  properties?: Record<string, any>;
  // Enhanced configuration for detailed connection analysis
  enhanced_config?: EnhancedConnectionConfig;
}

// Drag and drop types
export interface DragItem {
  type: 'component';
  componentType: string;
  componentConfig: ComponentConfiguration;
}

// Component configuration form field
export interface ConfigField {
  key: string;
  label: string;
  type: 'string' | 'number' | 'boolean' | 'select' | 'array';
  options?: string[] | number[];
  required?: boolean;
  description?: string;
}

// Component configuration form section
export interface ConfigSection {
  title: string;
  fields: ConfigField[];
}

// Flow state management
export interface FlowState {
  nodes: CustomNode[];
  edges: CustomEdge[];
  selectedNode: CustomNode | null;
  selectedEdge: CustomEdge | null;
  isConfigModalOpen: boolean;
  isDirty: boolean;
}

// Application state
export interface AppState {
  components: ComponentCategory[];
  flow: FlowState;
  currentArchitecture: Architecture | null;
  savedArchitectures: Architecture[];
}

// Event handlers
export interface FlowEventHandlers {
  onNodesChange: (changes: any[]) => void;
  onEdgesChange: (changes: any[]) => void;
  onConnect: (connection: any) => void;
  onNodeClick: (event: React.MouseEvent, node: CustomNode) => void;
  onEdgeClick: (event: React.MouseEvent, edge: CustomEdge) => void;
  onDrop: (event: React.DragEvent) => void;
  onDragOver: (event: React.DragEvent) => void;
}

// Storage operations
export interface StorageOperations {
  saveToLocalStorage: (architecture: Architecture) => void;
  loadFromLocalStorage: (architectureId: string) => Architecture | null;
  exportToFile: (architecture: Architecture) => void;
  importFromFile: (file: File) => Promise<Architecture>;
  listSavedArchitectures: () => Architecture[];
  deleteArchitecture: (architectureId: string) => void;
}

// Utility types
export type ComponentType = 
  | 'web_server' 
  | 'database' 
  | 'firewall' 
  | 'user_workstation' 
  | 'api_gateway' 
  | 'cache_server' 
  | 'file_storage'
  | string; // Allow for dynamic component types

export type SecurityLevel = 'low' | 'medium' | 'high';
export type TrustLevel = 'low' | 'medium' | 'high';

// Error types
export interface ArchitectureError {
  type: 'validation' | 'storage' | 'network' | 'component';
  message: string;
  nodeId?: string;
  edgeId?: string;
}