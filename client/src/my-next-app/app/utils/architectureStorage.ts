/**
 * Architecture Storage Utilities
 * Handles saving, loading, and managing architecture files
 * Supports both localStorage and file system operations
 */

import { Architecture, ArchitectureMetadata, CustomNode, CustomEdge } from '../types';

/**
 * Local Storage Keys
 */
const STORAGE_KEYS = {
  ARCHITECTURES: 'insightx_architectures',
  CURRENT_ARCHITECTURE: 'insightx_current_architecture',
  ARCHITECTURE_LIST: 'insightx_architecture_list'
} as const;

/**
 * Architecture Storage Manager
 */
export class ArchitectureStorage {
  private static instance: ArchitectureStorage;

  private constructor() {}

  public static getInstance(): ArchitectureStorage {
    if (!ArchitectureStorage.instance) {
      ArchitectureStorage.instance = new ArchitectureStorage();
    }
    return ArchitectureStorage.instance;
  }

  /**
   * Convert React Flow nodes and edges to architecture format
   */
  public convertFlowToArchitecture(
    nodes: CustomNode[],
    edges: CustomEdge[],
    metadata?: Partial<ArchitectureMetadata>
  ): Architecture {
    const now = new Date().toISOString();
    
    const architectureMetadata: ArchitectureMetadata = {
      company_name: metadata?.company_name || 'New Company',
      architecture_type: metadata?.architecture_type || 'Custom Architecture',
      created_at: metadata?.created_at || now,
      updated_at: now,
      security_level: metadata?.security_level || 'medium',
      description: metadata?.description || 'Architecture created with InsightX'
    };

    // Convert nodes
    const architectureNodes = nodes.map(node => ({
      id: node.id,
      type: node.data.type,
      name: node.data.name,
      properties: {
        ...node.data.properties,
        icon: node.data.icon,
        description: node.data.description,
        category: node.data.category,
        configured: node.data.configured
      },
      position: {
        x: node.position.x,
        y: node.position.y,
        zone: node.data.properties?.zone || 'default'
      }
    }));

    // Convert edges with enhanced configurations
    const architectureConnections = edges.map(edge => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      type: edge.data?.type || 'network',
      properties: edge.data?.properties || {},
      // Include enhanced configuration if available
      enhanced_config: edge.data?.enhanced_config || undefined
    }));

    // Create default network zones
    const networkZones = [
      {
        zone_id: 'public',
        name: 'Public Zone',
        trust_level: 'low' as const,
        internet_facing: true
      },
      {
        zone_id: 'dmz',
        name: 'DMZ (Demilitarized Zone)',
        trust_level: 'low' as const,
        internet_facing: true
      },
      {
        zone_id: 'internal',
        name: 'Internal Network',
        trust_level: 'high' as const,
        internet_facing: false
      },
      {
        zone_id: 'private',
        name: 'Private Network',
        trust_level: 'high' as const,
        internet_facing: false
      }
    ];

    return {
      metadata: architectureMetadata,
      nodes: architectureNodes,
      connections: architectureConnections,
      network_zones: networkZones
    };
  }

  /**
   * Convert architecture format to React Flow nodes and edges
   */
  public convertArchitectureToFlow(architecture: Architecture): {
    nodes: CustomNode[];
    edges: CustomEdge[];
  } {
    // Convert nodes
    const nodes: CustomNode[] = architecture.nodes.map(node => ({
      id: node.id,
      type: 'custom',
      position: { x: node.position.x, y: node.position.y },
      data: {
        id: node.id,
        type: node.type,
        component_type: node.type, // Map type to component_type
        name: node.name,
        icon: node.properties.icon || '📦',
        description: node.properties.description || '',
        category: node.properties.category || 'general',
        properties: node.properties,
        configurations: node.properties.configurations || {},
        configured: node.properties.configured || false
      }
    }));

    // Convert edges with enhanced configurations
    const edges: CustomEdge[] = architecture.connections.map(connection => ({
      id: connection.id,
      source: connection.source,
      target: connection.target,
      type: 'smoothstep',
      data: {
        id: connection.id,
        type: connection.type,
        properties: connection.properties,
        // Include enhanced configuration if available
        enhanced_config: connection.enhanced_config
      }
    }));

    return { nodes, edges };
  }

  /**
   * Save architecture to localStorage
   */
  public saveToLocalStorage(architecture: Architecture): string {
    try {
      // Check if we're in the browser environment
      if (typeof window === 'undefined') {
        throw new Error('localStorage not available in server environment');
      }
      
      const architectureId = this.generateArchitectureId(architecture);
      const architecturesData = this.getArchitecturesFromStorage();
      
      // Update or add architecture
      architecturesData[architectureId] = architecture;
      
      // Save to database as well
      this.saveToDatabase(architecture, architectureId).catch(error => {
        console.warn('Failed to save architecture to database:', error);
      });

      // Save to localStorage
      localStorage.setItem(STORAGE_KEYS.ARCHITECTURES, JSON.stringify(architecturesData));
      
      // Update architecture list
      this.updateArchitectureList(architectureId, architecture.metadata);
      
      return architectureId;
    } catch (error) {
      console.error('Failed to save architecture to localStorage:', error);
      throw new Error('Failed to save architecture');
    }
  }

  /**
   * Load architecture from localStorage
   */
  public loadFromLocalStorage(architectureId: string): Architecture | null {
    try {
      // Check if we're in the browser environment
      if (typeof window === 'undefined') {
        return null;
      }
      
      const architecturesData = this.getArchitecturesFromStorage();
      return architecturesData[architectureId] || null;
    } catch (error) {
      console.error('Failed to load architecture from localStorage:', error);
      return null;
    }
  }

  /**
   * Get all saved architectures metadata
   */
  public listSavedArchitectures(): Array<{ id: string; metadata: ArchitectureMetadata }> {
    try {
      // Check if we're in the browser environment
      if (typeof window === 'undefined') {
        return [];
      }
      
      const listData = localStorage.getItem(STORAGE_KEYS.ARCHITECTURE_LIST);
      return listData ? JSON.parse(listData) : [];
    } catch (error) {
      console.error('Failed to list architectures:', error);
      return [];
    }
  }


  /**
   * Delete architecture from localStorage
   */
  public deleteArchitecture(architectureId: string): boolean {
    try {
      // Check if we're in the browser environment
      if (typeof window === 'undefined') {
        return false;
      }
      
      const architecturesData = this.getArchitecturesFromStorage();
      delete architecturesData[architectureId];
      
      localStorage.setItem(STORAGE_KEYS.ARCHITECTURES, JSON.stringify(architecturesData));
      
      // Update architecture list
      const list = this.listSavedArchitectures().filter(item => item.id !== architectureId);
      localStorage.setItem(STORAGE_KEYS.ARCHITECTURE_LIST, JSON.stringify(list));
      
      return true;
    } catch (error) {
      console.error('Failed to delete architecture:', error);
      return false;
    }
  }

  /**
   * Export architecture to JSON file
   */
  public exportToFile(architecture: Architecture, filename?: string): void {
    try {
      const jsonData = JSON.stringify(architecture, null, 2);
      const blob = new Blob([jsonData], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      
      const link = document.createElement('a');
      link.href = url;
      link.download = filename || `architecture_${architecture.metadata.company_name}_${Date.now()}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Failed to export architecture:', error);
      throw new Error('Failed to export architecture');
    }
  }

  /**
   * Import architecture from JSON file
   */
  public async importFromFile(file: File): Promise<Architecture> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      
      reader.onload = (event) => {
        try {
          const jsonData = event.target?.result as string;
          const architecture: Architecture = JSON.parse(jsonData);
          
          // Validate architecture structure
          if (this.validateArchitecture(architecture)) {
            resolve(architecture);
          } else {
            reject(new Error('Invalid architecture file format'));
          }
        } catch (error) {
          reject(new Error('Failed to parse architecture file'));
        }
      };
      
      reader.onerror = () => {
        reject(new Error('Failed to read file'));
      };
      
      reader.readAsText(file);
    });
  }

  /**
   * Save current work to localStorage (auto-save)
   */
  public autoSave(nodes: CustomNode[], edges: CustomEdge[], metadata?: Partial<ArchitectureMetadata>): void {
    try {
      // Check if we're in the browser environment
      if (typeof window === 'undefined') {
        return;
      }
      
      const architecture = this.convertFlowToArchitecture(nodes, edges, metadata);
      localStorage.setItem(STORAGE_KEYS.CURRENT_ARCHITECTURE, JSON.stringify(architecture));
    } catch (error) {
      console.warn('Auto-save failed:', error);
    }
  }

  /**
   * Load current work from localStorage (auto-save recovery)
   */
  public loadAutoSave(): { nodes: CustomNode[]; edges: CustomEdge[] } | null {
    try {
      // Check if we're in the browser environment
      if (typeof window === 'undefined') {
        return null;
      }
      
      const data = localStorage.getItem(STORAGE_KEYS.CURRENT_ARCHITECTURE);
      if (data) {
        const architecture: Architecture = JSON.parse(data);
        return this.convertArchitectureToFlow(architecture);
      }
      return null;
    } catch (error) {
      console.warn('Failed to load auto-save:', error);
      return null;
    }
  }

  /**
   * Clear auto-save data
   */
  public clearAutoSave(): void {
    // Check if we're in the browser environment
    if (typeof window === 'undefined') {
      return;
    }
    
    localStorage.removeItem(STORAGE_KEYS.CURRENT_ARCHITECTURE);
  }

  // Private helper methods

  private getArchitecturesFromStorage(): Record<string, Architecture> {
    try {
      // Check if we're in the browser environment
      if (typeof window === 'undefined') {
        return {};
      }
      
      const data = localStorage.getItem(STORAGE_KEYS.ARCHITECTURES);
      return data ? JSON.parse(data) : {};
    } catch (error) {
      console.error('Failed to parse architectures from storage:', error);
      return {};
    }
  }

  private generateArchitectureId(architecture: Architecture): string {
    // Generate ID based on company name and timestamp
    const cleanName = architecture.metadata.company_name
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '_');
    const timestamp = Date.now();
    return `${cleanName}_${timestamp}`;
  }

  private updateArchitectureList(id: string, metadata: ArchitectureMetadata): void {
    // Check if we're in the browser environment
    if (typeof window === 'undefined') {
      return;
    }
    
    const list = this.listSavedArchitectures();
    const existingIndex = list.findIndex(item => item.id === id);
    
    const item = { id, metadata };
    
    if (existingIndex >= 0) {
      list[existingIndex] = item;
    } else {
      list.push(item);
    }
    
    localStorage.setItem(STORAGE_KEYS.ARCHITECTURE_LIST, JSON.stringify(list));
  }

  private validateArchitecture(architecture: any): architecture is Architecture {
    return (
      architecture &&
      typeof architecture === 'object' &&
      architecture.metadata &&
      typeof architecture.metadata === 'object' &&
      Array.isArray(architecture.nodes) &&
      Array.isArray(architecture.connections) &&
      Array.isArray(architecture.network_zones)
    );
  }

  /**
   * Save architecture to database via API
   */
  private async saveToDatabase(architecture: Architecture, architectureId: string): Promise<void> {
    try {
      console.log('🔍 Saving to database - Architecture data:', {
        metadata: architecture.metadata,
        nodesCount: architecture.nodes?.length || 0,
        connectionsCount: architecture.connections?.length || 0,
        networkZonesCount: architecture.network_zones?.length || 0,
        fullArchitecture: architecture
      });

      const response = await fetch('/api/architectures', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          user_id: 'sample_user_123',
          architecture_data: architecture,
          trigger_info: {
            trigger_type: 'manual_save',
            notes: 'Saved from architecture builder'
          }
        }),
      });

        console.log("save response",response);
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(`HTTP error! status: ${response.status}, message: ${errorData.error}`);
      }

      const result = await response.json();

      console.log('✅ Architecture saved to database:', result.data);
    } catch (error) {
      console.error('Failed to save architecture to database:', error);
      throw error;
    }
  }
}

/**
 * Utility function to get the storage instance
 */
export const getArchitectureStorage = (): ArchitectureStorage => {
  return ArchitectureStorage.getInstance();
};

/**
 * Hook for React components to use architecture storage
 */
export const useArchitectureStorage = () => {
  const storage = ArchitectureStorage.getInstance();
  
  return {
    save: (architecture: Architecture) => storage.saveToLocalStorage(architecture),
    load: (id: string) => storage.loadFromLocalStorage(id),
    list: () => storage.listSavedArchitectures(),
    delete: (id: string) => storage.deleteArchitecture(id),
    exportToFile: (architecture: Architecture, filename?: string) => 
      storage.exportToFile(architecture, filename),
    importFromFile: (file: File) => storage.importFromFile(file),
    convertFlowToArchitecture: (nodes: CustomNode[], edges: CustomEdge[], metadata?: Partial<ArchitectureMetadata>) =>
      storage.convertFlowToArchitecture(nodes, edges, metadata),
    convertArchitectureToFlow: (architecture: Architecture) =>
      storage.convertArchitectureToFlow(architecture),
    autoSave: (nodes: CustomNode[], edges: CustomEdge[], metadata?: Partial<ArchitectureMetadata>) =>
      storage.autoSave(nodes, edges, metadata),
    loadAutoSave: () => storage.loadAutoSave(),
    clearAutoSave: () => storage.clearAutoSave()
  };
};