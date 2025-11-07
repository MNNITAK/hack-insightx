/**
 * Component Registry System
 * Loads and manages all component configurations from JSON files
 * Provides categorized access to components for the sidebar
 */

import { ComponentConfiguration, ComponentCategory } from '../types';

// Create static component data since JSON imports are having issues
const createComponentData = () => {
  const webServerComponent: ComponentConfiguration = {
    component_type: "web_server",
    icon: "🌐",
    category: "compute",
    description: "Public-facing web server hosting applications",
    configurations: {
      basic: {
        name: "String",
        os: ["Linux", "Windows", "FreeBSD"],
        os_version: "String",
        ip_address: "String"
      },
      security: {
        firewall_enabled: "Boolean",
        waf_enabled: "Boolean",
        ssl_tls_version: ["TLS 1.3", "TLS 1.2", "None"]
      }
    }
  };

  const databaseComponent: ComponentConfiguration = {
    component_type: "database",
    icon: "💾",
    category: "data",
    description: "Database server storing application data",
    configurations: {
      basic: {
        name: "String",
        db_type: ["MySQL", "PostgreSQL", "MongoDB", "Oracle"],
        port: "Integer"
      },
      security: {
        encryption_at_rest: "Boolean",
        encryption_in_transit: "Boolean"
      }
    }
  };

  const firewallComponent: ComponentConfiguration = {
    component_type: "firewall",
    icon: "🛡️",
    category: "security",
    description: "Network security firewall",
    configurations: {
      basic: {
        name: "String",
        vendor: ["pfSense", "Cisco", "Fortinet"],
        version: "String"
      },
      rules: {
        default_action: ["deny", "allow"],
        logging_enabled: "Boolean"
      }
    }
  };

  const userWorkstationComponent: ComponentConfiguration = {
    component_type: "user_workstation",
    icon: "💻",
    category: "endpoints",
    description: "Employee desktop/laptop computer",
    configurations: {
      basic: {
        name: "String",
        device_type: ["Desktop", "Laptop"],
        os: ["Windows 10", "Windows 11", "macOS", "Linux"]
      },
      security: {
        antivirus_enabled: "Boolean",
        firewall_enabled: "Boolean",
        admin_privileges: "Boolean"
      }
    }
  };

  const loadBalancerComponent: ComponentConfiguration = {
    component_type: "load_balancer",
    icon: "⚖️",
    category: "network",
    description: "Distributes incoming requests across multiple servers",
    configurations: {
      basic: {
        name: "String",
        type: ["Application", "Network", "Global"],
        algorithm: ["Round Robin", "Least Connections", "IP Hash"]
      },
      health_checks: {
        enabled: "Boolean",
        interval_seconds: "Integer"
      }
    }
  };

  const apiGatewayComponent: ComponentConfiguration = {
    component_type: "api_gateway",
    icon: "🔌",
    category: "compute",
    description: "API gateway managing API requests and authentication",
    configurations: {
      basic: {
        name: "String",
        provider: ["Kong", "AWS API Gateway", "Azure API Management"]
      },
      security: {
        authentication: ["OAuth 2.0", "JWT", "API Keys"],
        rate_limiting: "Boolean"
      }
    }
  };

  const mobileDeviceComponent: ComponentConfiguration = {
    component_type: "mobile_device",
    icon: "📱",
    category: "endpoints",
    description: "Smartphone or tablet",
    configurations: {
      basic: {
        name: "String",
        device_type: ["iPhone", "iPad", "Android Phone", "Android Tablet"],
        os: ["iOS", "Android"]
      },
      security: {
        mdm_enrolled: "Boolean",
        device_encryption: "Boolean"
      }
    }
  };

  const cloudStorageComponent: ComponentConfiguration = {
    component_type: "cloud_storage",
    icon: "☁️",
    category: "cloud",
    description: "Cloud-based file storage service",
    configurations: {
      basic: {
        name: "String",
        provider: ["AWS S3", "Azure Blob", "Google Cloud Storage"],
        storage_size_tb: "Integer"
      },
      security: {
        public_access: "Boolean",
        encryption_at_rest: "Boolean"
      }
    }
  };

  return [
    webServerComponent,
    databaseComponent,
    firewallComponent,
    userWorkstationComponent,
    loadBalancerComponent,
    apiGatewayComponent,
    mobileDeviceComponent,
    cloudStorageComponent
  ];
};

/**
 * Component Registry class for managing all available components
 */
export class ComponentRegistry {
  private static instance: ComponentRegistry;
  private categories: Map<string, ComponentCategory> = new Map();
  private components: Map<string, ComponentConfiguration> = new Map();

  private constructor() {
    this.initializeComponents();
  }

  /**
   * Get singleton instance of ComponentRegistry
   */
  public static getInstance(): ComponentRegistry {
    if (!ComponentRegistry.instance) {
      ComponentRegistry.instance = new ComponentRegistry();
    }
    return ComponentRegistry.instance;
  }

  /**
   * Initialize all components from static data
   */
  private initializeComponents(): void {
    const allComponents = createComponentData();
    
    // Define category mappings with icons and descriptions
    const categoryMappings = {
      compute: { id: 'web-servers', name: 'Web Servers', icon: '🌐' },
      data: { id: 'data-storage', name: 'Data Storage', icon: '💾' },
      security: { id: 'security', name: 'Security Components', icon: '🛡️' },
      network: { id: 'network', name: 'Network Components', icon: '🔗' },
      endpoints: { id: 'user-devices', name: 'User Devices', icon: '💻' },
      cloud: { id: 'cloud', name: 'Cloud Services', icon: '☁️' },
    };

    // Group components by category
    const categoryGroups: { [key: string]: ComponentConfiguration[] } = {};
    
    allComponents.forEach(component => {
      const categoryKey = component.category;
      if (!categoryGroups[categoryKey]) {
        categoryGroups[categoryKey] = [];
      }
      categoryGroups[categoryKey].push(component);
      this.components.set(component.component_type, component);
    });

    // Create categories
    Object.entries(categoryGroups).forEach(([categoryKey, components]) => {
      const categoryMapping = categoryMappings[categoryKey as keyof typeof categoryMappings];
      if (categoryMapping) {
        const category: ComponentCategory = {
          id: categoryMapping.id,
          name: categoryMapping.name,
          icon: categoryMapping.icon,
          components: components
        };
        this.categories.set(categoryMapping.id, category);
      }
    });
  }

  /**
   * Validate if an object is a valid component configuration
   */
  private isValidComponent(obj: any): obj is ComponentConfiguration {
    return (
      obj &&
      typeof obj === 'object' &&
      typeof obj.component_type === 'string' &&
      typeof obj.icon === 'string' &&
      typeof obj.category === 'string' &&
      typeof obj.description === 'string' &&
      obj.configurations &&
      typeof obj.configurations === 'object'
    );
  }

  /**
   * Get all categories with their components
   */
  public getCategories(): ComponentCategory[] {
    return Array.from(this.categories.values());
  }

  /**
   * Get a specific category by ID
   */
  public getCategory(categoryId: string): ComponentCategory | undefined {
    return this.categories.get(categoryId);
  }

  /**
   * Get a specific component by type
   */
  public getComponent(componentType: string): ComponentConfiguration | undefined {
    return this.components.get(componentType);
  }

  /**
   * Get all components (flat list)
   */
  public getAllComponents(): ComponentConfiguration[] {
    return Array.from(this.components.values());
  }

  /**
   * Search components by name or description
   */
  public searchComponents(query: string): ComponentConfiguration[] {
    const searchTerm = query.toLowerCase();
    return this.getAllComponents().filter(component =>
      component.component_type.toLowerCase().includes(searchTerm) ||
      component.description.toLowerCase().includes(searchTerm) ||
      component.category.toLowerCase().includes(searchTerm)
    );
  }

  /**
   * Get components by category
   */
  public getComponentsByCategory(categoryId: string): ComponentConfiguration[] {
    const category = this.categories.get(categoryId);
    return category ? category.components : [];
  }

  /**
   * Get configuration schema for a component type
   */
  public getComponentConfigSchema(componentType: string): Record<string, any> | undefined {
    const component = this.getComponent(componentType);
    return component?.configurations;
  }

  /**
   * Get default properties for a component
   */
  public getDefaultProperties(componentType: string): Record<string, any> {
    const component = this.getComponent(componentType);
    if (!component) return {};

    const defaultProps: Record<string, any> = {};
    
    // Extract default values from configurations
    Object.entries(component.configurations).forEach(([sectionKey, section]) => {
      if (typeof section === 'object' && section !== null) {
        Object.entries(section).forEach(([key, value]) => {
          // Set reasonable defaults based on the field type
          if (typeof value === 'string') {
            if (value.includes('Boolean')) {
              defaultProps[key] = false;
            } else if (value.includes('Integer')) {
              defaultProps[key] = 0;
            } else if (Array.isArray(value)) {
              defaultProps[key] = value[0]; // Take first option as default
            } else {
              defaultProps[key] = '';
            }
          } else if (Array.isArray(value)) {
            defaultProps[key] = value[0]; // Take first option as default
          } else {
            defaultProps[key] = value;
          }
        });
      }
    });

    return defaultProps;
  }

  /**
   * Validate component configuration
   */
  public validateConfiguration(componentType: string, config: Record<string, any>): {
    isValid: boolean;
    errors: string[];
  } {
    const component = this.getComponent(componentType);
    if (!component) {
      return { isValid: false, errors: ['Unknown component type'] };
    }

    const errors: string[] = [];
    
    // Basic validation - can be extended based on requirements
    if (!config.name || typeof config.name !== 'string') {
      errors.push('Component name is required');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }
}

/**
 * Utility function to get the component registry instance
 */
export const getComponentRegistry = (): ComponentRegistry => {
  return ComponentRegistry.getInstance();
};

/**
 * Hook for React components to use the component registry
 */
export const useComponentRegistry = () => {
  const registry = ComponentRegistry.getInstance();
  
  return {
    getCategories: () => registry.getCategories(),
    getComponent: (type: string) => registry.getComponent(type),
    searchComponents: (query: string) => registry.searchComponents(query),
    getDefaultProperties: (type: string) => registry.getDefaultProperties(type),
    validateConfiguration: (type: string, config: Record<string, any>) => 
      registry.validateConfiguration(type, config)
  };
};