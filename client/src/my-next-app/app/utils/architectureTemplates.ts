/**
 * Architecture Templates Library
 * Pre-built architecture templates for common system types
 */

export interface ArchitectureTemplate {
  id: string;
  name: string;
  type: string;
  category: string;
  icon: string;
  description: string;
  tags: string[];
  complexity: 'simple' | 'medium' | 'complex';
  estimatedCost: string;
  nodes: TemplateNode[];
  connections: TemplateConnection[];
}

export interface TemplateNode {
  id: string;
  name: string;
  component_type: string;
  tier: string;
  position: { x: number; y: number };
  properties: Record<string, any>;
}

export interface TemplateConnection {
  id: string;
  source: string;
  target: string;
  protocol: string;
  encrypted: boolean;
  description: string;
}



// ==================== E-COMMERCE TEMPLATE ====================


export const ecommerceTemplate: ArchitectureTemplate = {
  id: 'template_ecommerce',
  name: 'E-Commerce Platform',
  type: 'e-commerce',
  category: 'Retail',
  icon: '🛒',
  description: 'Complete e-commerce architecture with payment processing, inventory management, and order fulfillment',
  tags: ['shopping', 'payments', 'retail', 'web'],
  complexity: 'medium',
  estimatedCost: '$5,000 - $15,000/month',
  nodes: [
    { id: 'node_ec_1', name: 'Customer Devices', component_type: 'user_workstation', tier: 'user', position: { x: 400, y: 50 }, properties: { description: 'Web browsers and mobile apps' } },
    { id: 'node_ec_2', name: 'CDN', component_type: 'cdn', tier: 'web', position: { x: 400, y: 150 }, properties: { provider: 'CloudFlare', caching: true } },
    { id: 'node_ec_3', name: 'Load Balancer', component_type: 'load_balancer', tier: 'web', position: { x: 400, y: 250 }, properties: { algorithm: 'round-robin' } },
    { id: 'node_ec_4', name: 'Web Server 1', component_type: 'web_server', tier: 'web', position: { x: 250, y: 350 }, properties: { server: 'nginx' } },
    { id: 'node_ec_5', name: 'Web Server 2', component_type: 'web_server', tier: 'web', position: { x: 550, y: 350 }, properties: { server: 'nginx' } },
    { id: 'node_ec_6', name: 'API Gateway', component_type: 'api_gateway', tier: 'application', position: { x: 400, y: 450 }, properties: { rate_limiting: true } },
    { id: 'node_ec_7', name: 'Product Service', component_type: 'microservice', tier: 'application', position: { x: 150, y: 550 }, properties: { service: 'products' } },
    { id: 'node_ec_8', name: 'Cart Service', component_type: 'microservice', tier: 'application', position: { x: 350, y: 550 }, properties: { service: 'cart' } },
    { id: 'node_ec_9', name: 'Order Service', component_type: 'microservice', tier: 'application', position: { x: 550, y: 550 }, properties: { service: 'orders' } },
    { id: 'node_ec_10', name: 'Payment Gateway', component_type: 'payment_gateway', tier: 'application', position: { x: 750, y: 550 }, properties: { provider: 'Stripe' } },
    { id: 'node_ec_11', name: 'Redis Cache', component_type: 'cache_server', tier: 'data', position: { x: 200, y: 650 }, properties: { cache_type: 'redis' } },
    { id: 'node_ec_12', name: 'Product Database', component_type: 'database', tier: 'data', position: { x: 400, y: 750 }, properties: { db_type: 'postgresql' } },
    { id: 'node_ec_13', name: 'Order Database', component_type: 'database', tier: 'data', position: { x: 600, y: 750 }, properties: { db_type: 'postgresql' } },
    { id: 'node_ec_14', name: 'Firewall', component_type: 'firewall', tier: 'security', position: { x: 100, y: 250 }, properties: { rules: 'strict' } },
  ],
  connections: [
    { id: 'conn_ec_1', source: 'node_ec_1', target: 'node_ec_2', protocol: 'HTTPS', encrypted: true, description: 'User requests' },
    { id: 'conn_ec_2', source: 'node_ec_2', target: 'node_ec_3', protocol: 'HTTPS', encrypted: true, description: 'CDN to load balancer' },
    { id: 'conn_ec_3', source: 'node_ec_3', target: 'node_ec_4', protocol: 'HTTP', encrypted: false, description: 'Load balanced traffic' },
    { id: 'conn_ec_4', source: 'node_ec_3', target: 'node_ec_5', protocol: 'HTTP', encrypted: false, description: 'Load balanced traffic' },
    { id: 'conn_ec_5', source: 'node_ec_4', target: 'node_ec_6', protocol: 'HTTP', encrypted: false, description: 'API calls' },
    { id: 'conn_ec_6', source: 'node_ec_5', target: 'node_ec_6', protocol: 'HTTP', encrypted: false, description: 'API calls' },
    { id: 'conn_ec_7', source: 'node_ec_6', target: 'node_ec_7', protocol: 'HTTP', encrypted: false, description: 'Product API' },
    { id: 'conn_ec_8', source: 'node_ec_6', target: 'node_ec_8', protocol: 'HTTP', encrypted: false, description: 'Cart API' },
    { id: 'conn_ec_9', source: 'node_ec_6', target: 'node_ec_9', protocol: 'HTTP', encrypted: false, description: 'Order API' },
    { id: 'conn_ec_10', source: 'node_ec_9', target: 'node_ec_10', protocol: 'HTTPS', encrypted: true, description: 'Payment processing' },
    { id: 'conn_ec_11', source: 'node_ec_8', target: 'node_ec_11', protocol: 'TCP', encrypted: false, description: 'Session cache' },
    { id: 'conn_ec_12', source: 'node_ec_7', target: 'node_ec_12', protocol: 'TCP', encrypted: false, description: 'Product data' },
    { id: 'conn_ec_13', source: 'node_ec_9', target: 'node_ec_13', protocol: 'TCP', encrypted: false, description: 'Order data' },
  ]
};

// ==================== HEALTHCARE TEMPLATE ====================
export const healthcareTemplate: ArchitectureTemplate = {
  id: 'template_healthcare',
  name: 'Hospital Management System',
  type: 'healthcare',
  category: 'Medical',
  icon: '🏥',
  description: 'HIPAA-compliant healthcare system with patient records, appointment scheduling, and secure data storage',
  tags: ['medical', 'hipaa', 'ehr', 'compliance'],
  complexity: 'complex',
  estimatedCost: '$10,000 - $30,000/month',
  nodes: [
    { id: 'node_hc_1', name: 'Staff Workstations', component_type: 'user_workstation', tier: 'user', position: { x: 400, y: 50 }, properties: { description: 'Doctor/nurse devices' } },
    { id: 'node_hc_2', name: 'VPN Gateway', component_type: 'vpn_gateway', tier: 'security', position: { x: 400, y: 150 }, properties: { encryption: 'AES-256' } },
    { id: 'node_hc_3', name: 'WAF', component_type: 'waf', tier: 'security', position: { x: 200, y: 250 }, properties: { rules: 'OWASP Top 10' } },
    { id: 'node_hc_4', name: 'API Gateway', component_type: 'api_gateway', tier: 'application', position: { x: 400, y: 250 }, properties: { authentication: 'OAuth2' } },
    { id: 'node_hc_5', name: 'Patient Portal', component_type: 'web_server', tier: 'application', position: { x: 400, y: 350 }, properties: { ssl_required: true } },
    { id: 'node_hc_6', name: 'EHR Service', component_type: 'microservice', tier: 'application', position: { x: 200, y: 450 }, properties: { service: 'ehr' } },
    { id: 'node_hc_7', name: 'Appointment Service', component_type: 'microservice', tier: 'application', position: { x: 400, y: 450 }, properties: { service: 'scheduling' } },
    { id: 'node_hc_8', name: 'Billing Service', component_type: 'microservice', tier: 'application', position: { x: 600, y: 450 }, properties: { service: 'billing' } },
    { id: 'node_hc_9', name: 'Encryption Gateway', component_type: 'encryption_gateway', tier: 'security', position: { x: 100, y: 550 }, properties: { encryption: 'at-rest' } },
    { id: 'node_hc_10', name: 'Patient Database', component_type: 'database', tier: 'data', position: { x: 300, y: 650 }, properties: { db_type: 'postgresql', encrypted: true } },
    { id: 'node_hc_11', name: 'Imaging Storage', component_type: 'file_storage', tier: 'data', position: { x: 500, y: 650 }, properties: { storage: 's3', encrypted: true } },
    { id: 'node_hc_12', name: 'Audit Log DB', component_type: 'database', tier: 'data', position: { x: 700, y: 650 }, properties: { db_type: 'mongodb' } },
    { id: 'node_hc_13', name: 'SIEM', component_type: 'siem', tier: 'security', position: { x: 700, y: 350 }, properties: { monitoring: 'real-time' } },
  ],
  connections: [
    { id: 'conn_hc_1', source: 'node_hc_1', target: 'node_hc_2', protocol: 'VPN', encrypted: true, description: 'Secure access' },
    { id: 'conn_hc_2', source: 'node_hc_2', target: 'node_hc_4', protocol: 'HTTPS', encrypted: true, description: 'API access' },
    { id: 'conn_hc_3', source: 'node_hc_3', target: 'node_hc_4', protocol: 'HTTPS', encrypted: true, description: 'Filtered traffic' },
    { id: 'conn_hc_4', source: 'node_hc_4', target: 'node_hc_5', protocol: 'HTTPS', encrypted: true, description: 'Portal access' },
    { id: 'conn_hc_5', source: 'node_hc_5', target: 'node_hc_6', protocol: 'HTTPS', encrypted: true, description: 'EHR API' },
    { id: 'conn_hc_6', source: 'node_hc_5', target: 'node_hc_7', protocol: 'HTTPS', encrypted: true, description: 'Appointment API' },
    { id: 'conn_hc_7', source: 'node_hc_5', target: 'node_hc_8', protocol: 'HTTPS', encrypted: true, description: 'Billing API' },
    { id: 'conn_hc_8', source: 'node_hc_6', target: 'node_hc_9', protocol: 'TCP', encrypted: true, description: 'Encrypted data' },
    { id: 'conn_hc_9', source: 'node_hc_9', target: 'node_hc_10', protocol: 'TCP', encrypted: true, description: 'Patient data' },
    { id: 'conn_hc_10', source: 'node_hc_6', target: 'node_hc_11', protocol: 'HTTPS', encrypted: true, description: 'Medical images' },
    { id: 'conn_hc_11', source: 'node_hc_13', target: 'node_hc_12', protocol: 'TCP', encrypted: false, description: 'Audit logs' },
  ]
};

// ==================== BANKING TEMPLATE ====================
export const bankingTemplate: ArchitectureTemplate = {
  id: 'template_banking',
  name: 'Banking & Financial Services',
  type: 'financial',
  category: 'Finance',
  icon: '🏦',
  description: 'Secure banking platform with transaction processing, fraud detection, and regulatory compliance',
  tags: ['banking', 'finance', 'pci-dss', 'transactions'],
  complexity: 'complex',
  estimatedCost: '$15,000 - $50,000/month',
  nodes: [
    { id: 'node_bnk_1', name: 'Customer Apps', component_type: 'mobile_device', tier: 'user', position: { x: 400, y: 50 }, properties: { platform: 'iOS/Android' } },
    { id: 'node_bnk_2', name: 'API Gateway', component_type: 'api_gateway', tier: 'web', position: { x: 400, y: 150 }, properties: { rate_limiting: 'strict' } },
    { id: 'node_bnk_3', name: 'WAF', component_type: 'waf', tier: 'security', position: { x: 200, y: 250 }, properties: { ddos_protection: true } },
    { id: 'node_bnk_4', name: 'Auth Service', component_type: 'authentication_service', tier: 'application', position: { x: 250, y: 350 }, properties: { mfa: 'required' } },
    { id: 'node_bnk_5', name: 'Transaction Service', component_type: 'microservice', tier: 'application', position: { x: 450, y: 350 }, properties: { service: 'transactions' } },
    { id: 'node_bnk_6', name: 'Fraud Detection', component_type: 'microservice', tier: 'application', position: { x: 650, y: 350 }, properties: { ml_enabled: true } },
    { id: 'node_bnk_7', name: 'Account Service', component_type: 'microservice', tier: 'application', position: { x: 350, y: 450 }, properties: { service: 'accounts' } },
    { id: 'node_bnk_8', name: 'Payment Processor', component_type: 'payment_gateway', tier: 'application', position: { x: 550, y: 450 }, properties: { pci_compliant: true } },
    { id: 'node_bnk_9', name: 'Transaction DB', component_type: 'database', tier: 'data', position: { x: 300, y: 650 }, properties: { db_type: 'postgresql', acid: true } },
    { id: 'node_bnk_10', name: 'Account DB (Primary)', component_type: 'database', tier: 'data', position: { x: 500, y: 650 }, properties: { db_type: 'postgresql', encrypted: true } },
    { id: 'node_bnk_11', name: 'Account DB (Replica)', component_type: 'database', tier: 'data', position: { x: 500, y: 750 }, properties: { db_type: 'postgresql', read_only: true } },
    { id: 'node_bnk_12', name: 'Backup System', component_type: 'backup_system', tier: 'data', position: { x: 700, y: 650 }, properties: { frequency: 'continuous' } },
    { id: 'node_bnk_13', name: 'HSM', component_type: 'encryption_gateway', tier: 'security', position: { x: 100, y: 450 }, properties: { hardware: 'thales' } },
  ],
  connections: [
    { id: 'conn_bnk_1', source: 'node_bnk_1', target: 'node_bnk_2', protocol: 'HTTPS', encrypted: true, description: 'Mobile API calls' },
    { id: 'conn_bnk_2', source: 'node_bnk_2', target: 'node_bnk_3', protocol: 'HTTPS', encrypted: true, description: 'Filtered traffic' },
    { id: 'conn_bnk_3', source: 'node_bnk_3', target: 'node_bnk_4', protocol: 'HTTPS', encrypted: true, description: 'Authentication' },
    { id: 'conn_bnk_4', source: 'node_bnk_4', target: 'node_bnk_5', protocol: 'HTTPS', encrypted: true, description: 'Authorized requests' },
    { id: 'conn_bnk_5', source: 'node_bnk_5', target: 'node_bnk_6', protocol: 'HTTPS', encrypted: true, description: 'Fraud check' },
    { id: 'conn_bnk_6', source: 'node_bnk_5', target: 'node_bnk_7', protocol: 'HTTPS', encrypted: true, description: 'Account operations' },
    { id: 'conn_bnk_7', source: 'node_bnk_5', target: 'node_bnk_8', protocol: 'HTTPS', encrypted: true, description: 'Payment processing' },
    { id: 'conn_bnk_8', source: 'node_bnk_5', target: 'node_bnk_9', protocol: 'TCP', encrypted: true, description: 'Transaction records' },
    { id: 'conn_bnk_9', source: 'node_bnk_7', target: 'node_bnk_10', protocol: 'TCP', encrypted: true, description: 'Account data' },
    { id: 'conn_bnk_10', source: 'node_bnk_10', target: 'node_bnk_11', protocol: 'TCP', encrypted: true, description: 'Replication' },
    { id: 'conn_bnk_11', source: 'node_bnk_10', target: 'node_bnk_12', protocol: 'TCP', encrypted: true, description: 'Backup sync' },
  ]
};

// ==================== SAAS TEMPLATE ====================
export const saasTemplate: ArchitectureTemplate = {
  id: 'template_saas',
  name: 'SaaS Application Platform',
  type: 'saas',
  category: 'Software',
  icon: '☁️',
  description: 'Multi-tenant SaaS platform with microservices, API management, and scalable infrastructure',
  tags: ['saas', 'multi-tenant', 'cloud', 'scalable'],
  complexity: 'medium',
  estimatedCost: '$8,000 - $20,000/month',
  nodes: [
    { id: 'node_saas_1', name: 'User Browsers', component_type: 'user_workstation', tier: 'user', position: { x: 400, y: 50 }, properties: {} },
    { id: 'node_saas_2', name: 'CDN', component_type: 'cdn', tier: 'web', position: { x: 400, y: 150 }, properties: { provider: 'CloudFront' } },
    { id: 'node_saas_3', name: 'Load Balancer', component_type: 'load_balancer', tier: 'web', position: { x: 400, y: 250 }, properties: { auto_scaling: true } },
    { id: 'node_saas_4', name: 'Web App Cluster', component_type: 'web_server', tier: 'application', position: { x: 400, y: 350 }, properties: { instances: 'auto-scale' } },
    { id: 'node_saas_5', name: 'API Gateway', component_type: 'api_gateway', tier: 'application', position: { x: 400, y: 450 }, properties: { versioning: 'v1/v2' } },
    { id: 'node_saas_6', name: 'Auth Service', component_type: 'authentication_service', tier: 'application', position: { x: 200, y: 550 }, properties: { sso: 'enabled' } },
    { id: 'node_saas_7', name: 'User Service', component_type: 'microservice', tier: 'application', position: { x: 350, y: 550 }, properties: { service: 'users' } },
    { id: 'node_saas_8', name: 'Billing Service', component_type: 'microservice', tier: 'application', position: { x: 500, y: 550 }, properties: { service: 'billing' } },
    { id: 'node_saas_9', name: 'Analytics Service', component_type: 'microservice', tier: 'application', position: { x: 650, y: 550 }, properties: { service: 'analytics' } },
    { id: 'node_saas_10', name: 'Redis Cache', component_type: 'cache_server', tier: 'data', position: { x: 200, y: 650 }, properties: { cache_strategy: 'LRU' } },
    { id: 'node_saas_11', name: 'Tenant DB', component_type: 'database', tier: 'data', position: { x: 400, y: 750 }, properties: { db_type: 'postgresql', multi_tenant: true } },
    { id: 'node_saas_12', name: 'Message Queue', component_type: 'message_queue', tier: 'data', position: { x: 600, y: 650 }, properties: { queue: 'rabbitmq' } },
  ],
  connections: [
    { id: 'conn_saas_1', source: 'node_saas_1', target: 'node_saas_2', protocol: 'HTTPS', encrypted: true, description: 'User requests' },
    { id: 'conn_saas_2', source: 'node_saas_2', target: 'node_saas_3', protocol: 'HTTPS', encrypted: true, description: 'Load balancing' },
    { id: 'conn_saas_3', source: 'node_saas_3', target: 'node_saas_4', protocol: 'HTTP', encrypted: false, description: 'App traffic' },
    { id: 'conn_saas_4', source: 'node_saas_4', target: 'node_saas_5', protocol: 'HTTP', encrypted: false, description: 'API calls' },
    { id: 'conn_saas_5', source: 'node_saas_5', target: 'node_saas_6', protocol: 'HTTP', encrypted: false, description: 'Authentication' },
    { id: 'conn_saas_6', source: 'node_saas_5', target: 'node_saas_7', protocol: 'HTTP', encrypted: false, description: 'User management' },
    { id: 'conn_saas_7', source: 'node_saas_5', target: 'node_saas_8', protocol: 'HTTP', encrypted: false, description: 'Billing' },
    { id: 'conn_saas_8', source: 'node_saas_5', target: 'node_saas_9', protocol: 'HTTP', encrypted: false, description: 'Analytics' },
    { id: 'conn_saas_9', source: 'node_saas_7', target: 'node_saas_10', protocol: 'TCP', encrypted: false, description: 'Session cache' },
    { id: 'conn_saas_10', source: 'node_saas_7', target: 'node_saas_11', protocol: 'TCP', encrypted: false, description: 'User data' },
    { id: 'conn_saas_11', source: 'node_saas_9', target: 'node_saas_12', protocol: 'AMQP', encrypted: false, description: 'Event processing' },
  ]
};

// ==================== SOCIAL MEDIA TEMPLATE ====================
export const socialMediaTemplate: ArchitectureTemplate = {
  id: 'template_social',
  name: 'Social Media Platform',
  type: 'social',
  category: 'Entertainment',
  icon: '📱',
  description: 'Scalable social network with real-time feeds, messaging, media storage, and content delivery',
  tags: ['social', 'realtime', 'media', 'messaging'],
  complexity: 'complex',
  estimatedCost: '$12,000 - $35,000/month',
  nodes: [
    { id: 'node_soc_1', name: 'Mobile Apps', component_type: 'mobile_device', tier: 'user', position: { x: 400, y: 50 }, properties: {} },
    { id: 'node_soc_2', name: 'CDN', component_type: 'cdn', tier: 'web', position: { x: 400, y: 150 }, properties: { edge_locations: 'global' } },
    { id: 'node_soc_3', name: 'API Gateway', component_type: 'api_gateway', tier: 'web', position: { x: 400, y: 250 }, properties: { websocket: true } },
    { id: 'node_soc_4', name: 'Feed Service', component_type: 'microservice', tier: 'application', position: { x: 200, y: 350 }, properties: { service: 'feed' } },
    { id: 'node_soc_5', name: 'Post Service', component_type: 'microservice', tier: 'application', position: { x: 400, y: 350 }, properties: { service: 'posts' } },
    { id: 'node_soc_6', name: 'Messaging Service', component_type: 'microservice', tier: 'application', position: { x: 600, y: 350 }, properties: { realtime: true } },
    { id: 'node_soc_7', name: 'Notification Service', component_type: 'microservice', tier: 'application', position: { x: 300, y: 450 }, properties: { push_enabled: true } },
    { id: 'node_soc_8', name: 'Media Processing', component_type: 'microservice', tier: 'application', position: { x: 500, y: 450 }, properties: { video_encoding: true } },
    { id: 'node_soc_9', name: 'User DB', component_type: 'database', tier: 'data', position: { x: 200, y: 650 }, properties: { db_type: 'postgresql' } },
    { id: 'node_soc_10', name: 'Feed Cache', component_type: 'cache_server', tier: 'data', position: { x: 400, y: 550 }, properties: { cache_type: 'redis' } },
    { id: 'node_soc_11', name: 'Post DB (NoSQL)', component_type: 'database', tier: 'data', position: { x: 400, y: 750 }, properties: { db_type: 'mongodb' } },
    { id: 'node_soc_12', name: 'Media Storage', component_type: 'file_storage', tier: 'data', position: { x: 600, y: 650 }, properties: { storage: 's3' } },
    { id: 'node_soc_13', name: 'Message Queue', component_type: 'message_queue', tier: 'data', position: { x: 700, y: 450 }, properties: { queue: 'kafka' } },
  ],
  connections: [
    { id: 'conn_soc_1', source: 'node_soc_1', target: 'node_soc_2', protocol: 'HTTPS', encrypted: true, description: 'App requests' },
    { id: 'conn_soc_2', source: 'node_soc_2', target: 'node_soc_3', protocol: 'HTTPS', encrypted: true, description: 'API calls' },
    { id: 'conn_soc_3', source: 'node_soc_3', target: 'node_soc_4', protocol: 'WebSocket', encrypted: true, description: 'Real-time feed' },
    { id: 'conn_soc_4', source: 'node_soc_3', target: 'node_soc_5', protocol: 'HTTP', encrypted: false, description: 'Post API' },
    { id: 'conn_soc_5', source: 'node_soc_3', target: 'node_soc_6', protocol: 'WebSocket', encrypted: true, description: 'Real-time messaging' },
    { id: 'conn_soc_6', source: 'node_soc_4', target: 'node_soc_10', protocol: 'TCP', encrypted: false, description: 'Feed cache' },
    { id: 'conn_soc_7', source: 'node_soc_5', target: 'node_soc_11', protocol: 'TCP', encrypted: false, description: 'Post data' },
    { id: 'conn_soc_8', source: 'node_soc_5', target: 'node_soc_8', protocol: 'HTTP', encrypted: false, description: 'Media upload' },
    { id: 'conn_soc_9', source: 'node_soc_8', target: 'node_soc_12', protocol: 'HTTPS', encrypted: true, description: 'Media storage' },
    { id: 'conn_soc_10', source: 'node_soc_6', target: 'node_soc_13', protocol: 'TCP', encrypted: false, description: 'Message events' },
    { id: 'conn_soc_11', source: 'node_soc_13', target: 'node_soc_7', protocol: 'TCP', encrypted: false, description: 'Notifications' },
  ]
};

// ==================== IOT TEMPLATE ====================
export const iotTemplate: ArchitectureTemplate = {
  id: 'template_iot',
  name: 'IoT Smart Home Platform',
  type: 'iot',
  category: 'IoT',
  icon: '🏠',
  description: 'IoT platform for smart home devices with real-time control, analytics, and automation',
  tags: ['iot', 'smart-home', 'mqtt', 'devices'],
  complexity: 'medium',
  estimatedCost: '$6,000 - $18,000/month',
  nodes: [
    { id: 'node_iot_1', name: 'Smart Devices', component_type: 'iot_device', tier: 'user', position: { x: 400, y: 50 }, properties: { devices: 'sensors, cameras, thermostats' } },
    { id: 'node_iot_2', name: 'IoT Gateway', component_type: 'api_gateway', tier: 'web', position: { x: 400, y: 150 }, properties: { protocol: 'MQTT/CoAP' } },
    { id: 'node_iot_3', name: 'Device Registry', component_type: 'microservice', tier: 'application', position: { x: 250, y: 250 }, properties: { service: 'registry' } },
    { id: 'node_iot_4', name: 'Data Ingestion', component_type: 'microservice', tier: 'application', position: { x: 450, y: 250 }, properties: { throughput: 'high' } },
    { id: 'node_iot_5', name: 'Control Service', component_type: 'microservice', tier: 'application', position: { x: 650, y: 250 }, properties: { service: 'control' } },
    { id: 'node_iot_6', name: 'Analytics Engine', component_type: 'microservice', tier: 'application', position: { x: 350, y: 350 }, properties: { ml_models: true } },
    { id: 'node_iot_7', name: 'Automation Rules', component_type: 'microservice', tier: 'application', position: { x: 550, y: 350 }, properties: { rule_engine: true } },
    { id: 'node_iot_8', name: 'Message Broker', component_type: 'message_queue', tier: 'data', position: { x: 300, y: 500 }, properties: { queue: 'mqtt_broker' } },
    { id: 'node_iot_9', name: 'Time Series DB', component_type: 'database', tier: 'data', position: { x: 500, y: 500 }, properties: { db_type: 'influxdb' } },
    { id: 'node_iot_10', name: 'Device DB', component_type: 'database', tier: 'data', position: { x: 400, y: 600 }, properties: { db_type: 'mongodb' } },
  ],
  connections: [
    { id: 'conn_iot_1', source: 'node_iot_1', target: 'node_iot_2', protocol: 'MQTT', encrypted: true, description: 'Device telemetry' },
    { id: 'conn_iot_2', source: 'node_iot_2', target: 'node_iot_3', protocol: 'HTTP', encrypted: false, description: 'Device registration' },
    { id: 'conn_iot_3', source: 'node_iot_2', target: 'node_iot_4', protocol: 'MQTT', encrypted: false, description: 'Data ingestion' },
    { id: 'conn_iot_4', source: 'node_iot_2', target: 'node_iot_5', protocol: 'HTTP', encrypted: false, description: 'Control commands' },
    { id: 'conn_iot_5', source: 'node_iot_4', target: 'node_iot_8', protocol: 'MQTT', encrypted: false, description: 'Event stream' },
    { id: 'conn_iot_6', source: 'node_iot_8', target: 'node_iot_6', protocol: 'TCP', encrypted: false, description: 'Analytics processing' },
    { id: 'conn_iot_7', source: 'node_iot_8', target: 'node_iot_7', protocol: 'TCP', encrypted: false, description: 'Rule evaluation' },
    { id: 'conn_iot_8', source: 'node_iot_4', target: 'node_iot_9', protocol: 'TCP', encrypted: false, description: 'Time series data' },
    { id: 'conn_iot_9', source: 'node_iot_3', target: 'node_iot_10', protocol: 'TCP', encrypted: false, description: 'Device metadata' },
  ]
};

// ==================== Export all templates ====================
export const allTemplates: ArchitectureTemplate[] = [
  ecommerceTemplate,
  healthcareTemplate,
  bankingTemplate,
  saasTemplate,
  socialMediaTemplate,
  iotTemplate,
];

export const getTemplateById = (id: string): ArchitectureTemplate | undefined => {
  return allTemplates.find(template => template.id === id);
};

export const getTemplatesByCategory = (category: string): ArchitectureTemplate[] => {
  return allTemplates.filter(template => template.category === category);
};

export const getTemplatesByComplexity = (complexity: 'simple' | 'medium' | 'complex'): ArchitectureTemplate[] => {
  return allTemplates.filter(template => template.complexity === complexity);
};
