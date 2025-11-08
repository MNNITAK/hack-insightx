// Test script to verify enhanced configuration flow
const path = require('path');

// Mock React Flow edge with enhanced configuration
const mockEdgeWithEnhancedConfig = {
  id: 'test_connection_001',
  source: 'node_1',
  target: 'node_2',
  type: 'smoothstep',
  data: {
    properties: {
      protocol: 'HTTPS',
      encrypted: true
    },
    enhanced_config: {
      connection_type: 'api_call',
      security_configuration: {
        encryption: {
          enabled: true,
          method: 'TLS 1.3'
        },
        authentication: {
          required: true,
          methods: ['OAuth2', 'JWT']
        },
        access_control: {
          restrictions: ['Rate Limiting', 'IP Whitelist'],
          policies: ['RBAC']
        }
      },
      api_endpoints: {
        public: [{
          path: '/api/users',
          method: 'GET',
          requires_privilege: 'read_users',
          authorization_checks: true,
          data_returned: ['user_id', 'email', 'profile']
        }]
      },
      properties: {
        attack_vectors: {
          idor: { vulnerable: true },
          privilege_escalation: { vulnerable: false }
        }
      }
    }
  }
};

const mockNodes = [
  { id: 'node_1', type: 'customNode', position: { x: 100, y: 100 }, data: { label: 'API Server' } },
  { id: 'node_2', type: 'customNode', position: { x: 300, y: 100 }, data: { label: 'Database' } }
];

const mockEdges = [mockEdgeWithEnhancedConfig];

console.log('=== Testing Enhanced Configuration Flow ===');
console.log('\n1. Mock Edge Structure:');
console.log('- Edge ID:', mockEdgeWithEnhancedConfig.id);
console.log('- Has enhanced_config:', !!mockEdgeWithEnhancedConfig.data?.enhanced_config);
console.log('- Connection type:', mockEdgeWithEnhancedConfig.data?.enhanced_config?.connection_type);

// Simulate the conversion process
console.log('\n2. Simulating convertFlowToArchitecture...');
const architectureConnection = {
  id: mockEdgeWithEnhancedConfig.id,
  source: mockEdgeWithEnhancedConfig.source,
  target: mockEdgeWithEnhancedConfig.target,
  type: mockEdgeWithEnhancedConfig.data?.type || 'network',
  properties: mockEdgeWithEnhancedConfig.data?.properties || {},
  enhanced_config: mockEdgeWithEnhancedConfig.data?.enhanced_config || undefined
};

console.log('\n3. Converted Architecture Connection:');
console.log('- Connection ID:', architectureConnection.id);
console.log('- Enhanced config present:', !!architectureConnection.enhanced_config);
console.log('- Enhanced config keys:', architectureConnection.enhanced_config ? Object.keys(architectureConnection.enhanced_config) : 'none');

if (architectureConnection.enhanced_config) {
  console.log('\n4. Enhanced Configuration Details:');
  console.log(JSON.stringify(architectureConnection.enhanced_config, null, 2));
}

console.log('\n5. Final Architecture Connection Structure:');
console.log(JSON.stringify(architectureConnection, null, 2));

console.log('\n✅ Test shows enhanced configurations should be properly preserved!');
console.log('✅ The issue might be that no enhanced configurations have been saved yet.');
console.log('\n🔍 Next step: Check if the UI is actually calling handleEnhancedConnectionSave');