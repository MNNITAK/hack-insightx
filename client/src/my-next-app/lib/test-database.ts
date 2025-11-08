/**
 * Database Testing Utility
 * Tests all CRUD operations with sample data
 */

import { connectToDatabase } from '../lib/dbConnection';

// Import MongoDB models
const ArchitectureStorage = require('../lib/models/ArchitectureStorage');
const AttackSimulation = require('../lib/models/AttackSimulation');
const SelfHealing = require('../lib/models/SelfHealing');

/**
 * Sample test data for validation
 */
const SAMPLE_DATA = {
  user_id: 'sample_user_123',
  
  architecture: {
    id: 'test_arch_001',
    metadata: {
      company_name: 'Test Company',
      architecture_type: 'web_application',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      security_level: 'medium',
      description: 'Test architecture for database validation'
    },
    components: [
      {
        id: 'web_server_1',
        type: 'web_server',
        name: 'Frontend Server',
        properties: { port: 80, ssl: false },
        position: { x: 100, y: 100, zone: 'public' }
      },
      {
        id: 'database_1',
        type: 'database',
        name: 'Main Database',
        properties: { db_type: 'postgresql', encrypted: false },
        position: { x: 300, y: 200, zone: 'private' }
      }
    ],
    connections: [
      {
        id: 'conn_1',
        source: 'web_server_1',
        target: 'database_1',
        type: 'http',
        properties: { protocol: 'tcp', port: 5432 }
      }
    ]
  },
  
  attack: {
    attack_id: 'test_attack_001',
    attack_name: 'SQL Injection Test',
    category: 'initial_access',
    configured_at: new Date().toISOString(),
    parameters: {
      target_url: 'http://test.com/login',
      payload_type: 'union_based',
      timeout: 30
    }
  },
  
  healing: {
    detected_vulnerabilities: [
      {
        vulnerability_id: 'VULN_001',
        vulnerability_type: 'unencrypted_communication',
        severity: 'medium',
        affected_components: ['web_server_1'],
        description: 'HTTP traffic not encrypted',
        cvss_score: 5.3
      }
    ],
    recommended_actions: [
      {
        action_id: 'ACTION_001',
        action_type: 'modify_component',
        target_component_id: 'web_server_1',
        action_description: 'Enable HTTPS/SSL encryption',
        justification: 'Protect data in transit',
        addresses_vulnerabilities: ['VULN_001']
      }
    ]
  }
};

interface TestResults {
  database_connection: boolean;
  architectures: {
    create: boolean;
    read: boolean;
    update: boolean;
    delete: boolean;
  };
  attacks: {
    create: boolean;
    read: boolean;
    update: boolean;
    delete: boolean;
  };
  healing: {
    create: boolean;
    read: boolean;
    update: boolean;
    delete: boolean;
  };
  errors: string[];
}

/**
 * Main testing function
 */
export async function runDatabaseTests(): Promise<TestResults> {
  const results: TestResults = {
    database_connection: false,
    architectures: { create: false, read: false, update: false, delete: false },
    attacks: { create: false, read: false, update: false, delete: false },
    healing: { create: false, read: false, update: false, delete: false },
    errors: []
  };

  try {
    console.log('🚀 Starting database tests...');

    // Test database connection
    await connectToDatabase();
    results.database_connection = true;
    console.log('✅ Database connection successful');

    // Test Architecture Storage
    await testArchitectureStorage(results);
    
    // Test Attack Simulations  
    await testAttackSimulations(results);
    
    // Test Self-Healing
    await testSelfHealing(results);

    const totalTests = 13; // 1 connection + 4 per model * 3 models
    const passedTests = Object.values(results.architectures).filter(Boolean).length +
                       Object.values(results.attacks).filter(Boolean).length +
                       Object.values(results.healing).filter(Boolean).length +
                       (results.database_connection ? 1 : 0);

    console.log(`\n📊 Test Results: ${passedTests}/${totalTests} tests passed`);
    
    if (results.errors.length > 0) {
      console.log('\n❌ Errors encountered:');
      results.errors.forEach(error => console.log(`  - ${error}`));
    }

  } catch (error) {
    console.error('💥 Test suite failed:', error);
    results.errors.push(error instanceof Error ? error.message : 'Unknown error');
  }

  return results;
}

/**
 * Test Architecture Storage operations
 */
async function testArchitectureStorage(results: TestResults): Promise<void> {
  let testArchitectureId: string;

  try {
    console.log('\n🏗️ Testing Architecture Storage...');

    // Test CREATE
    const newArchitecture = new ArchitectureStorage({
      user_id: SAMPLE_DATA.user_id,
      architecture_id: SAMPLE_DATA.architecture.id,
      current_version: {
        architecture_data: SAMPLE_DATA.architecture,
        metadata: {
          name: SAMPLE_DATA.architecture.metadata.company_name,
          description: SAMPLE_DATA.architecture.metadata.description,
          tags: [SAMPLE_DATA.architecture.metadata.architecture_type]
        },
        trigger_info: {
          trigger_type: 'test',
          notes: 'Database test creation'
        }
      }
    });

    const savedArchitecture = await newArchitecture.save();
    testArchitectureId = savedArchitecture.architecture_id;
    results.architectures.create = true;
    console.log('  ✅ CREATE: Architecture saved');

    // Test READ
    const foundArchitecture = await ArchitectureStorage.findOne({
      architecture_id: testArchitectureId,
      user_id: SAMPLE_DATA.user_id
    });
    
    if (foundArchitecture) {
      results.architectures.read = true;
      console.log('  ✅ READ: Architecture retrieved');
    }

    // Test UPDATE (add new version)
    const updatedVersion = await foundArchitecture.addNewVersion(
      { ...SAMPLE_DATA.architecture, metadata: { ...SAMPLE_DATA.architecture.metadata, description: 'Updated for testing' }},
      { name: 'Updated Architecture', description: 'Updated in test', tags: ['updated'] },
      { trigger_type: 'test_update', notes: 'Update test' }
    );
    
    if (updatedVersion) {
      results.architectures.update = true;
      console.log('  ✅ UPDATE: Architecture version added');
    }

    // Test DELETE
    const deleteResult = await ArchitectureStorage.deleteOne({
      architecture_id: testArchitectureId,
      user_id: SAMPLE_DATA.user_id
    });
    
    if (deleteResult.deletedCount > 0) {
      results.architectures.delete = true;
      console.log('  ✅ DELETE: Architecture removed');
    }

  } catch (error) {
    console.error('  ❌ Architecture test failed:', error);
    results.errors.push(`Architecture: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Test Attack Simulation operations
 */
async function testAttackSimulations(results: TestResults): Promise<void> {
  let testAttackSessionId: string;

  try {
    console.log('\n⚔️ Testing Attack Simulations...');

    // Test CREATE
    const newAttack = new AttackSimulation({
      user_id: SAMPLE_DATA.user_id,
      configured_attack: SAMPLE_DATA.attack,
      target_architecture: SAMPLE_DATA.architecture,
      attack_configuration: SAMPLE_DATA.attack.parameters,
      attack_status: 'initiated'
    });

    const savedAttack = await newAttack.save();
    testAttackSessionId = savedAttack.attack_session_id;
    results.attacks.create = true;
    console.log('  ✅ CREATE: Attack simulation saved');

    // Test READ
    const foundAttack = await AttackSimulation.findOne({
      attack_session_id: testAttackSessionId,
      user_id: SAMPLE_DATA.user_id
    });
    
    if (foundAttack) {
      results.attacks.read = true;
      console.log('  ✅ READ: Attack simulation retrieved');
    }

    // Test UPDATE
    foundAttack.updateStatus('validation_completed');
    foundAttack.validation_result = {
      is_valid: true,
      validation_details: 'Test validation',
      can_proceed: true
    };
    
    const updatedAttack = await foundAttack.save();
    if (updatedAttack.attack_status === 'validation_completed') {
      results.attacks.update = true;
      console.log('  ✅ UPDATE: Attack status updated');
    }

    // Test DELETE
    const deleteResult = await AttackSimulation.deleteOne({
      attack_session_id: testAttackSessionId,
      user_id: SAMPLE_DATA.user_id
    });
    
    if (deleteResult.deletedCount > 0) {
      results.attacks.delete = true;
      console.log('  ✅ DELETE: Attack simulation removed');
    }

  } catch (error) {
    console.error('  ❌ Attack test failed:', error);
    results.errors.push(`Attack: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Test Self-Healing operations
 */
async function testSelfHealing(results: TestResults): Promise<void> {
  let testHealingSessionId: string;

  try {
    console.log('\n🔧 Testing Self-Healing...');

    // Test CREATE
    const newHealing = new SelfHealing({
      user_id: SAMPLE_DATA.user_id,
      original_architecture: SAMPLE_DATA.architecture,
      detected_vulnerabilities: SAMPLE_DATA.healing.detected_vulnerabilities,
      recommended_actions: SAMPLE_DATA.healing.recommended_actions,
      trigger_type: 'manual'
    });

    const savedHealing = await newHealing.save();
    testHealingSessionId = savedHealing.healing_session_id;
    results.healing.create = true;
    console.log('  ✅ CREATE: Healing session saved');

    // Test READ
    const foundHealing = await SelfHealing.findOne({
      healing_session_id: testHealingSessionId,
      user_id: SAMPLE_DATA.user_id
    });
    
    if (foundHealing) {
      results.healing.read = true;
      console.log('  ✅ READ: Healing session retrieved');
    }

    // Test UPDATE
    foundHealing.updateStatus('completed');
    foundHealing.acceptHealing(['ACTION_001']);
    
    const updatedHealing = await foundHealing.save();
    if (updatedHealing.healing_status === 'completed') {
      results.healing.update = true;
      console.log('  ✅ UPDATE: Healing session updated');
    }

    // Test DELETE
    const deleteResult = await SelfHealing.deleteOne({
      healing_session_id: testHealingSessionId,
      user_id: SAMPLE_DATA.user_id
    });
    
    if (deleteResult.deletedCount > 0) {
      results.healing.delete = true;
      console.log('  ✅ DELETE: Healing session removed');
    }

  } catch (error) {
    console.error('  ❌ Healing test failed:', error);
    results.errors.push(`Healing: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Test API endpoints
 */
export async function testAPIEndpoints(): Promise<{ success: boolean; results: any }> {
  console.log('\n🌐 Testing API endpoints...');
  
  try {
    // Test Architecture API
    const archResponse = await fetch('/api/architectures?user_id=sample_user_123&limit=5');
    const archData = await archResponse.json();
    console.log('  ✅ Architectures API:', archData.success ? 'Working' : 'Failed');

    // Test Attacks API
    const attackResponse = await fetch('/api/attacks?user_id=sample_user_123&limit=5');
    const attackData = await attackResponse.json();
    console.log('  ✅ Attacks API:', attackData.success ? 'Working' : 'Failed');

    // Test Healing API
    const healingResponse = await fetch('/api/healing?user_id=sample_user_123&limit=5');
    const healingData = await healingResponse.json();
    console.log('  ✅ Healing API:', healingData.success ? 'Working' : 'Failed');

    return {
      success: true,
      results: {
        architectures: archData,
        attacks: attackData,
        healing: healingData
      }
    };

  } catch (error) {
    console.error('  ❌ API test failed:', error);
    return { success: false, results: error };
  }
}

/**
 * Browser-compatible test runner
 */
export async function runAllTests() {
  console.log('🧪 Running comprehensive database tests...');
  
  const databaseTests = await runDatabaseTests();
  const apiTests = await testAPIEndpoints();
  
  console.log('\n📋 Final Test Summary:');
  console.log(`Database Connection: ${databaseTests.database_connection ? '✅' : '❌'}`);
  console.log(`Architecture CRUD: ${Object.values(databaseTests.architectures).every(Boolean) ? '✅' : '❌'}`);
  console.log(`Attack CRUD: ${Object.values(databaseTests.attacks).every(Boolean) ? '✅' : '❌'}`);
  console.log(`Healing CRUD: ${Object.values(databaseTests.healing).every(Boolean) ? '✅' : '❌'}`);
  console.log(`API Endpoints: ${apiTests.success ? '✅' : '❌'}`);

  if (databaseTests.errors.length > 0) {
    console.log('\n🚨 Issues found:');
    databaseTests.errors.forEach(error => console.log(`  - ${error}`));
  }

  return { databaseTests, apiTests };
}

// Make available globally for browser testing
if (typeof window !== 'undefined') {
  (window as any).runAllTests = runAllTests;
  (window as any).runDatabaseTests = runDatabaseTests;
  (window as any).testAPIEndpoints = testAPIEndpoints;
}

/*
Usage Instructions:

1. In Browser Console:
   - Open browser dev tools
   - Run: runAllTests()
   - Or run individual tests: runDatabaseTests(), testAPIEndpoints()

2. In React Component:
   import { runAllTests } from '../lib/test-database';
   
   const handleTest = async () => {
     const results = await runAllTests();
     console.log(results);
   };

3. From command line (if needed):
   node -e "require('./lib/test-database').runAllTests()"
*/