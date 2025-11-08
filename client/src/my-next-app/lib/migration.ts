/**
 * MongoDB Migration Script
 * Transfers data from localStorage to MongoDB Atlas
 * Run this script to migrate existing localStorage data to database
 */

import { connectToDatabase } from '../lib/dbConnection';

// Import MongoDB models
const ArchitectureStorage = require('../lib/models/ArchitectureStorage');
const AttackSimulation = require('../lib/models/AttackSimulation');
const SelfHealing = require('../lib/models/SelfHealing');

/**
 * Local Storage Keys (matching the existing application)
 */
const STORAGE_KEYS = {
  // Architecture Storage
  ARCHITECTURES: 'insightx_architectures',
  CURRENT_ARCHITECTURE: 'insightx_current_architecture',
  ARCHITECTURE_LIST: 'insightx_architecture_list',
  
  // Attack Storage
  CURRENT_ATTACK: 'insightx_current_attack',
  ATTACK_HISTORY: 'insightx_attack_history',
  VALIDATION_RESULTS: 'insightx_validation_results',
  SUGGESTED_ARCHITECTURES: 'insightx_suggested_architectures',
  ARCHITECTURE_VERSIONS: 'insightx_architecture_versions',
  
  // Healing Storage (if exists)
  HEALING_SESSIONS: 'insightx_healing_sessions',
  HEALING_HISTORY: 'insightx_healing_history'
} as const;

interface MigrationResult {
  success: boolean;
  migrated: {
    architectures: number;
    attacks: number;
    healingSessions: number;
  };
  errors: string[];
}

/**
 * Main Migration Function
 */
export async function migrateFromLocalStorageToMongoDB(
  userId: string = 'sample_user_123'
): Promise<MigrationResult> {
  const result: MigrationResult = {
    success: false,
    migrated: {
      architectures: 0,
      attacks: 0,
      healingSessions: 0
    },
    errors: []
  };

  try {
    // Connect to MongoDB
    await connectToDatabase();
    console.log('✅ Connected to MongoDB Atlas');

    // Check if running in browser environment
    if (typeof window === 'undefined') {
      result.errors.push('Migration must be run in browser environment with localStorage access');
      return result;
    }

    // Migrate Architectures
    result.migrated.architectures = await migrateArchitectures(userId);
    console.log(`✅ Migrated ${result.migrated.architectures} architectures`);

    // Migrate Attack Simulations
    result.migrated.attacks = await migrateAttackSimulations(userId);
    console.log(`✅ Migrated ${result.migrated.attacks} attack simulations`);

    // Migrate Healing Sessions
    result.migrated.healingSessions = await migrateHealingSessions(userId);
    console.log(`✅ Migrated ${result.migrated.healingSessions} healing sessions`);

    result.success = true;
    console.log('🎉 Migration completed successfully!');

  } catch (error) {
    console.error('❌ Migration failed:', error);
    result.errors.push(error instanceof Error ? error.message : 'Unknown error');
  }

  return result;
}

/**
 * Migrate Architecture Storage Data
 */
async function migrateArchitectures(userId: string): Promise<number> {
  let migratedCount = 0;

  try {
    // Get architectures from localStorage
    const architecturesData = localStorage.getItem(STORAGE_KEYS.ARCHITECTURES);
    const currentArchitecture = localStorage.getItem(STORAGE_KEYS.CURRENT_ARCHITECTURE);

    if (architecturesData) {
      const architectures = JSON.parse(architecturesData);
      
      for (const [architectureId, architecture] of Object.entries(architectures)) {
        try {
          const architectureData = architecture as any;
          
          // Create ArchitectureStorage document
          const newArchitectureStorage = new ArchitectureStorage({
            user_id: userId,
            architecture_id: architectureId,
            current_version: {
              version_number: 1,
              architecture_data: architectureData,
              metadata: {
                name: architectureData.metadata?.company_name || 'Migrated Architecture',
                description: architectureData.metadata?.description || 'Migrated from localStorage',
                tags: architectureData.metadata?.architecture_type ? [architectureData.metadata.architecture_type] : []
              },
              trigger_info: {
                trigger_type: 'migration',
                notes: 'Migrated from localStorage'
              }
            },
            version_history: [{
              version_number: 1,
              architecture_data: architectureData,
              metadata: {
                name: architectureData.metadata?.company_name || 'Migrated Architecture',
                description: architectureData.metadata?.description || 'Migrated from localStorage',
                tags: architectureData.metadata?.architecture_type ? [architectureData.metadata.architecture_type] : []
              },
              trigger_info: {
                trigger_type: 'migration',
                notes: 'Initial version from migration'
              },
              created_at: new Date(architectureData.metadata?.created_at || Date.now())
            }]
          });

          await newArchitectureStorage.save();
          migratedCount++;
          
        } catch (error) {
          console.warn(`Failed to migrate architecture ${architectureId}:`, error);
        }
      }
    }

    // Handle current architecture (auto-save)
    if (currentArchitecture) {
      try {
        const archData = JSON.parse(currentArchitecture);
        
        const autoSaveArchitecture = new ArchitectureStorage({
          user_id: userId,
          architecture_id: 'auto_save_' + Date.now(),
          current_version: {
            version_number: 1,
            architecture_data: archData,
            metadata: {
              name: 'Auto-saved Architecture',
              description: 'Auto-saved work from localStorage',
              tags: ['auto-save']
            },
            trigger_info: {
              trigger_type: 'auto_save',
              notes: 'Migrated auto-save from localStorage'
            }
          },
          is_auto_save: true
        });

        await autoSaveArchitecture.save();
        migratedCount++;
        
      } catch (error) {
        console.warn('Failed to migrate current architecture:', error);
      }
    }

  } catch (error) {
    console.error('Error migrating architectures:', error);
  }

  return migratedCount;
}

/**
 * Migrate Attack Simulation Data
 */
async function migrateAttackSimulations(userId: string): Promise<number> {
  let migratedCount = 0;

  try {
    // Get attack data from localStorage
    const attackHistory = localStorage.getItem(STORAGE_KEYS.ATTACK_HISTORY);
    const validationResults = localStorage.getItem(STORAGE_KEYS.VALIDATION_RESULTS);
    const suggestedArchitectures = localStorage.getItem(STORAGE_KEYS.SUGGESTED_ARCHITECTURES);

    const attacks = attackHistory ? JSON.parse(attackHistory) : [];
    const validations = validationResults ? JSON.parse(validationResults) : {};
    const suggestions = suggestedArchitectures ? JSON.parse(suggestedArchitectures) : [];

    // Create mapping of attack IDs to their data
    const attackMap = new Map();
    
    // Process attack history
    for (const attack of attacks) {
      attackMap.set(attack.attack_id, {
        configured_attack: attack,
        validation_result: validations[attack.attack_id] || null,
        suggested_architecture: null
      });
    }

    // Add suggested architectures
    for (const suggestion of suggestions) {
      const attackId = suggestion.attack_mitigation?.attack_id;
      if (attackId && attackMap.has(attackId)) {
        attackMap.get(attackId).suggested_architecture = suggestion;
      }
    }

    // Create AttackSimulation documents
    for (const [attackId, attackData] of attackMap.entries()) {
      try {
        const newAttackSimulation = new AttackSimulation({
          user_id: userId,
          attack_session_id: `migrated_${attackId}_${Date.now()}`,
          configured_attack: attackData.configured_attack,
          target_architecture: {
            // Extract architecture from attack configuration
            id: attackData.configured_attack.target_architecture_id || 'unknown',
            metadata: {
              company_name: 'Migrated Target',
              architecture_type: 'migrated',
              created_at: new Date(),
              updated_at: new Date(),
              security_level: 'medium'
            },
            components: [], // Will be empty for migrated data
            connections: []
          },
          attack_configuration: {
            attack_parameters: attackData.configured_attack.attack_parameters || {},
            environment_setup: attackData.configured_attack.environment_setup || {}
          },
          validation_result: attackData.validation_result,
          suggested_architecture: attackData.suggested_architecture?.new_architecture || null,
          attack_status: 'completed',
          user_decision: attackData.suggested_architecture ? 'pending' : 'no_suggestion',
          processing_metrics: {
            total_processing_time_ms: 0 // Not available from localStorage
          }
        });

        await newAttackSimulation.save();
        migratedCount++;
        
      } catch (error) {
        console.warn(`Failed to migrate attack ${attackId}:`, error);
      }
    }

  } catch (error) {
    console.error('Error migrating attack simulations:', error);
  }

  return migratedCount;
}

/**
 * Migrate Healing Session Data
 */
async function migrateHealingSessions(userId: string): Promise<number> {
  let migratedCount = 0;

  try {
    // Check if healing data exists in localStorage
    const healingData = localStorage.getItem(STORAGE_KEYS.HEALING_SESSIONS);
    
    if (healingData) {
      const healingSessions = JSON.parse(healingData);
      
      for (const session of healingSessions) {
        try {
          const newHealingSession = new SelfHealing({
            user_id: userId,
            healing_session_id: `migrated_healing_${session.id || Date.now()}`,
            original_architecture: session.original_architecture || {
              id: 'unknown',
              metadata: {
                company_name: 'Migrated Architecture',
                architecture_type: 'migrated',
                created_at: new Date(),
                updated_at: new Date(),
                security_level: 'medium'
              },
              components: [],
              connections: []
            },
            healed_architecture: session.healed_architecture || null,
            detected_vulnerabilities: session.detected_vulnerabilities || [],
            recommended_actions: session.recommended_actions || [],
            healing_assessment: session.healing_assessment || null,
            healing_status: session.status || 'completed',
            user_decision: session.user_decision || 'pending',
            trigger_type: 'migration'
          });

          await newHealingSession.save();
          migratedCount++;
          
        } catch (error) {
          console.warn('Failed to migrate healing session:', error);
        }
      }
    }

  } catch (error) {
    console.error('Error migrating healing sessions:', error);
  }

  return migratedCount;
}

/**
 * Clear localStorage after successful migration
 */
export function clearLocalStorageAfterMigration(): void {
  try {
    if (typeof window === 'undefined') {
      console.warn('Cannot clear localStorage in server environment');
      return;
    }

    const keysToRemove = Object.values(STORAGE_KEYS);
    keysToRemove.forEach(key => {
      localStorage.removeItem(key);
    });

    console.log('✅ localStorage cleared after migration');
  } catch (error) {
    console.error('Error clearing localStorage:', error);
  }
}

/**
 * Validate migration by checking database content
 */
export async function validateMigration(userId: string = 'sample_user_123'): Promise<{
  architectures: number;
  attacks: number;
  healingSessions: number;
}> {
  try {
    await connectToDatabase();

    const architecturesCount = await ArchitectureStorage.countDocuments({ user_id: userId });
    const attacksCount = await AttackSimulation.countDocuments({ user_id: userId });
    const healingCount = await SelfHealing.countDocuments({ user_id: userId });

    return {
      architectures: architecturesCount,
      attacks: attacksCount,
      healingSessions: healingCount
    };
  } catch (error) {
    console.error('Error validating migration:', error);
    return { architectures: 0, attacks: 0, healingSessions: 0 };
  }
}

/**
 * Browser-compatible migration runner
 * Call this function from browser console or a React component
 */
export async function runMigration(userId?: string) {
  console.log('🚀 Starting localStorage to MongoDB migration...');
  
  const result = await migrateFromLocalStorageToMongoDB(userId);
  
  if (result.success) {
    console.log('✅ Migration completed successfully!');
    console.log('📊 Migration Summary:', result.migrated);
    
    // Validate the migration
    const validation = await validateMigration(userId);
    console.log('✔️ Database Validation:', validation);
    
    // Ask user if they want to clear localStorage
    const shouldClear = confirm(
      'Migration completed! Do you want to clear localStorage data? ' +
      '(Recommended after successful migration)'
    );
    
    if (shouldClear) {
      clearLocalStorageAfterMigration();
    }
  } else {
    console.error('❌ Migration failed!');
    console.error('Errors:', result.errors);
  }
  
  return result;
}

// Export for use in React components or direct browser usage
if (typeof window !== 'undefined') {
  (window as any).runMigration = runMigration;
}

/*
Usage Instructions:

1. In Browser Console:
   - Open browser dev tools
   - Go to Console tab
   - Run: runMigration()
   - Or: runMigration('your_user_id')

2. In React Component:
   import { runMigration } from '../utils/migration';
   
   const handleMigration = async () => {
     const result = await runMigration('user_123');
     console.log(result);
   };

3. Validation Only:
   import { validateMigration } from '../utils/migration';
   
   const counts = await validateMigration('user_123');
   console.log(counts);
*/