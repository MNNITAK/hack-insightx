/**
 * Attack Storage Utilities
 * Handles saving, loading, and managing attack configurations
 */

import {
  AttackData,
  AttackDefinition,
  ConfiguredAttack,
  AttackValidationResult,
  SuggestedArchitecture,
  ArchitectureVersion,
} from '../types/attack';

/**
 * Local Storage Keys
 */
const ATTACK_STORAGE_KEYS = {
  CURRENT_ATTACK: 'insightx_current_attack',
  ATTACK_HISTORY: 'insightx_attack_history',
  VALIDATION_RESULTS: 'insightx_validation_results',
  SUGGESTED_ARCHITECTURES: 'insightx_suggested_architectures',
  ARCHITECTURE_VERSIONS: 'insightx_architecture_versions',
} as const;

/**
 * Attack Storage Manager
 */
export class AttackStorage {
  private static instance: AttackStorage;

  private constructor() {}

  public static getInstance(): AttackStorage {
    if (!AttackStorage.instance) {
      AttackStorage.instance = new AttackStorage();
    }
    return AttackStorage.instance;
  }

  /**
   * Load attack catalog from at.json
   */
  public async loadAttackCatalog(): Promise<AttackData | null> {
    try {
      const response = await fetch('/attack_json/at.json');
      if (!response.ok) {
        throw new Error('Failed to load attack catalog');
      }
      const data: AttackData = await response.json();
      return data;
    } catch (error) {
      console.error('Error loading attack catalog:', error);
      return null;
    }
  }



  /**
   * Save current attack configuration
   */
  public saveCurrentAttack(attack: ConfiguredAttack): boolean {
    if (typeof window === 'undefined') return false;

    try {
      localStorage.setItem(
        ATTACK_STORAGE_KEYS.CURRENT_ATTACK,
        JSON.stringify(attack)
      );
      
      // Save to database as well
      this.saveAttackToDatabase(attack).catch(error => {
        console.warn('Failed to save attack to database:', error);
      });

      // Also add to history
      this.addToHistory(attack);
      
      console.log('✅ Current attack saved:', attack.attack_id);
      return true;
    } catch (error) {
      console.error('Error saving current attack:', error);
      return false;
    }
  }

  /**
   * Load current attack configuration
   */
  public loadCurrentAttack(): ConfiguredAttack | null {
    if (typeof window === 'undefined') return null;

    try {
      const stored = localStorage.getItem(ATTACK_STORAGE_KEYS.CURRENT_ATTACK);
      if (!stored) return null;
      
      return JSON.parse(stored) as ConfiguredAttack;
    } catch (error) {
      console.error('Error loading current attack:', error);
      return null;
    }
  }

  /**
   * Clear current attack
   */
  public clearCurrentAttack(): boolean {
    if (typeof window === 'undefined') return false;

    try {
      localStorage.removeItem(ATTACK_STORAGE_KEYS.CURRENT_ATTACK);
      return true;
    } catch (error) {
      console.error('Error clearing current attack:', error);
      return false;
    }
  }

  /**
   * Add attack to history
   */
  private addToHistory(attack: ConfiguredAttack): void {
    if (typeof window === 'undefined') return;

    try {
      const history = this.getAttackHistory();
      history.push(attack);
      
      // Keep only last 50 attacks
      const limitedHistory = history.slice(-50);
      
      localStorage.setItem(
        ATTACK_STORAGE_KEYS.ATTACK_HISTORY,
        JSON.stringify(limitedHistory)
      );
    } catch (error) {
      console.error('Error adding to attack history:', error);
    }
  }

  /**
   * Get attack history
   */
  public getAttackHistory(): ConfiguredAttack[] {
    if (typeof window === 'undefined') return [];

    try {
      const stored = localStorage.getItem(ATTACK_STORAGE_KEYS.ATTACK_HISTORY);
      if (!stored) return [];
      
      return JSON.parse(stored) as ConfiguredAttack[];
    } catch (error) {
      console.error('Error loading attack history:', error);
      return [];
    }
  }

  /**
   * Save validation result
   */
  public saveValidationResult(result: AttackValidationResult): boolean {
    if (typeof window === 'undefined') return false;

    try {
      const results = this.getValidationResults();
      results[result.attack_id] = result;
      
      localStorage.setItem(
        ATTACK_STORAGE_KEYS.VALIDATION_RESULTS,
        JSON.stringify(results)
      );
      
      // Save to database as well
      this.saveValidationResultToDatabase(result.attack_id, result).catch((error: any) => {
        console.warn('Failed to save validation result to database:', error);
      });
      
      console.log('✅ Validation result saved:', result.attack_id);
      return true;
    } catch (error) {
      console.error('Error saving validation result:', error);
      return false;
    }
  }

  /**
   * Get validation results
   */
  public getValidationResults(): { [attackId: string]: AttackValidationResult } {
    if (typeof window === 'undefined') return {};

    try {
      const stored = localStorage.getItem(ATTACK_STORAGE_KEYS.VALIDATION_RESULTS);
      if (!stored) return {};
      
      return JSON.parse(stored);
    } catch (error) {
      console.error('Error loading validation results:', error);
      return {};
    }
  }

  /**
   * Get validation result for specific attack
   */
  public getValidationResult(attackId: string): AttackValidationResult | null {
    const results = this.getValidationResults();
    return results[attackId] || null;
  }

  /**
   * Save suggested architecture
   */
  public saveSuggestedArchitecture(suggestion: SuggestedArchitecture): boolean {
    if (typeof window === 'undefined') return false;

    try {
      const suggestions = this.getSuggestedArchitectures();
      suggestions.push(suggestion);
      
      localStorage.setItem(
        ATTACK_STORAGE_KEYS.SUGGESTED_ARCHITECTURES,
        JSON.stringify(suggestions)
      );
      
      // Save to database as well
      this.saveSuggestedArchitectureToDatabase(suggestion).catch((error: any) => {
        console.warn('Failed to save suggested architecture to database:', error);
      });
      
      // Update architecture versions
      this.addArchitectureVersion({
        architecture_id: suggestion.new_architecture.id,
        parent_id: suggestion.original_architecture_id,
        version_number: this.getNextVersionNumber(suggestion.original_architecture_id),
        created_at: suggestion.new_architecture.metadata.created_at,
        attack_that_triggered_change: suggestion.attack_mitigation.attack_id,
        is_current: true,
      });
      
      console.log('✅ Suggested architecture saved:', suggestion.new_architecture.id);
      return true;
    } catch (error) {
      console.error('Error saving suggested architecture:', error);
      return false;
    }
  }

  /**
   * Get all suggested architectures
   */
  public getSuggestedArchitectures(): SuggestedArchitecture[] {
    if (typeof window === 'undefined') return [];

    try {
      const stored = localStorage.getItem(ATTACK_STORAGE_KEYS.SUGGESTED_ARCHITECTURES);
      if (!stored) return [];
      
      return JSON.parse(stored) as SuggestedArchitecture[];
    } catch (error) {
      console.error('Error loading suggested architectures:', error);
      return [];
    }
  }

  /**
   * Get suggested architecture by ID
   */
  public getSuggestedArchitecture(architectureId: string): SuggestedArchitecture | null {
    const suggestions = this.getSuggestedArchitectures();
    return suggestions.find((s) => s.new_architecture.id === architectureId) || null;
  }

  /**
   * Add architecture version
   */
  private addArchitectureVersion(version: ArchitectureVersion): void {
    if (typeof window === 'undefined') return;

    try {
      const versions = this.getArchitectureVersions();
      
      // Mark all other versions with same parent as not current
      versions.forEach((v) => {
        if (v.parent_id === version.parent_id) {
          v.is_current = false;
        }
      });
      
      versions.push(version);
      
      localStorage.setItem(
        ATTACK_STORAGE_KEYS.ARCHITECTURE_VERSIONS,
        JSON.stringify(versions)
      );
    } catch (error) {
      console.error('Error adding architecture version:', error);
    }
  }

  /**
   * Get all architecture versions
   */
  public getArchitectureVersions(): ArchitectureVersion[] {
    if (typeof window === 'undefined') return [];

    try {
      const stored = localStorage.getItem(ATTACK_STORAGE_KEYS.ARCHITECTURE_VERSIONS);
      if (!stored) return [];
      
      return JSON.parse(stored) as ArchitectureVersion[];
    } catch (error) {
      console.error('Error loading architecture versions:', error);
      return [];
    }
  }

  /**
   * Get version history for an architecture
   */
  public getVersionHistory(architectureId: string): ArchitectureVersion[] {
    const versions = this.getArchitectureVersions();
    return versions.filter(
      (v) => v.architecture_id === architectureId || v.parent_id === architectureId
    );
  }

  /**
   * Get next version number for an architecture
   */
  private getNextVersionNumber(parentId: string): number {
    const versions = this.getVersionHistory(parentId);
    if (versions.length === 0) return 1;
    
    const maxVersion = Math.max(...versions.map((v) => v.version_number));
    return maxVersion + 1;
  }

  /**
   * Clear all attack data
   */
  public clearAll(): boolean {
    if (typeof window === 'undefined') return false;

    try {
      Object.values(ATTACK_STORAGE_KEYS).forEach((key) => {
        localStorage.removeItem(key);
      });
      console.log('✅ All attack data cleared');
      return true;
    } catch (error) {
      console.error('Error clearing attack data:', error);
      return false;
    }
  }

  /**
   * Database API Methods
   * These methods integrate with the MongoDB backend
   */

  /**
   * Save attack to database via API
   */
  private async saveAttackToDatabase(attack: ConfiguredAttack): Promise<void> {
    try {
      const response = await fetch('/api/attacks', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          user_id: 'sample_user_123',
          configured_attack: attack,
          target_architecture: {
            id: 'current_architecture',
            metadata: {
              company_name: 'Target Architecture',
              architecture_type: 'target',
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
              security_level: 'medium'
            },
            components: [],
            connections: []
          },
          attack_configuration: attack.parameters
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      console.log('✅ Attack saved to database:', result.data?.attack_session_id);
    } catch (error) {
      console.error('Failed to save attack to database:', error);
      throw error;
    }
  }

  /**
   * Save validation result to database via API
   */
  private async saveValidationResultToDatabase(
    attackId: string,
    validationResult: AttackValidationResult
  ): Promise<void> {
    try {
      const response = await fetch('/api/attacks', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          attack_session_id: `migrated_${attackId}_${Date.now()}`,
          user_id: 'sample_user_123',
          validation_result: validationResult,
          attack_status: 'validation_completed'
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      console.log('✅ Validation result saved to database');
    } catch (error) {
      console.error('Failed to save validation result to database:', error);
      throw error;
    }
  }

  /**
   * Save suggested architecture to database via API
   */
  private async saveSuggestedArchitectureToDatabase(
    suggestion: SuggestedArchitecture
  ): Promise<void> {
    try {
      const response = await fetch('/api/attacks', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          attack_session_id: `migrated_${suggestion.attack_mitigation.attack_id}_${Date.now()}`,
          user_id: 'sample_user_123',
          suggested_architecture: suggestion.new_architecture,
          attack_status: 'suggestion_generated'
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      console.log('✅ Suggested architecture saved to database');
    } catch (error) {
      console.error('Failed to save suggested architecture to database:', error);
      throw error;
    }
  }

  /**
   * Get attacks from database via API
   */
  public async getAttacksFromDatabase(userId: string = 'sample_user_123'): Promise<any[]> {
    try {
      const response = await fetch(`/api/attacks?user_id=${userId}&limit=50`);

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      return result.data || [];
    } catch (error) {
      console.error('Failed to fetch attacks from database:', error);
      return [];
    }
  }
}

/**
 * Export singleton instance
 */
export const attackStorage = AttackStorage.getInstance();
