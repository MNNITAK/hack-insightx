/**
 * Attack Type Definitions
 * Based on at.json attack catalog structure
 */

export type AttackCategory =
  | 'reconnaissance'
  | 'initial_access'
  | 'execution'
  | 'persistence'
  | 'privilege_escalation'
  | 'defense_evasion'
  | 'credential_access'
  | 'discovery'
  | 'lateral_movement'
  | 'collection'
  | 'exfiltration'
  | 'impact'
  | 'command_and_control';

export type AttackDifficulty = 'easy' | 'medium' | 'hard';
export type DetectionDifficulty = 'easy' | 'medium' | 'hard';

/**
 * User Configurable Parameter Types
 */
export type ParameterType =
  | 'text'
  | 'textarea'
  | 'number'
  | 'select'
  | 'multiselect'
  | 'boolean'
  | 'slider'
  | 'node_selector';

export interface BaseParameter {
  type: ParameterType;
  label: string;
  description?: string;
  required?: boolean;
  optional?: boolean;
}

export interface TextParameter extends BaseParameter {
  type: 'text' | 'textarea';
  default?: string;
}

export interface NumberParameter extends BaseParameter {
  type: 'number' | 'slider';
  default: number;
  min: number;
  max: number;
}

export interface SelectParameter extends BaseParameter {
  type: 'select';
  options: string[];
  default: string;
}

export interface MultiSelectParameter extends BaseParameter {
  type: 'multiselect';
  options: string[];
  default: string[];
}

export interface BooleanParameter extends BaseParameter {
  type: 'boolean';
  default: boolean;
}

export interface NodeSelectorParameter extends BaseParameter {
  type: 'node_selector';
  filter?: string;
  multiple?: boolean;
}

export type AttackParameter =
  | TextParameter
  | NumberParameter
  | SelectParameter
  | MultiSelectParameter
  | BooleanParameter
  | NodeSelectorParameter;

/**
 * Attack Pattern Structure
 */
export interface DetectionIndicators {
  [key: string]: boolean | string | number;
}

export interface AttackEvent {
  event_type: string;
  target_property?: string;
  detection_indicators: DetectionIndicators;
}

export interface AttackStage {
  stage: number;
  name: string;
  events: AttackEvent[];
}

export interface AttackPattern {
  stages: AttackStage[];
}

/**
 * Architecture Vulnerabilities
 */
export interface ArchitectureVulnerabilities {
  [key: string]: boolean;
}

/**
 * Success Conditions
 */
export interface SuccessConditions {
  [key: string]: boolean | string;
}

/**
 * Expected AI Detections
 */
export interface ExpectedAIDetection {
  detection_type: string;
  confidence_threshold: number;
  detection_time_seconds: number;
}

/**
 * Attack Definition (from at.json)
 */
export interface AttackDefinition {
  attack_id: string;
  attack_name: string;
  category: AttackCategory;
  difficulty: AttackDifficulty;
  mitre_attack_id: string;
  description: string;
  typical_duration_seconds: number;
  detection_difficulty: DetectionDifficulty;
  user_configurable_parameters: {
    [key: string]: AttackParameter;
  };
  attack_pattern: AttackPattern;
  success_conditions?: SuccessConditions;
  expected_ai_detections?: ExpectedAIDetection[];
  architecture_vulnerabilities: ArchitectureVulnerabilities;
  vulnerability_requirements?: {
    [key: string]: boolean;
  };
  impact?: {
    [key: string]: boolean;
  };
}

/**
 * Attack Catalog
 */
export interface AttackCatalog {
  version: string;
  last_updated: string;
  total_attacks: number;
  categories: AttackCategory[];
}

/**
 * Complete Attack Data Structure
 */
export interface AttackData {
  attack_catalog: AttackCatalog;
  attacks: AttackDefinition[];
}

/**
 * User-Configured Attack Instance
 */
export interface ConfiguredAttack {
  attack_id: string;
  attack_name: string;
  category: AttackCategory;
  configured_at: string;
  parameters: {
    [key: string]: any; // Actual values filled by user
  };
}

/**
 * Attack Validation Result (from validator agent)
 */
export interface AttackValidationResult {
  is_valid: boolean;
  attack_id: string;
  validation_timestamp: string;
  missing_components: string[];
  security_analysis: {
    overall_security_level: 'low' | 'medium' | 'high';
    vulnerability_score: number; // 0-100
    reason: string;
    affected_nodes: string[];
    recommended_actions: string[];
  };
  can_proceed: boolean;
  error_message?: string;
}

/**
 * Agent Response - New Architecture Suggestion
 */
export interface SuggestedArchitecture {
  original_architecture_id: string;
  new_architecture: {
    id: string;
    metadata: {
      company_name: string;
      architecture_type: string;
      created_at: string;
      updated_at: string;
      security_level: 'low' | 'medium' | 'high';
      description: string;
      parent_architecture_id?: string; // Reference to original
    };
    components: any[]; // Node data
    connections: any[]; // Edge data
  };
  change_summary: {
    total_changes: number;
    added_components: Array<{
      id: string;
      type: string;
      label: string;
      reason: string;
    }>;
    modified_components: Array<{
      id: string;
      changes: string[];
      reason: string;
    }>;
    removed_components: Array<{
      id: string;
      reason: string;
    }>;
    added_connections: Array<{
      source: string;
      target: string;
      reason: string;
    }>;
    security_improvements: string[];
    mitigated_vulnerabilities: string[];
  };
  attack_mitigation: {
    attack_id: string;
    attack_name: string;
    prevented: boolean;
    mitigation_techniques: string[];
  };
}

/**
 * Architecture Version Tracking
 */
export interface ArchitectureVersion {
  architecture_id: string;
  parent_id: string | null;
  version_number: number;
  created_at: string;
  attack_that_triggered_change: string;
  is_current: boolean;
}
