/**
 * Attack Simulation Model for MongoDB
 * Handles attack simulations with original/suggested architectures and results
 * Based on localStorage: insightx_attack_history, insightx_suggested_architectures
 */

const mongoose = require('mongoose');

// Attack Parameter Schema
const AttackParameterSchema = new mongoose.Schema({
  parameter_name: { type: String, required: true },
  parameter_value: { type: mongoose.Schema.Types.Mixed, required: true },
  parameter_type: { 
    type: String, 
    enum: ['text', 'textarea', 'number', 'select', 'multiselect', 'boolean', 'slider', 'node_selector'],
    required: true 
  }
});

// Configured Attack Schema
const ConfiguredAttackSchema = new mongoose.Schema({
  attack_id: { type: String, required: true }, // e.g., "ATK001"
  attack_name: { type: String, required: true },
  category: { 
    type: String, 
    enum: [
      'reconnaissance', 'initial_access', 'execution', 'persistence',
      'privilege_escalation', 'defense_evasion', 'credential_access',
      'discovery', 'lateral_movement', 'collection', 'exfiltration',
      'impact', 'command_and_control'
    ],
    required: true 
  },
  difficulty: { 
    type: String, 
    enum: ['easy', 'medium', 'hard'],
    required: true 
  },
  mitre_attack_id: { type: String, required: true },
  description: { type: String, required: true },
  configured_at: { type: Date, required: true },
  parameters: [AttackParameterSchema]
});

// Architecture Component Schema (for storing both original and suggested)
const ArchitectureComponentSchema = new mongoose.Schema({
  id: { type: String, required: true },
  type: { type: String, required: true },
  name: { type: String, required: true },
  label: { type: String },
  category: { type: String },
  description: { type: String },
  properties: { type: mongoose.Schema.Types.Mixed, default: {} },
  position: {
    x: { type: Number, required: true },
    y: { type: Number, required: true },
    zone: { type: String, default: 'default' }
  }
});

// Architecture Connection Schema
const ArchitectureConnectionSchema = new mongoose.Schema({
  id: { type: String, required: true },
  source: { type: String, required: true },
  target: { type: String, required: true },
  type: { type: String, required: true },
  properties: { type: mongoose.Schema.Types.Mixed, default: {} }
});

// Complete Architecture Schema
const CompleteArchitectureSchema = new mongoose.Schema({
  id: { type: String, required: true },
  metadata: {
    company_name: { type: String, required: true },
    architecture_type: { type: String, required: true },
    created_at: { type: Date, required: true },
    updated_at: { type: Date, default: Date.now },
    security_level: { 
      type: String, 
      enum: ['low', 'medium', 'high'], 
      required: true 
    },
    description: { type: String, default: '' },
    parent_architecture_id: { type: String } // Reference to original if this is suggested
  },
  components: [ArchitectureComponentSchema],
  connections: [ArchitectureConnectionSchema]
});

// Validation Result Schema
const ValidationResultSchema = new mongoose.Schema({
  is_valid: { type: Boolean, required: true },
  validation_timestamp: { type: Date, required: true },
  missing_components: [{ type: String }],
  security_analysis: {
    overall_security_level: { 
      type: String, 
      enum: ['low', 'medium', 'high'], 
      required: true 
    },
    vulnerability_score: { type: Number, min: 0, max: 100, required: true },
    reason: { type: String, required: true },
    affected_nodes: [{ type: String }],
    recommended_actions: [{ type: String }]
  },
  can_proceed: { type: Boolean, required: true },
  error_message: { type: String }
});

// Change Summary Schema
const ChangeSummarySchema = new mongoose.Schema({
  total_changes: { type: Number, required: true, default: 0 },
  added_components: [{
    id: { type: String, required: true },
    type: { type: String, required: true },
    label: { type: String, required: true },
    reason: { type: String, required: true }
  }],
  modified_components: [{
    id: { type: String, required: true },
    changes: [{ type: String }],
    reason: { type: String, required: true }
  }],
  removed_components: [{
    id: { type: String, required: true },
    reason: { type: String, required: true }
  }],
  added_connections: [{
    source: { type: String, required: true },
    target: { type: String, required: true },
    reason: { type: String, required: true }
  }],
  security_improvements: [{ type: String }],
  mitigated_vulnerabilities: [{ type: String }]
});

// Attack Mitigation Schema
const AttackMitigationSchema = new mongoose.Schema({
  attack_id: { type: String, required: true },
  attack_name: { type: String, required: true },
  prevented: { type: Boolean, required: true },
  mitigation_techniques: [{ type: String }],
  effectiveness_score: { type: Number, min: 0, max: 100, default: 0 },
  residual_risk: { 
    type: String, 
    enum: ['low', 'medium', 'high'],
    default: 'low'
  }
});

// Main Attack Simulation Schema
const AttackSimulationSchema = new mongoose.Schema({
  // User identification
  user_id: { type: String, required: true, default: 'sample_user_123' },
  
  // Simulation identification
  simulation_id: { type: String, required: true, unique: true },
  
  // Attack configuration
  configured_attack: ConfiguredAttackSchema,
  
  // Original architecture (before attack)
  original_architecture: CompleteArchitectureSchema,
  
  // Suggested/improved architecture (after AI analysis)
  suggested_architecture: {
    type: CompleteArchitectureSchema,
    required: false
  },
  
  // Attack validation results
  validation_result: {
    type: ValidationResultSchema,
    required: false
  },
  
  // Change analysis
  change_summary: {
    type: ChangeSummarySchema,
    required: false
  },
  
  // Attack mitigation details
  attack_mitigation: {
    type: AttackMitigationSchema,
    required: false
  },
  
  // Simulation status and results
  simulation_status: {
    type: String,
    enum: ['configured', 'validating', 'validated', 'generating_suggestion', 'completed', 'failed'],
    default: 'configured'
  },
  
  // User decision
  user_decision: {
    type: String,
    enum: ['pending', 'accepted', 'rejected'],
    default: 'pending'
  },
  accepted_at: { type: Date },
  rejected_at: { type: Date },
  
  // Processing time metrics
  processing_time: {
    validation_ms: { type: Number },
    suggestion_generation_ms: { type: Number },
    total_ms: { type: Number }
  },
  
  // Timestamps
  created_at: { type: Date, default: Date.now },
  completed_at: { type: Date },
  updated_at: { type: Date, default: Date.now }
});

// Indexes for performance
AttackSimulationSchema.index({ user_id: 1, created_at: -1 });
AttackSimulationSchema.index({ simulation_id: 1 });
AttackSimulationSchema.index({ 'configured_attack.attack_id': 1 });
AttackSimulationSchema.index({ 'original_architecture.id': 1 });
AttackSimulationSchema.index({ simulation_status: 1 });
AttackSimulationSchema.index({ user_decision: 1 });

// Instance methods
AttackSimulationSchema.methods.updateStatus = function(status) {
  this.simulation_status = status;
  this.updated_at = new Date();
  
  if (status === 'completed') {
    this.completed_at = new Date();
  }
};

AttackSimulationSchema.methods.acceptSuggestion = function() {
  this.user_decision = 'accepted';
  this.accepted_at = new Date();
  this.updated_at = new Date();
};

AttackSimulationSchema.methods.rejectSuggestion = function() {
  this.user_decision = 'rejected';
  this.rejected_at = new Date();
  this.updated_at = new Date();
};

AttackSimulationSchema.methods.calculateProcessingTime = function() {
  if (this.completed_at && this.created_at) {
    this.processing_time.total_ms = this.completed_at - this.created_at;
  }
};

// Static methods
AttackSimulationSchema.statics.findByUserId = function(userId) {
  return this.find({ user_id: userId }).sort({ created_at: -1 });
};

AttackSimulationSchema.statics.findByAttackId = function(attackId) {
  return this.find({ 'configured_attack.attack_id': attackId }).sort({ created_at: -1 });
};

AttackSimulationSchema.statics.findByArchitecture = function(architectureId) {
  return this.find({ 'original_architecture.id': architectureId }).sort({ created_at: -1 });
};

AttackSimulationSchema.statics.getAttackStatistics = function(userId) {
  return this.aggregate([
    { $match: { user_id: userId } },
    {
      $group: {
        _id: '$configured_attack.category',
        count: { $sum: 1 },
        accepted: {
          $sum: { $cond: [{ $eq: ['$user_decision', 'accepted'] }, 1, 0] }
        },
        rejected: {
          $sum: { $cond: [{ $eq: ['$user_decision', 'rejected'] }, 1, 0] }
        },
        avg_processing_time: { $avg: '$processing_time.total_ms' }
      }
    }
  ]);
};

AttackSimulationSchema.statics.generateSimulationId = function(attackId, architectureId) {
  const timestamp = Date.now();
  return `sim_${attackId}_${architectureId.slice(-8)}_${timestamp}`;
};

// Pre-save middleware
AttackSimulationSchema.pre('save', function(next) {
  this.updated_at = new Date();
  
  // Auto-generate simulation_id if not provided
  if (!this.simulation_id && this.configured_attack && this.original_architecture) {
    this.simulation_id = this.constructor.generateSimulationId(
      this.configured_attack.attack_id,
      this.original_architecture.id
    );
  }
  
  next();
});

module.exports = mongoose.model('AttackSimulation', AttackSimulationSchema);

/*
Example Usage:

// Create new attack simulation
const simulation = new AttackSimulation({
  user_id: 'sample_user_123',
  configured_attack: {
    attack_id: 'ATK001',
    attack_name: 'Port Scanning',
    category: 'reconnaissance',
    difficulty: 'easy',
    mitre_attack_id: 'T1046',
    description: 'Network port scanning attack',
    configured_at: new Date(),
    parameters: [
      {
        parameter_name: 'target_node',
        parameter_value: 'web-server-1',
        parameter_type: 'node_selector'
      }
    ]
  },
  original_architecture: {
    id: 'arch_123',
    metadata: {...},
    components: [...],
    connections: [...]
  }
});
await simulation.save();

// Update with validation result
simulation.validation_result = {
  is_valid: true,
  validation_timestamp: new Date(),
  missing_components: [],
  security_analysis: {...},
  can_proceed: true
};
simulation.updateStatus('validated');
await simulation.save();

// Add suggested architecture
simulation.suggested_architecture = {
  id: 'arch_123_improved',
  metadata: {...},
  components: [...],
  connections: [...]
};
simulation.change_summary = {...};
simulation.attack_mitigation = {...};
simulation.updateStatus('completed');
await simulation.save();

// Accept suggestion
simulation.acceptSuggestion();
await simulation.save();

// Get user's attack history
const userAttacks = await AttackSimulation.findByUserId('sample_user_123');

// Get statistics
const stats = await AttackSimulation.getAttackStatistics('sample_user_123');
*/