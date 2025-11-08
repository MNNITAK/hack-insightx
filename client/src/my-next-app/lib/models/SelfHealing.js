/**
 * Self Healing Model for MongoDB
 * Handles self-healing processes with before/after architectures and healing results
 * Based on healing functionality in the application
 */

const mongoose = require('mongoose');

// Vulnerability Detection Schema
const VulnerabilitySchema = new mongoose.Schema({
  vulnerability_id: { type: String, required: true },
  vulnerability_type: { 
    type: String, 
    enum: [
      'unencrypted_communication', 'missing_firewall', 'weak_authentication',
      'exposed_database', 'missing_backup', 'insecure_configuration',
      'outdated_software', 'missing_monitoring', 'weak_access_control',
      'data_exposure', 'network_segmentation', 'privilege_escalation'
    ],
    required: true 
  },
  severity: { 
    type: String, 
    enum: ['low', 'medium', 'high', 'critical'],
    required: true 
  },
  affected_components: [{ type: String }], // Component IDs
  description: { type: String, required: true },
  cvss_score: { type: Number, min: 0, max: 10 },
  remediation_priority: { type: Number, min: 1, max: 10, default: 5 },
  detected_at: { type: Date, default: Date.now }
});

// Healing Action Schema
const HealingActionSchema = new mongoose.Schema({
  action_id: { type: String, required: true },
  action_type: { 
    type: String, 
    enum: [
      'add_component', 'modify_component', 'remove_component',
      'add_connection', 'modify_connection', 'remove_connection',
      'update_configuration', 'apply_security_policy'
    ],
    required: true 
  },
  target_component_id: { type: String },
  action_description: { type: String, required: true },
  justification: { type: String, required: true },
  implementation_complexity: { 
    type: String, 
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  estimated_impact: { 
    type: String, 
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  addresses_vulnerabilities: [{ type: String }], // Vulnerability IDs
  
  // Specific action data
  component_data: {
    type: { type: String },
    name: { type: String },
    properties: { type: mongoose.Schema.Types.Mixed },
    position: {
      x: { type: Number },
      y: { type: Number }
    }
  },
  
  connection_data: {
    source: { type: String },
    target: { type: String },
    type: { type: String },
    properties: { type: mongoose.Schema.Types.Mixed }
  },
  
  configuration_changes: { type: mongoose.Schema.Types.Mixed }
});

// Architecture Component Schema (reused from AttackSimulation)
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
    description: { type: String, default: '' }
  },
  components: [ArchitectureComponentSchema],
  connections: [ArchitectureConnectionSchema]
});

// Healing Assessment Schema
const HealingAssessmentSchema = new mongoose.Schema({
  overall_health_score: { type: Number, min: 0, max: 100, required: true },
  security_score: { type: Number, min: 0, max: 100, required: true },
  resilience_score: { type: Number, min: 0, max: 100, required: true },
  compliance_score: { type: Number, min: 0, max: 100, required: true },
  
  improvement_metrics: {
    vulnerabilities_fixed: { type: Number, default: 0 },
    security_controls_added: { type: Number, default: 0 },
    compliance_gaps_closed: { type: Number, default: 0 },
    redundancy_improved: { type: Boolean, default: false }
  },
  
  risk_reduction: {
    before_risk_level: { 
      type: String, 
      enum: ['low', 'medium', 'high', 'critical'],
      required: true 
    },
    after_risk_level: { 
      type: String, 
      enum: ['low', 'medium', 'high', 'critical'],
      required: true 
    },
    risk_reduction_percentage: { type: Number, min: 0, max: 100 }
  },
  
  cost_benefit_analysis: {
    implementation_cost: { 
      type: String, 
      enum: ['low', 'medium', 'high'],
      default: 'medium'
    },
    maintenance_cost: { 
      type: String, 
      enum: ['low', 'medium', 'high'],
      default: 'low'
    },
    roi_timeline: { type: String, default: '3-6 months' }
  }
});

// Main Self Healing Schema
const SelfHealingSchema = new mongoose.Schema({
  // User identification
  user_id: { type: String, required: true, default: 'sample_user_123' },
  
  // Healing session identification
  healing_session_id: { type: String, required: true, unique: true },
  
  // Original architecture (before healing)
  original_architecture: CompleteArchitectureSchema,
  
  // Healed/corrected architecture (after AI healing)
  healed_architecture: {
    type: CompleteArchitectureSchema,
    required: false
  },
  
  // Vulnerability analysis
  detected_vulnerabilities: [VulnerabilitySchema],
  
  // Healing recommendations
  recommended_actions: [HealingActionSchema],
  
  // Applied healing actions (subset of recommended)
  applied_actions: [HealingActionSchema],
  
  // Healing assessment and metrics
  healing_assessment: {
    type: HealingAssessmentSchema,
    required: false
  },
  
  // Healing process status
  healing_status: {
    type: String,
    enum: [
      'initiated', 'analyzing_vulnerabilities', 'generating_recommendations',
      'creating_healed_architecture', 'assessment_complete', 'completed', 'failed'
    ],
    default: 'initiated'
  },
  
  // User decision and feedback
  user_decision: {
    type: String,
    enum: ['pending', 'accepted', 'rejected', 'partially_accepted'],
    default: 'pending'
  },
  accepted_actions: [{ type: String }], // Action IDs that user accepted
  rejected_actions: [{ type: String }], // Action IDs that user rejected
  user_feedback: { type: String },
  
  // Healing trigger information
  trigger_type: {
    type: String,
    enum: ['manual', 'scheduled', 'post_attack', 'compliance_check', 'incident_response'],
    default: 'manual'
  },
  trigger_id: { type: String }, // ID of attack or incident that triggered healing
  
  // Processing and performance metrics
  processing_metrics: {
    vulnerability_scan_time_ms: { type: Number },
    recommendation_generation_time_ms: { type: Number },
    architecture_creation_time_ms: { type: Number },
    total_processing_time_ms: { type: Number }
  },
  
  // AI agent information
  ai_agent_version: { type: String, default: '1.0' },
  ai_confidence_score: { type: Number, min: 0, max: 100 },
  
  // Timestamps
  initiated_at: { type: Date, default: Date.now },
  completed_at: { type: Date },
  accepted_at: { type: Date },
  rejected_at: { type: Date },
  updated_at: { type: Date, default: Date.now }
});

// Indexes for performance
SelfHealingSchema.index({ user_id: 1, initiated_at: -1 });
SelfHealingSchema.index({ healing_session_id: 1 });
SelfHealingSchema.index({ 'original_architecture.id': 1 });
SelfHealingSchema.index({ healing_status: 1 });
SelfHealingSchema.index({ user_decision: 1 });
SelfHealingSchema.index({ trigger_type: 1 });

// Instance methods
SelfHealingSchema.methods.updateStatus = function(status) {
  this.healing_status = status;
  this.updated_at = new Date();
  
  if (status === 'completed') {
    this.completed_at = new Date();
    this.calculateTotalProcessingTime();
  }
};

SelfHealingSchema.methods.acceptHealing = function(acceptedActionIds = []) {
  this.user_decision = acceptedActionIds.length === this.recommended_actions.length ? 
    'accepted' : 'partially_accepted';
  this.accepted_actions = acceptedActionIds;
  this.accepted_at = new Date();
  this.updated_at = new Date();
};

SelfHealingSchema.methods.rejectHealing = function(rejectedActionIds = [], feedback = '') {
  this.user_decision = 'rejected';
  this.rejected_actions = rejectedActionIds;
  this.user_feedback = feedback;
  this.rejected_at = new Date();
  this.updated_at = new Date();
};

SelfHealingSchema.methods.calculateTotalProcessingTime = function() {
  if (this.completed_at && this.initiated_at) {
    this.processing_metrics.total_processing_time_ms = this.completed_at - this.initiated_at;
  }
};

SelfHealingSchema.methods.getEffectivenessScore = function() {
  if (!this.healing_assessment) return 0;
  
  const { before_risk_level, after_risk_level } = this.healing_assessment.risk_reduction;
  const riskLevels = { low: 1, medium: 2, high: 3, critical: 4 };
  
  const beforeScore = riskLevels[before_risk_level] || 0;
  const afterScore = riskLevels[after_risk_level] || 0;
  
  return Math.max(0, Math.round(((beforeScore - afterScore) / beforeScore) * 100));
};

// Static methods
SelfHealingSchema.statics.findByUserId = function(userId) {
  return this.find({ user_id: userId }).sort({ initiated_at: -1 });
};

SelfHealingSchema.statics.findByArchitecture = function(architectureId) {
  return this.find({ 'original_architecture.id': architectureId }).sort({ initiated_at: -1 });
};

SelfHealingSchema.statics.getHealingStatistics = function(userId) {
  return this.aggregate([
    { $match: { user_id: userId } },
    {
      $group: {
        _id: '$trigger_type',
        count: { $sum: 1 },
        accepted: {
          $sum: { $cond: [{ $eq: ['$user_decision', 'accepted'] }, 1, 0] }
        },
        partially_accepted: {
          $sum: { $cond: [{ $eq: ['$user_decision', 'partially_accepted'] }, 1, 0] }
        },
        rejected: {
          $sum: { $cond: [{ $eq: ['$user_decision', 'rejected'] }, 1, 0] }
        },
        avg_processing_time: { $avg: '$processing_metrics.total_processing_time_ms' },
        avg_vulnerabilities_fixed: { $avg: '$healing_assessment.improvement_metrics.vulnerabilities_fixed' }
      }
    }
  ]);
};

SelfHealingSchema.statics.generateHealingSessionId = function(architectureId, triggerType) {
  const timestamp = Date.now();
  return `healing_${triggerType}_${architectureId.slice(-8)}_${timestamp}`;
};

// Pre-save middleware
SelfHealingSchema.pre('save', function(next) {
  this.updated_at = new Date();
  
  // Auto-generate healing_session_id if not provided
  if (!this.healing_session_id && this.original_architecture && this.trigger_type) {
    this.healing_session_id = this.constructor.generateHealingSessionId(
      this.original_architecture.id,
      this.trigger_type
    );
  }
  
  next();
});

module.exports = mongoose.model('SelfHealing', SelfHealingSchema);

/*
Example Usage:

// Create new healing session
const healingSession = new SelfHealing({
  user_id: 'sample_user_123',
  original_architecture: {
    id: 'arch_123',
    metadata: {...},
    components: [...],
    connections: [...]
  },
  trigger_type: 'manual'
});
await healingSession.save();

// Add vulnerability analysis
healingSession.detected_vulnerabilities = [
  {
    vulnerability_id: 'VULN_001',
    vulnerability_type: 'missing_firewall',
    severity: 'high',
    affected_components: ['web-server-1'],
    description: 'Web server exposed without firewall protection',
    cvss_score: 7.5
  }
];
healingSession.updateStatus('analyzing_vulnerabilities');
await healingSession.save();

// Add healing recommendations
healingSession.recommended_actions = [
  {
    action_id: 'ACTION_001',
    action_type: 'add_component',
    action_description: 'Add Web Application Firewall',
    justification: 'Protect web server from direct exposure',
    addresses_vulnerabilities: ['VULN_001'],
    component_data: {
      type: 'firewall',
      name: 'Web Application Firewall',
      properties: {...},
      position: { x: 100, y: 200 }
    }
  }
];
healingSession.updateStatus('generating_recommendations');
await healingSession.save();

// Complete healing with assessment
healingSession.healed_architecture = {
  id: 'arch_123_healed',
  metadata: {...},
  components: [...],
  connections: [...]
};
healingSession.healing_assessment = {
  overall_health_score: 85,
  security_score: 90,
  resilience_score: 80,
  compliance_score: 85,
  risk_reduction: {
    before_risk_level: 'high',
    after_risk_level: 'medium',
    risk_reduction_percentage: 60
  }
};
healingSession.updateStatus('completed');
await healingSession.save();

// Accept healing
healingSession.acceptHealing(['ACTION_001']);
await healingSession.save();

// Get user's healing history
const userHealingSessions = await SelfHealing.findByUserId('sample_user_123');

// Get healing statistics
const stats = await SelfHealing.getHealingStatistics('sample_user_123');

// Get effectiveness score
const effectiveness = healingSession.getEffectivenessScore();
*/