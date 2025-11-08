/**
 * Architecture Storage Model for MongoDB
 * Handles user architectures with versioning support
 * Based on localStorage structure: insightx_architectures, insightx_architecture_list
 */

const mongoose = require('mongoose');

// Network Zone Schema
const NetworkZoneSchema = new mongoose.Schema({
  zone_id: { type: String, required: true },
  name: { type: String, required: true },
  trust_level: { 
    type: String, 
    enum: ['low', 'medium', 'high'], 
    required: true 
  },
  internet_facing: { type: Boolean, required: true },
  color: { type: String }
});

// Architecture Node Schema
const ArchitectureNodeSchema = new mongoose.Schema({
  id: { type: String, required: true },
  type: { type: String, required: true },
  name: { type: String, required: true },
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

// Version Schema - Each version contains a complete architecture snapshot
const ArchitectureVersionSchema = new mongoose.Schema({
  version_name: { type: String, required: true }, // e.g., "v1.0", "v1.1-security-update"
  version_number: { type: Number, required: true },
  created_at: { type: Date, default: Date.now },
  description: { type: String, default: '' },
  is_current: { type: Boolean, default: false },
  
  // Complete architecture data for this version
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
  
  nodes: [ArchitectureNodeSchema],
  connections: [ArchitectureConnectionSchema],
  network_zones: [NetworkZoneSchema],
  
  // Track what triggered this version
  trigger_type: { 
    type: String, 
    enum: ['manual_save', 'attack_mitigation', 'self_healing', 'ai_suggestion'],
    default: 'manual_save'
  },
  trigger_id: { type: String }, // ID of attack or healing session that created this
});

// Main Architecture Storage Schema
const ArchitectureStorageSchema = new mongoose.Schema({
  // User identification
  user_id: { type: String, required: true, default: 'sample_user_123' },
  
  // Architecture identification (same format as localStorage)
  architecture_id: { type: String, required: true, unique: true },
  
  // Current architecture metadata (for quick access)
  current_metadata: {
    company_name: { type: String, required: true },
    architecture_type: { type: String, required: true },
    security_level: { 
      type: String, 
      enum: ['low', 'medium', 'high'], 
      required: true 
    },
    description: { type: String, default: '' }
  },
  
  // All versions of this architecture
  versions: [ArchitectureVersionSchema],
  
  // Auto-save data (temporary unsaved work)
  auto_save: {
    has_unsaved_changes: { type: Boolean, default: false },
    last_auto_save: { type: Date },
    unsaved_data: {
      nodes: [ArchitectureNodeSchema],
      connections: [ArchitectureConnectionSchema],
      network_zones: [NetworkZoneSchema]
    }
  },
  
  // Timestamps
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now },
  last_accessed: { type: Date, default: Date.now }
});

// Indexes for performance
ArchitectureStorageSchema.index({ user_id: 1, architecture_id: 1 });
ArchitectureStorageSchema.index({ user_id: 1, 'current_metadata.company_name': 1 });
ArchitectureStorageSchema.index({ created_at: -1 });
ArchitectureStorageSchema.index({ 'versions.is_current': 1 });

// Instance methods
ArchitectureStorageSchema.methods.getCurrentVersion = function() {
  return this.versions.find(v => v.is_current) || this.versions[this.versions.length - 1];
};

ArchitectureStorageSchema.methods.addNewVersion = function(versionData, triggerType = 'manual_save', triggerId = null) {
  // Mark all existing versions as not current
  this.versions.forEach(v => v.is_current = false);
  
  // Create new version
  const newVersion = {
    version_name: versionData.version_name || `v${this.versions.length + 1}.0`,
    version_number: this.versions.length + 1,
    description: versionData.description || '',
    is_current: true,
    metadata: versionData.metadata,
    nodes: versionData.nodes,
    connections: versionData.connections,
    network_zones: versionData.network_zones,
    trigger_type: triggerType,
    trigger_id: triggerId
  };
  
  this.versions.push(newVersion);
  this.updated_at = new Date();
  
  return newVersion;
};

ArchitectureStorageSchema.methods.saveAutoSave = function(autoSaveData) {
  this.auto_save = {
    has_unsaved_changes: true,
    last_auto_save: new Date(),
    unsaved_data: autoSaveData
  };
  this.last_accessed = new Date();
};

ArchitectureStorageSchema.methods.clearAutoSave = function() {
  this.auto_save.has_unsaved_changes = false;
  this.auto_save.unsaved_data = {
    nodes: [],
    connections: [],
    network_zones: []
  };
};

// Static methods
ArchitectureStorageSchema.statics.findByUserId = function(userId) {
  return this.find({ user_id: userId }).sort({ updated_at: -1 });
};

ArchitectureStorageSchema.statics.createFromLocalStorage = function(localStorageData, userId = 'sample_user_123') {
  const architectureId = this.generateArchitectureId(localStorageData.metadata.company_name);
  
  return new this({
    user_id: userId,
    architecture_id: architectureId,
    current_metadata: {
      company_name: localStorageData.metadata.company_name,
      architecture_type: localStorageData.metadata.architecture_type,
      security_level: localStorageData.metadata.security_level,
      description: localStorageData.metadata.description
    },
    versions: [{
      version_name: 'v1.0',
      version_number: 1,
      description: 'Initial version',
      is_current: true,
      metadata: localStorageData.metadata,
      nodes: localStorageData.nodes,
      connections: localStorageData.connections,
      network_zones: localStorageData.network_zones,
      trigger_type: 'manual_save'
    }]
  });
};

ArchitectureStorageSchema.statics.generateArchitectureId = function(companyName) {
  const cleanName = companyName.toLowerCase().replace(/[^a-z0-9]/g, '_');
  const timestamp = Date.now();
  return `${cleanName}_${timestamp}`;
};

// Pre-save middleware
ArchitectureStorageSchema.pre('save', function(next) {
  this.updated_at = new Date();
  
  // Update current_metadata from current version
  const currentVersion = this.getCurrentVersion();
  if (currentVersion) {
    this.current_metadata = {
      company_name: currentVersion.metadata.company_name,
      architecture_type: currentVersion.metadata.architecture_type,
      security_level: currentVersion.metadata.security_level,
      description: currentVersion.metadata.description
    };
  }
  
  next();
});

module.exports = mongoose.model('ArchitectureStorage', ArchitectureStorageSchema);

/*
Example Usage:

// Create new architecture
const newArchitecture = await ArchitectureStorage.createFromLocalStorage({
  metadata: {
    company_name: "Tech Corp",
    architecture_type: "Web Application",
    security_level: "medium",
    description: "E-commerce platform"
  },
  nodes: [...],
  connections: [...],
  network_zones: [...]
});
await newArchitecture.save();

// Add new version after attack mitigation
architecture.addNewVersion({
  version_name: "v1.1-attack-mitigation",
  description: "Added firewall after port scanning attack",
  metadata: {...},
  nodes: [...],
  connections: [...],
  network_zones: [...]
}, 'attack_mitigation', 'ATK001');
await architecture.save();

// Get user's architectures
const userArchitectures = await ArchitectureStorage.findByUserId('sample_user_123');

// Get current version
const currentVersion = architecture.getCurrentVersion();
*/