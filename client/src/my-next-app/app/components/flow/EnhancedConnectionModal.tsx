"use client";

import React, { useState } from 'react';

interface EnhancedConnectionModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (config: any) => void; // Using any for now to avoid type conflicts
  connection?: any;
}

interface EnhancedConnectionConfig {
  connection_type: 'database_query' | 'api_call' | 'file_transfer' | 'authentication_flow';
  security_configuration: {
    encryption: {
      enabled: boolean;
      method: string;
    };
    authentication: {
      required: boolean;
      methods: string[];
    };
    access_control: {
      restrictions: string[];
      policies: string[];
    };
  };
  database_operations?: {
    allowed_operations: string[];
    sensitive_data: string[];
    parameterized_queries: boolean;
    query_examples: string[];
  };
  api_endpoints?: {
    public: Array<{
      path: string;
      method: string;
      requires_privilege: string;
      authorization_checks: boolean;
      data_returned: string[];
      vulnerability?: string;
    }>;
  };
  file_transfer_details?: {
    file_types: string[];
    max_size_mb: number;
    antivirus_scanning: boolean;
    path_restrictions: boolean;
  };
  auth_flow_config?: {
    password_policy: {
      min_length: number;
      complexity_required: boolean;
    };
    multi_factor: {
      enabled: boolean;
      methods: string[];
    };
    session_management: {
      session_timeout: string;
      concurrent_sessions: number;
    };
  };
  properties: {
    attack_vectors: {
      [key: string]: {
        vulnerable: boolean;
        method?: string;
        entry_points?: string[];
        restricted_paths?: string[];
      };
    };
  };
}

const EnhancedConnectionModal: React.FC<EnhancedConnectionModalProps> = ({
  isOpen,
  onClose,
  onSave,
  connection
}) => {
  const [activeTab, setActiveTab] = useState('basic');
  const [config, setConfig] = useState<EnhancedConnectionConfig>({
    connection_type: 'database_query',
    security_configuration: {
      encryption: { enabled: true, method: 'TLS 1.3' },
      authentication: { required: true, methods: ['username_password'] },
      access_control: { restrictions: [], policies: [] }
    },
    properties: {
      attack_vectors: {}
    }
  });

  // Database operations state
  const [dbOperations, setDbOperations] = useState<string[]>(['SELECT']);
  const [sensitiveData, setSensitiveData] = useState('');
  const [queryExamples, setQueryExamples] = useState('');
  const [parameterizedQueries, setParameterizedQueries] = useState(true);

  // API endpoints state
  const [apiEndpoint, setApiEndpoint] = useState({ path: '', method: 'GET', auth: true, data: '' });

  // File transfer state
  const [fileTypes, setFileTypes] = useState<string[]>(['images']);
  const [maxSize, setMaxSize] = useState(10);
  const [antivirusScan, setAntivirusScan] = useState(true);
  const [pathRestrictions, setPathRestrictions] = useState(true);

  // Auth flow state
  const [passwordMinLength, setPasswordMinLength] = useState(8);
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [sessionTimeout, setSessionTimeout] = useState('30min');

  // Attack vectors state
  const [attackVectors, setAttackVectors] = useState<{[key: string]: boolean}>({
    sql_injection: false,
    idor: false,
    path_traversal: false,
    xss: false,
    privilege_escalation: false
  });

  if (!isOpen) return null;

  const handleSave = () => {
    // Build configuration based on connection type
    const finalConfig: EnhancedConnectionConfig = {
      ...config,
      properties: {
        attack_vectors: Object.entries(attackVectors).reduce((acc, [key, vulnerable]) => {
          if (vulnerable) {
            acc[key] = { vulnerable: true };
          }
          return acc;
        }, {} as any)
      }
    };

    // Add type-specific configurations
    if (config.connection_type === 'database_query') {
      finalConfig.database_operations = {
        allowed_operations: dbOperations,
        sensitive_data: sensitiveData.split(',').map(s => s.trim()).filter(Boolean),
        parameterized_queries: parameterizedQueries,
        query_examples: queryExamples.split('\n').filter(Boolean)
      };
    } else if (config.connection_type === 'api_call') {
      finalConfig.api_endpoints = {
        public: [{
          path: apiEndpoint.path,
          method: apiEndpoint.method,
          requires_privilege: 'none',
          authorization_checks: apiEndpoint.auth,
          data_returned: apiEndpoint.data.split(',').map(s => s.trim()).filter(Boolean)
        }]
      };
    } else if (config.connection_type === 'file_transfer') {
      finalConfig.file_transfer_details = {
        file_types: fileTypes,
        max_size_mb: maxSize,
        antivirus_scanning: antivirusScan,
        path_restrictions: pathRestrictions
      };
    } else if (config.connection_type === 'authentication_flow') {
      finalConfig.auth_flow_config = {
        password_policy: {
          min_length: passwordMinLength,
          complexity_required: true
        },
        multi_factor: {
          enabled: mfaEnabled,
          methods: mfaEnabled ? ['totp'] : []
        },
        session_management: {
          session_timeout: sessionTimeout,
          concurrent_sessions: 3
        }
      };
    }

    onSave(finalConfig);
    onClose();
  };

  const tabs = [
    { id: 'basic', name: 'Basic', icon: '⚙️' },
    { id: 'security', name: 'Security', icon: '🔒' },
    { id: 'specific', name: 'Type-Specific', icon: '🔧' },
    { id: 'attacks', name: 'Attack Vectors', icon: '⚠️' }
  ];

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 rounded-xl shadow-2xl w-full max-w-4xl max-h-[85vh] overflow-hidden border border-gray-700/50">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-gray-700/50 bg-gradient-to-r from-gray-800 to-gray-900">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center shadow-lg">
              <span className="text-xl">🔒</span>
            </div>
            <div>
              <h2 className="text-xl font-semibold text-white">Enhanced Connection Configuration</h2>
              <p className="text-sm text-gray-400">Configure advanced security settings for this connection</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white hover:bg-gray-700 rounded-full p-2 transition-all duration-200"
          >
            <span className="text-2xl font-light">×</span>
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="border-b border-gray-700/50 bg-gray-900/50">
          <div className="flex overflow-x-auto">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-3 px-6 py-4 text-sm font-medium border-b-2 transition-all duration-200 whitespace-nowrap ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-400 bg-blue-500/10'
                    : 'border-transparent text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
                }`}
              >
                <span className="text-lg">{tab.icon}</span>
                {tab.name}
              </button>
            ))}
          </div>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto max-h-[55vh] bg-gray-900/30">
          {/* Basic Tab */}
          {activeTab === 'basic' && (
            <div className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-200 mb-3">
                  Connection Type
                </label>
                <select
                  value={config.connection_type}
                  onChange={(e) => setConfig(prev => ({ 
                    ...prev, 
                    connection_type: e.target.value as any 
                  }))}
                  className="w-full p-3 bg-gray-800 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all duration-200"
                >
                  <option value="database_query">🗄️ Database Query</option>
                  <option value="api_call">🌐 API Call</option>
                  <option value="file_transfer">📁 File Transfer</option>
                  <option value="authentication_flow">🔐 Authentication Flow</option>
                </select>
              </div>
              
              <div className="p-4 bg-gradient-to-r from-blue-500/10 to-purple-500/10 rounded-lg border border-blue-500/20">
                <h4 className="font-medium text-blue-300 mb-2 flex items-center gap-2">
                  <span>💡</span>
                  Connection Type Details:
                </h4>
                {config.connection_type === 'database_query' && (
                  <p className="text-blue-200 text-sm">Configure database operations, query security, and sensitive data handling.</p>
                )}
                {config.connection_type === 'api_call' && (
                  <p className="text-blue-200 text-sm">Configure API endpoints, authorization requirements, and data exposure settings.</p>
                )}
                {config.connection_type === 'file_transfer' && (
                  <p className="text-blue-200 text-sm">Configure file upload/download security, type restrictions, and scanning policies.</p>
                )}
                {config.connection_type === 'authentication_flow' && (
                  <p className="text-blue-200 text-sm">Configure password policies, multi-factor authentication, and session management.</p>
                )}
              </div>
            </div>
          )}

          {/* Security Tab */}
          {activeTab === 'security' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Encryption Settings */}
                <div className="p-4 bg-gray-800/50 border border-gray-700 rounded-lg">
                  <h3 className="font-semibold mb-3 flex items-center gap-2 text-gray-200">
                    <span className="text-lg">🔒</span>
                    Encryption
                  </h3>
                  <div className="space-y-3">
                    <label className="flex items-center gap-2 text-gray-300 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={config.security_configuration.encryption.enabled}
                        onChange={(e) => setConfig(prev => ({
                          ...prev,
                          security_configuration: {
                            ...prev.security_configuration,
                            encryption: {
                              ...prev.security_configuration.encryption,
                              enabled: e.target.checked
                            }
                          }
                        }))}
                        className="w-4 h-4 text-blue-500 bg-gray-700 border-gray-600 rounded focus:ring-blue-500 focus:ring-2"
                      />
                      Enable Encryption
                    </label>
                    
                    {config.security_configuration.encryption.enabled && (
                      <div>
                        <label className="block text-sm font-medium mb-2 text-gray-300">Encryption Method:</label>
                        <select
                          value={config.security_configuration.encryption.method}
                          onChange={(e) => setConfig(prev => ({
                            ...prev,
                            security_configuration: {
                              ...prev.security_configuration,
                              encryption: {
                                ...prev.security_configuration.encryption,
                                method: e.target.value
                              }
                            }
                          }))}
                          className="w-full p-2 bg-gray-700 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        >
                          <option value="TLS 1.3">TLS 1.3 (Recommended)</option>
                          <option value="TLS 1.2">TLS 1.2</option>
                          <option value="AES-256">AES-256</option>
                          <option value="none">None (Insecure)</option>
                        </select>
                      </div>
                    )}
                  </div>
                </div>

                {/* Authentication Settings */}
                <div className="p-4 bg-gray-800/50 border border-gray-700 rounded-lg">
                  <h3 className="font-semibold mb-3 flex items-center gap-2 text-gray-200">
                    <span className="text-lg">🔐</span>
                    Authentication
                  </h3>
                  <div className="space-y-3">
                    <label className="flex items-center gap-2 text-gray-300 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={config.security_configuration.authentication.required}
                        onChange={(e) => setConfig(prev => ({
                          ...prev,
                          security_configuration: {
                            ...prev.security_configuration,
                            authentication: {
                              ...prev.security_configuration.authentication,
                              required: e.target.checked
                            }
                          }
                        }))}
                        className="w-4 h-4 text-blue-500 bg-gray-700 border-gray-600 rounded focus:ring-blue-500 focus:ring-2"
                      />
                      Require Authentication
                    </label>
                    
                    <div className="text-sm text-gray-400">
                      <p className="mb-2">Available Methods:</p>
                      <ul className="list-disc list-inside space-y-1">
                        <li>Username/Password</li>
                        <li>API Key</li>
                        <li>OAuth2</li>
                        <li>JWT Token</li>
                        <li>Certificate-based</li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Type-Specific Tab */}
          {activeTab === 'specific' && (
            <div className="space-y-6">
              {config.connection_type === 'database_query' && (
                <div className="p-6 bg-gray-800/50 border border-gray-700 rounded-lg">
                  <h3 className="font-semibold mb-4 flex items-center gap-2 text-gray-200">
                    <span className="text-lg">🗄️</span>
                    Database Configuration
                  </h3>
                  
                  <div className="space-y-6">
                    <div>
                      <label className="block text-sm font-medium mb-3 text-gray-200">Allowed Operations:</label>
                      <div className="grid grid-cols-4 gap-3">
                        {['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER', 'GRANT'].map(op => (
                          <label key={op} className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={dbOperations.includes(op)}
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setDbOperations(prev => [...prev, op]);
                                } else {
                                  setDbOperations(prev => prev.filter(o => o !== op));
                                }
                              }}
                              className="w-3 h-3 text-blue-500 bg-gray-700 border-gray-600 rounded focus:ring-blue-500 focus:ring-1"
                            />
                            <span className={op === 'DELETE' || op === 'DROP' || op === 'ALTER' || op === 'GRANT' ? 'text-red-400 font-medium' : 'text-gray-300'}>
                              {op}
                            </span>
                          </label>
                        ))}
                      </div>
                    </div>

                    <div>
                      <label className="block text-sm font-medium mb-2 text-gray-200">Sensitive Data Tables:</label>
                      <input
                        type="text"
                        value={sensitiveData}
                        onChange={(e) => setSensitiveData(e.target.value)}
                        placeholder="users, payments, personal_info, credit_cards"
                        className="w-full p-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                      <p className="text-xs text-gray-400 mt-1">Comma-separated list of table names containing sensitive data</p>
                    </div>

                    <div>
                      <label className="flex items-center gap-2 text-gray-300 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={parameterizedQueries}
                          onChange={(e) => setParameterizedQueries(e.target.checked)}
                          className="w-4 h-4 text-blue-500 bg-gray-700 border-gray-600 rounded focus:ring-blue-500 focus:ring-2"
                        />
                        Use Parameterized Queries (Recommended)
                      </label>
                    </div>

                    <div>
                      <label className="block text-sm font-medium mb-2 text-gray-200">Example Queries:</label>
                      <textarea
                        value={queryExamples}
                        onChange={(e) => setQueryExamples(e.target.value)}
                        placeholder="SELECT * FROM users WHERE id = ?&#10;INSERT INTO logs (user_id, action) VALUES (?, ?)"
                        className="w-full p-3 bg-gray-700 border border-gray-600 rounded-lg h-24 font-mono text-sm text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                      <p className="text-xs text-gray-400 mt-1">One query per line. Use ? for parameters.</p>
                    </div>
                  </div>
                </div>
              )}

              {config.connection_type === 'api_call' && (
                <div className="p-6 bg-gray-800/50 border border-gray-700 rounded-lg">
                  <h3 className="font-semibold mb-4 flex items-center gap-2 text-gray-200">
                    <span className="text-lg">🌐</span>
                    API Configuration
                  </h3>
                  
                  <div className="space-y-6">
                    <div className="grid grid-cols-4 gap-4">
                      <div>
                        <label className="block text-xs font-medium mb-2 text-gray-300">Endpoint:</label>
                        <input
                          type="text"
                          value={apiEndpoint.path}
                          onChange={(e) => setApiEndpoint(prev => ({ ...prev, path: e.target.value }))}
                          placeholder="/api/users/{id}"
                          className="w-full p-2 bg-gray-700 border border-gray-600 rounded text-sm font-mono text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>
                      <div>
                        <label className="block text-xs font-medium mb-2 text-gray-300">Method:</label>
                        <select
                          value={apiEndpoint.method}
                          onChange={(e) => setApiEndpoint(prev => ({ ...prev, method: e.target.value }))}
                          className="w-full p-2 bg-gray-700 border border-gray-600 rounded text-sm text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        >
                          <option value="GET">GET</option>
                          <option value="POST">POST</option>
                          <option value="PUT">PUT</option>
                          <option value="DELETE">DELETE</option>
                          <option value="PATCH">PATCH</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-xs font-medium mb-2 text-gray-300">Auth Required:</label>
                        <div className="pt-2">
                          <input
                            type="checkbox"
                            checked={apiEndpoint.auth}
                            onChange={(e) => setApiEndpoint(prev => ({ ...prev, auth: e.target.checked }))}
                            className="w-4 h-4 text-blue-500 bg-gray-700 border-gray-600 rounded focus:ring-blue-500 focus:ring-2"
                          />
                        </div>
                      </div>
                      <div>
                        <label className="block text-xs font-medium mb-2 text-gray-300">Data Exposed:</label>
                        <input
                          type="text"
                          value={apiEndpoint.data}
                          onChange={(e) => setApiEndpoint(prev => ({ ...prev, data: e.target.value }))}
                          placeholder="email, phone, ssn"
                          className="w-full p-2 bg-gray-700 border border-gray-600 rounded text-sm text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                      </div>
                    </div>
                    <p className="text-xs text-gray-400">Specify sensitive data fields that this endpoint returns (comma-separated)</p>
                  </div>
                </div>
              )}

              {config.connection_type === 'file_transfer' && (
                <div className="p-6 bg-gray-800/50 border border-gray-700 rounded-lg">
                  <h3 className="font-semibold mb-4 flex items-center gap-2 text-gray-200">
                    <span className="text-lg">📁</span>
                    File Transfer Configuration
                  </h3>
                  
                  <div className="space-y-6">
                    <div>
                      <label className="block text-sm font-medium mb-3 text-gray-200">Allowed File Types:</label>
                      <div className="grid grid-cols-3 gap-3">
                        {['images', 'documents', 'executables', 'scripts', 'archives'].map(type => (
                          <label key={type} className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={fileTypes.includes(type)}
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setFileTypes(prev => [...prev, type]);
                                } else {
                                  setFileTypes(prev => prev.filter(t => t !== type));
                                }
                              }}
                              className="w-3 h-3 text-blue-500 bg-gray-700 border-gray-600 rounded focus:ring-blue-500 focus:ring-1"
                            />
                            <span className={type === 'executables' || type === 'scripts' ? 'text-red-400 font-medium' : 'text-gray-300'}>
                              {type}
                            </span>
                          </label>
                        ))}
                      </div>
                      <p className="text-xs text-red-400 mt-2 flex items-center gap-1">
                        <span>⚠️</span>
                        Executables and scripts are high-risk file types
                      </p>
                    </div>

                    <div>
                      <label className="block text-sm font-medium mb-2 text-gray-200">Max File Size (MB):</label>
                      <input
                        type="number"
                        value={maxSize}
                        onChange={(e) => setMaxSize(parseInt(e.target.value) || 10)}
                        min="1"
                        max="1000"
                        className="w-32 p-2 bg-gray-700 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                    </div>

                    <div className="space-y-3">
                      <label className="flex items-center gap-2 text-gray-300 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={antivirusScan}
                          onChange={(e) => setAntivirusScan(e.target.checked)}
                          className="w-4 h-4 text-blue-500 bg-gray-700 border-gray-600 rounded focus:ring-blue-500 focus:ring-2"
                        />
                        Enable Antivirus Scanning (Recommended)
                      </label>

                      <label className="flex items-center gap-2 text-gray-300 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={pathRestrictions}
                          onChange={(e) => setPathRestrictions(e.target.checked)}
                          className="w-4 h-4 text-blue-500 bg-gray-700 border-gray-600 rounded focus:ring-blue-500 focus:ring-2"
                        />
                        Enable Path Restrictions (Recommended)
                      </label>
                    </div>
                  </div>
                </div>
              )}

              {config.connection_type === 'authentication_flow' && (
                <div className="p-6 bg-gray-800/50 border border-gray-700 rounded-lg">
                  <h3 className="font-semibold mb-4 flex items-center gap-2 text-gray-200">
                    <span className="text-lg">🔐</span>
                    Authentication Flow Configuration
                  </h3>
                  
                  <div className="space-y-6">
                    <div className="grid grid-cols-2 gap-6">
                      <div>
                        <label className="block text-sm font-medium mb-2 text-gray-200">Password Min Length:</label>
                        <input
                          type="number"
                          value={passwordMinLength}
                          onChange={(e) => setPasswordMinLength(parseInt(e.target.value) || 8)}
                          min="4"
                          max="128"
                          className="w-full p-2 bg-gray-700 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                        <p className="text-xs text-gray-400 mt-1">Recommended: 12+ characters</p>
                      </div>
                      <div>
                        <label className="block text-sm font-medium mb-2 text-gray-200">Session Timeout:</label>
                        <select
                          value={sessionTimeout}
                          onChange={(e) => setSessionTimeout(e.target.value)}
                          className="w-full p-2 bg-gray-700 border border-gray-600 rounded text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        >
                          <option value="15min">15 minutes</option>
                          <option value="30min">30 minutes</option>
                          <option value="1hour">1 hour</option>
                          <option value="4hours">4 hours</option>
                          <option value="none">No timeout (Insecure)</option>
                        </select>
                      </div>
                    </div>

                    <div>
                      <label className="flex items-center gap-2 text-gray-300 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={mfaEnabled}
                          onChange={(e) => setMfaEnabled(e.target.checked)}
                          className="w-4 h-4 text-blue-500 bg-gray-700 border-gray-600 rounded focus:ring-blue-500 focus:ring-2"
                        />
                        Enable Multi-Factor Authentication (Recommended)
                      </label>
                      {mfaEnabled && (
                        <p className="text-xs text-green-400 mt-2 flex items-center gap-1">
                          <span>✓</span>
                          MFA significantly reduces account compromise risk
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Attack Vectors Tab */}
          {activeTab === 'attacks' && (
            <div className="p-6 bg-gray-800/50 border border-gray-700 rounded-lg">
              <h3 className="font-semibold mb-4 flex items-center gap-2 text-gray-200">
                <span className="text-lg">⚠️</span>
                Vulnerability Assessment
              </h3>
              <p className="text-sm text-gray-400 mb-6">
                Mark any vulnerabilities that this connection is susceptible to. This helps the analysis engine provide more accurate security assessments.
              </p>

              <div className="space-y-4">
                {/* SQL Injection */}
                <div className="flex items-center justify-between p-4 bg-gray-800 border border-gray-700 rounded-lg hover:bg-gray-700/50 transition-colors">
                  <div>
                    <div className="font-medium text-white">SQL Injection</div>
                    <div className="text-sm text-gray-400">Malicious SQL code execution through user input</div>
                  </div>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={attackVectors.sql_injection}
                      onChange={(e) => setAttackVectors(prev => ({ ...prev, sql_injection: e.target.checked }))}
                      className="w-4 h-4 text-red-500 bg-gray-700 border-gray-600 rounded focus:ring-red-500 focus:ring-2"
                    />
                    <span className="text-sm text-gray-300">Vulnerable</span>
                  </label>
                </div>

                {/* IDOR */}
                <div className="flex items-center justify-between p-4 bg-gray-800 border border-gray-700 rounded-lg hover:bg-gray-700/50 transition-colors">
                  <div>
                    <div className="font-medium text-white">IDOR (Insecure Direct Object Reference)</div>
                    <div className="text-sm text-gray-400">Unauthorized access to objects by manipulating parameters</div>
                  </div>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={attackVectors.idor}
                      onChange={(e) => setAttackVectors(prev => ({ ...prev, idor: e.target.checked }))}
                      className="w-4 h-4 text-red-500 bg-gray-700 border-gray-600 rounded focus:ring-red-500 focus:ring-2"
                    />
                    <span className="text-sm text-gray-300">Vulnerable</span>
                  </label>
                </div>

                {/* Path Traversal */}
                <div className="flex items-center justify-between p-4 bg-gray-800 border border-gray-700 rounded-lg hover:bg-gray-700/50 transition-colors">
                  <div>
                    <div className="font-medium text-white">Path Traversal</div>
                    <div className="text-sm text-gray-400">Access to restricted file system paths using directory traversal</div>
                  </div>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={attackVectors.path_traversal}
                      onChange={(e) => setAttackVectors(prev => ({ ...prev, path_traversal: e.target.checked }))}
                      className="w-4 h-4 text-red-500 bg-gray-700 border-gray-600 rounded focus:ring-red-500 focus:ring-2"
                    />
                    <span className="text-sm text-gray-300">Vulnerable</span>
                  </label>
                </div>

                {/* XSS */}
                <div className="flex items-center justify-between p-4 bg-gray-800 border border-gray-700 rounded-lg hover:bg-gray-700/50 transition-colors">
                  <div>
                    <div className="font-medium text-white">Cross-Site Scripting (XSS)</div>
                    <div className="text-sm text-gray-400">Malicious script injection in web applications</div>
                  </div>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={attackVectors.xss}
                      onChange={(e) => setAttackVectors(prev => ({ ...prev, xss: e.target.checked }))}
                      className="w-4 h-4 text-red-500 bg-gray-700 border-gray-600 rounded focus:ring-red-500 focus:ring-2"
                    />
                    <span className="text-sm text-gray-300">Vulnerable</span>
                  </label>
                </div>

                {/* Privilege Escalation */}
                <div className="flex items-center justify-between p-4 bg-gray-800 border border-gray-700 rounded-lg hover:bg-gray-700/50 transition-colors">
                  <div>
                    <div className="font-medium text-white">Privilege Escalation</div>
                    <div className="text-sm text-gray-400">Unauthorized elevation of user permissions</div>
                  </div>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={attackVectors.privilege_escalation}
                      onChange={(e) => setAttackVectors(prev => ({ ...prev, privilege_escalation: e.target.checked }))}
                      className="w-4 h-4 text-red-500 bg-gray-700 border-gray-600 rounded focus:ring-red-500 focus:ring-2"
                    />
                    <span className="text-sm text-gray-300">Vulnerable</span>
                  </label>
                </div>
              </div>

              <div className="mt-6 p-4 bg-gradient-to-r from-yellow-500/10 to-orange-500/10 border border-yellow-500/20 rounded-lg">
                <p className="text-sm text-yellow-200 flex items-center gap-2">
                  <span className="text-lg">💡</span>
                  <strong>Tip:</strong> Marking vulnerabilities helps the rule engine generate more accurate security assessments and recommendations for this connection.
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-end gap-3 p-6 border-t border-gray-700 bg-gray-900/50">
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-300 bg-gray-700 border border-gray-600 rounded-md hover:bg-gray-600 hover:text-white transition-all duration-200"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            className="px-6 py-2 text-white bg-gradient-to-r from-blue-500 to-blue-600 rounded-md hover:from-blue-600 hover:to-blue-700 transition-all duration-200 font-medium shadow-lg shadow-blue-500/25"
          >
            Save Configuration
          </button>
        </div>
      </div>
    </div>
  );
};

export default EnhancedConnectionModal;