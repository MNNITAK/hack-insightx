/**
 * Agent Integration Service
 * Communicates with Python backend agents for attack validation and architecture correction
 */

import {
  ConfiguredAttack,
  AttackValidationResult,
  SuggestedArchitecture,
} from '../types/attack';
import { Architecture } from '../types';

/**
 * Agent API Client
 */
export class AgentService {
  private static instance: AgentService;
  private apiBaseUrl: string;

  private constructor() {
    // Python backend URL
    this.apiBaseUrl = process.env.NEXT_PUBLIC_AGENT_API_URL || 'http://localhost:5000/api';
  }

  public static getInstance(): AgentService {
    if (!AgentService.instance) {
      AgentService.instance = new AgentService();
    }
    return AgentService.instance;
  }

  /**
   * Validate if attack is possible on current architecture
   */
  public async validateAttack(
    attack: ConfiguredAttack,
    architecture: Architecture
  ): Promise<AttackValidationResult> {
    try {
      console.log('🔍 Validating attack:', attack.attack_id);

      // Call real Python backend
      const response = await this.callPythonAPI('validate-attack', {
        attack,
        architecture,
      });
      
      return response as AttackValidationResult;
    } catch (error) {
      console.error('Error validating attack:', error);
      // Fallback to simulation if backend is unavailable
      return this.simulateValidation(attack, architecture);
    }
  }

  /**
   * Get corrected architecture from agent
   */
  public async getCorrectedArchitecture(
    attack: ConfiguredAttack,
    architecture: Architecture
  ): Promise<SuggestedArchitecture> {
    try {
      console.log('🏗️ Getting corrected architecture for attack:', attack.attack_id);

      // Call real Python backend
      const response = await this.callPythonAPI('correct-architecture', {
        attack,
        architecture,
      });
      
      return response as SuggestedArchitecture;
    } catch (error) {
      console.error('Error getting corrected architecture:', error);
      // Fallback to simulation if backend is unavailable
      return this.simulateCorrectedArchitecture(attack, architecture);
    }
  }

  /**
   * Simulate attack validation (replace with actual API call)
   */
  private simulateValidation(
    attack: ConfiguredAttack,
    architecture: Architecture
  ): AttackValidationResult {
    // Check if target nodes exist in architecture
    const targetNode = attack.parameters.target_node;
    const missingComponents: string[] = [];
    
    if (targetNode && !architecture.nodes.find((c: any) => c.id === targetNode)) {
      missingComponents.push(`Target node: ${targetNode}`);
    }

    // Simple validation logic
    const isValid = missingComponents.length === 0;
    const vulnerabilityScore = isValid ? 75 : 30;

    return {
      is_valid: isValid,
      attack_id: attack.attack_id,
      validation_timestamp: new Date().toISOString(),
      missing_components: missingComponents,
      security_analysis: {
        overall_security_level: vulnerabilityScore > 60 ? 'low' : vulnerabilityScore > 30 ? 'medium' : 'high',
        vulnerability_score: vulnerabilityScore,
        reason: isValid
          ? `Your architecture is vulnerable to ${attack.attack_name}. The system lacks proper security controls.`
          : `This attack cannot be executed because required components are missing: ${missingComponents.join(', ')}`,
        affected_nodes: isValid ? [targetNode] : [],
        recommended_actions: isValid
          ? [
              'Implement firewall rules',
              'Add intrusion detection system',
              'Enable multi-factor authentication',
              'Implement network segmentation',
            ]
          : ['Add the missing components first', 'Review architecture completeness'],
      },
      can_proceed: isValid,
      error_message: !isValid ? 'Missing required components for this attack' : undefined,
    };
  }

  /**
   * Simulate corrected architecture (replace with actual API call)
   */
  private simulateCorrectedArchitecture(
    attack: ConfiguredAttack,
    architecture: Architecture
  ): SuggestedArchitecture {
    const now = new Date().toISOString();
    const newArchId = `arch_corrected_${Date.now()}`;

    // Create improved nodes
    const improvedNodes = [
      ...architecture.nodes,
      {
        id: `firewall_${Date.now()}`,
        type: 'security',
        name: 'Next-Gen Firewall',
        properties: {
          vendor: 'Palo Alto Networks',
          capabilities: ['Deep packet inspection', 'IDS/IPS', 'Threat intelligence'],
        },
        position: { x: 400, y: 200 },
      },
      {
        id: `ids_${Date.now()}`,
        type: 'security',
        name: 'Intrusion Detection System',
        properties: {
          vendor: 'Snort',
          monitoring: 'Real-time',
        },
        position: { x: 600, y: 200 },
      },
      {
        id: `waf_${Date.now()}`,
        type: 'security',
        name: 'Web Application Firewall',
        properties: {
          vendor: 'Cloudflare',
          protection: ['SQL injection', 'XSS', 'DDoS'],
        },
        position: { x: 800, y: 200 },
      },
    ];

    return {
      original_architecture_id: architecture.metadata.company_name,
      new_architecture: {
        id: newArchId,
        metadata: {
          company_name: `${architecture.metadata.company_name} (Secured)`,
          architecture_type: architecture.metadata.architecture_type,
          created_at: now,
          updated_at: now,
          security_level: 'high',
          description: `Improved architecture to mitigate ${attack.attack_name}`,
          parent_architecture_id: architecture.metadata.company_name,
        },
        components: improvedNodes,
        connections: architecture.connections,
      },
      change_summary: {
        total_changes: 3,
        added_components: [
          {
            id: `firewall_${Date.now()}`,
            type: 'security',
            label: 'Next-Gen Firewall',
            reason: 'Blocks unauthorized access and malicious traffic',
          },
          {
            id: `ids_${Date.now()}`,
            type: 'security',
            label: 'Intrusion Detection System',
            reason: 'Detects and alerts on suspicious activities',
          },
          {
            id: `waf_${Date.now()}`,
            type: 'security',
            label: 'Web Application Firewall',
            reason: 'Protects web applications from attacks',
          },
        ],
        modified_components: [],
        removed_components: [],
        added_connections: [
          {
            source: 'firewall',
            target: 'web_server',
            reason: 'Route all traffic through firewall',
          },
        ],
        security_improvements: [
          'Added perimeter security with next-gen firewall',
          'Implemented real-time threat detection with IDS',
          'Protected web layer with WAF',
          'Enabled network segmentation',
          'Added security monitoring and logging',
        ],
        mitigated_vulnerabilities: [
          'Unauthorized network access',
          'DDoS attacks',
          'SQL injection attempts',
          'Cross-site scripting (XSS)',
          'Malware infiltration',
        ],
      },
      attack_mitigation: {
        attack_id: attack.attack_id,
        attack_name: attack.attack_name,
        prevented: true,
        mitigation_techniques: [
          'Firewall rules to block malicious IPs',
          'IDS signatures to detect attack patterns',
          'WAF rules to filter malicious requests',
          'Rate limiting to prevent brute force',
          'Network segmentation to limit lateral movement',
        ],
      },
    };
  }

  /**
   * Call Python backend API (for production use)
   */
  private async callPythonAPI(endpoint: string, data: any): Promise<any> {
    try {
      const response = await fetch(`${this.apiBaseUrl}/${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('API call failed:', error);
      throw error;
    }
  }
}

/**
 * Export singleton instance
 */
export const agentService = AgentService.getInstance();
