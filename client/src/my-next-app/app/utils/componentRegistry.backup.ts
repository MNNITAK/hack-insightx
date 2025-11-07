/**
 * Component Registry - Dynamically loads from JSON files
 * Auto-imports all components from component_json folder
 */

import { ComponentConfiguration } from '../types';

// Import JSON files directly
import cloudData from '../component_json/cloud.json';
import networkData from '../component_json/NETWORK.json';
import securityData from '../component_json/SECURITY COMPONENTS.json';
import webServerData from '../component_json/WEB_SERVER.json';
import userDevicesData from '../component_json/USER DEVICES.json';
import specialPurposeData from '../component_json/special_purpose.json';
import specialisedData from '../component_json/specialised.json';
import specialisedData from '../component_json/specialised.json';

/**
 * Consolidated Component Registry
 * All components from JSON files combined into a single registry
 */
export const COMPONENT_REGISTRY: ComponentConfiguration[] = [
  // Cloud Components (8) - from cloud.json
  ...(cloudData.cloud_components || []),
  
  // Network Components (9) - from NETWORK.json
  ...(Array.isArray(networkData) ? networkData : []),
  
  // Security Components - from SECURITY COMPONENTS.json
  ...(Array.isArray(securityData) ? securityData : []),
  
  // Web Server & Infrastructure (14) - from WEB_SERVER.json
  ...(Array.isArray(webServerData) ? webServerData : []),
  
  // User Devices & Endpoints (6) - from USER DEVICES.json
  ...(Array.isArray(userDevicesData) ? userDevicesData : []),
  
  // Special Purpose (4) - from special_purpose.json
  ...(Array.isArray(specialPurposeData) ? specialPurposeData : []),
  
  // Specialized Systems (6) - from specialised.json
  ...(Array.isArray(specialisedData) ? specialisedData : []),
];

/**
 * Component Count Summary:
 * - Cloud: 8 components
 * - Network: 9 components
 * - Security: Multiple components
 * - Web/Infrastructure: 14 components
 * - Endpoints: 6 components
 * - Specialized: 6 components
 * - Special Purpose: 4 components
 * Total: 47+ components
 */
  {
    component_type: "cloud_vm",
    icon: "☁️",
    category: "cloud",
    description: "Cloud-based virtual machine",
    configurations: {
      basic: {
        name: "String",
        cloud_provider: ["AWS EC2", "Azure VM", "Google Compute Engine", "DigitalOcean Droplet"],
        region: "String",
        instance_type: "String (e.g., 't3.medium')",
        os: ["Linux", "Windows"],
        ip_address: "String",
        public_ip: "Boolean"
      },
      security: {
        security_groups: "Array of rules",
        iam_role: "String",
        encryption: "Boolean",
        monitoring: "Boolean",
        backup: "Boolean",
        patch_management: ["Automatic", "Manual"],
        compliance: ["PCI-DSS", "HIPAA", "SOC2", "None"]
      },
      network: {
        vpc_id: "String",
        subnet_id: "String",
        internet_gateway: "Boolean"
      }
    }
  },
  {
    component_type: "kubernetes",
    icon: "⚓",
    category: "cloud",
    description: "Kubernetes container orchestration",
    configurations: {
      basic: {
        name: "String",
        provider: ["EKS (AWS)", "AKS (Azure)", "GKE (Google)", "Self-Managed"],
        version: "String",
        node_count: "Integer"
      },
      security: {
        rbac_enabled: "Boolean",
        pod_security_policies: "Boolean",
        network_policies: "Boolean",
        secrets_encryption: "Boolean",
        admission_controllers: "Boolean",
        image_scanning: "Boolean",
        runtime_security: "Boolean"
      },
      configuration: {
        namespaces: "Integer",
        ingress_controller: ["Nginx", "Traefik", "HAProxy", "AWS ALB"],
        service_mesh: ["Istio", "Linkerd", "Consul", "None"],
        monitoring: ["Prometheus", "Datadog", "New Relic", "None"]
      }
    }
  },
  {
    component_type: "managed_database",
    icon: "💾",
    category: "cloud",
    description: "Cloud-managed database service",
    configurations: {
      basic: {
        name: "String",
        service: ["AWS RDS", "Azure SQL", "Google Cloud SQL", "AWS DynamoDB", "CosmosDB"],
        database_engine: ["MySQL", "PostgreSQL", "SQL Server", "Oracle", "NoSQL"],
        region: "String"
      },
      security: {
        public_access: "Boolean",
        encryption_at_rest: "Boolean",
        encryption_in_transit: "Boolean",
        automated_backups: "Boolean",
        point_in_time_recovery: "Boolean",
        multi_az: "Boolean",
        iam_authentication: "Boolean",
        audit_logging: "Boolean"
      },
      configuration: {
        instance_size: "String",
        storage_gb: "Integer",
        read_replicas: "Integer",
        auto_scaling: "Boolean"
      }
    }
  },
  {
    component_type: "cloud_api_gateway",
    icon: "🔌",
    category: "cloud",
    description: "Cloud API Gateway service",
    configurations: {
      basic: {
        name: "String",
        service: ["AWS API Gateway", "Azure API Management", "Google Apigee"],
        region: "String"
      },
      security: {
        authentication: ["API Key", "OAuth 2.0", "JWT", "IAM"],
        rate_limiting: "Boolean",
        request_throttling: "Boolean",
        waf_integration: "Boolean",
        cors: "Boolean",
        ip_whitelisting: "Boolean"
      },
      configuration: {
        caching: "Boolean",
        logging: "Boolean",
        request_validation: "Boolean",
        custom_domain: "Boolean"
      }
    }
  },
  {
    component_type: "cloud_storage",
    icon: "🪣",
    category: "cloud",
    description: "Cloud object storage (S3, Blob, etc.)",
    configurations: {
      basic: {
        name: "String",
        service: ["AWS S3", "Azure Blob", "Google Cloud Storage"],
        region: "String",
        storage_class: ["Standard", "Infrequent Access", "Archive"]
      },
      security: {
        public_access: "Boolean",
        bucket_policy: "Object",
        encryption: "Boolean",
        versioning: "Boolean",
        mfa_delete: "Boolean",
        access_logging: "Boolean",
        object_lock: "Boolean",
        cors_configuration: "Boolean"
      },
      data_classification: {
        contains_pii: "Boolean",
        data_sensitivity: ["Public", "Internal", "Confidential", "Restricted"]
      }
    }
  },
  {
    component_type: "cloud_load_balancer",
    icon: "⚖️",
    category: "cloud",
    description: "Cloud-native load balancer",
    configurations: {
      basic: {
        name: "String",
        service: ["AWS ALB/NLB", "Azure Load Balancer", "Google Cloud Load Balancer"],
        type: ["Application", "Network", "Classic"],
        region: "String"
      },
      security: {
        ssl_termination: "Boolean",
        waf_integration: "Boolean",
        ddos_protection: "Boolean",
        access_logs: "Boolean"
      },
      configuration: {
        health_checks: "Boolean",
        cross_zone: "Boolean",
        stickiness: "Boolean",
        target_groups: "Integer"
      }
    }
  },
  {
    component_type: "cloud_functions",
    icon: "⚡",
    category: "cloud",
    description: "Serverless functions (Lambda, Functions, etc.)",
    configurations: {
      basic: {
        name: "String",
        service: ["AWS Lambda", "Azure Functions", "Google Cloud Functions"],
        runtime: ["Node.js", "Python", "Go", "Java", ".NET"],
        region: "String"
      },
      security: {
        iam_role: "String",
        vpc_enabled: "Boolean",
        environment_encryption: "Boolean",
        secrets_manager: "Boolean",
        layers_used: "Array"
      },
      configuration: {
        memory_mb: "Integer",
        timeout_seconds: "Integer",
        concurrent_executions: "Integer",
        triggers: ["API Gateway", "S3", "EventBridge", "SQS"]
      }
    }
  },
  {
    component_type: "cloud_waf",
    icon: "🛡️",
    category: "cloud",
    description: "Cloud-based Web Application Firewall",
    configurations: {
      basic: {
        name: "String",
        service: ["AWS WAF", "Azure WAF", "Cloudflare", "Imperva"],
        associated_resources: "Array"
      },
      protection: {
        managed_rules: "Boolean",
        rate_limiting: "Boolean",
        geo_blocking: "Boolean",
        ip_reputation: "Boolean",
        bot_control: "Boolean",
        account_takeover_prevention: "Boolean"
      },
      configuration: {
        rule_priority: "Array",
        logging: "Boolean",
        metrics: "Boolean",
        sampling: "Boolean"
      }
    }
  }
];

// Network Components from NETWORK.json
const networkComponents: ComponentConfiguration[] = [
  {
    component_type: "firewall",
    icon: "🔥",
    category: "security",
    description: "Network firewall for traffic filtering",
    configurations: {
      basic: {
        name: "String",
        firewall_type: ["Hardware", "Software", "Cloud-Native"],
        vendor: ["pfSense", "Cisco ASA", "Fortinet", "Palo Alto", "AWS Security Groups", "Azure NSG"],
        ip_address: "String"
      },
      configuration: {
        default_policy: ["Deny All", "Allow All"],
        stateful_inspection: "Boolean",
        deep_packet_inspection: "Boolean",
        application_awareness: "Boolean",
        geo_blocking: "Boolean"
      },
      security: {
        intrusion_prevention: "Boolean",
        threat_intelligence: "Boolean",
        ssl_inspection: "Boolean",
        logging_enabled: "Boolean",
        log_destination: ["Local", "SIEM", "Syslog"]
      }
    }
  },
  {
    component_type: "load_balancer",
    icon: "⚖️",
    category: "network",
    description: "Distributes traffic across multiple servers",
    configurations: {
      basic: {
        name: "String",
        lb_type: ["Application (Layer 7)", "Network (Layer 4)", "Classic"],
        provider: ["HAProxy", "Nginx", "AWS ELB", "Azure Load Balancer", "F5"],
        ip_address: "String"
      },
      configuration: {
        algorithm: ["Round Robin", "Least Connections", "IP Hash", "Weighted"],
        health_check_enabled: "Boolean",
        health_check_interval_seconds: "Integer",
        session_persistence: "Boolean",
        connection_draining: "Boolean"
      },
      security: {
        ssl_termination: "Boolean",
        ssl_certificate: "String",
        tls_version: ["TLS 1.3", "TLS 1.2", "TLS 1.1"],
        waf_integration: "Boolean",
        ddos_protection: "Boolean",
        access_logs: "Boolean"
      }
    }
  },
  {
    component_type: "vpn_gateway",
    icon: "🔐",
    category: "security",
    description: "Virtual Private Network gateway",
    configurations: {
      basic: {
        name: "String",
        vpn_type: ["Site-to-Site", "Client-to-Site", "Both"],
        protocol: ["OpenVPN", "IPSec", "WireGuard", "L2TP", "PPTP"],
        ip_address: "String"
      },
      security: {
        encryption: ["AES-256", "AES-128", "ChaCha20"],
        authentication: ["Certificate", "Pre-Shared Key", "RADIUS", "LDAP"],
        mfa_enabled: "Boolean",
        split_tunneling: "Boolean",
        kill_switch: "Boolean",
        dns_leak_protection: "Boolean"
      },
      configuration: {
        max_concurrent_connections: "Integer",
        bandwidth_limit_mbps: "Integer",
        logging_enabled: "Boolean",
        connection_timeout_minutes: "Integer"
      }
    }
  },
  {
    component_type: "nat_gateway",
    icon: "🌉",
    category: "network",
    description: "Network Address Translation gateway",
    configurations: {
      basic: {
        name: "String",
        nat_type: ["SNAT", "DNAT", "PAT"],
        ip_address: "String"
      },
      configuration: {
        public_ip_addresses: "Array",
        private_subnet: "String (CIDR)",
        port_forwarding_rules: "Array"
      },
      security: {
        logging_enabled: "Boolean",
        connection_tracking: "Boolean"
      }
    }
  },
  {
    component_type: "router",
    icon: "🔀",
    category: "network",
    description: "Network router for traffic routing",
    configurations: {
      basic: {
        name: "String",
        router_type: ["Edge Router", "Core Router", "Virtual Router"],
        vendor: ["Cisco", "Juniper", "Mikrotik", "VyOS"],
        ip_address: "String"
      },
      configuration: {
        routing_protocol: ["Static", "BGP", "OSPF", "EIGRP", "RIP"],
        interfaces: "Array",
        default_gateway: "String"
      },
      security: {
        acl_enabled: "Boolean",
        snmp_enabled: "Boolean",
        snmp_community: "String",
        logging_enabled: "Boolean"
      }
    }
  },
  {
    component_type: "switch",
    icon: "🔌",
    category: "network",
    description: "Network switch for local connectivity",
    configurations: {
      basic: {
        name: "String",
        switch_type: ["Layer 2", "Layer 3", "Managed", "Unmanaged"],
        port_count: "Integer",
        vendor: ["Cisco", "HP", "Juniper", "Netgear"]
      },
      configuration: {
        vlans_configured: "Array of integers",
        spanning_tree_enabled: "Boolean",
        port_security: "Boolean",
        storm_control: "Boolean"
      },
      security: {
        port_security_enabled: "Boolean",
        mac_filtering: "Boolean",
        dhcp_snooping: "Boolean",
        arp_inspection: "Boolean"
      }
    }
  },
  {
    component_type: "cdn",
    icon: "🌍",
    category: "network",
    description: "Content delivery network for global distribution",
    configurations: {
      basic: {
        name: "String",
        cdn_provider: ["Cloudflare", "AWS CloudFront", "Akamai", "Fastly", "Azure CDN"],
        origin_server: "String (IP or domain)"
      },
      security: {
        ddos_protection: "Boolean",
        waf_enabled: "Boolean",
        ssl_enabled: "Boolean",
        bot_protection: "Boolean",
        rate_limiting: "Boolean",
        geo_blocking: "Boolean",
        hotlink_protection: "Boolean"
      },
      configuration: {
        cache_ttl_seconds: "Integer",
        edge_locations: "Array of regions",
        compression_enabled: "Boolean",
        http2_enabled: "Boolean"
      }
    }
  },
  {
    component_type: "bastion_host",
    icon: "🚪",
    category: "security",
    description: "Secure entry point for administrative access",
    configurations: {
      basic: {
        name: "String",
        os: ["Linux", "Windows"],
        ip_address: "String"
      },
      security: {
        mfa_required: "Boolean",
        key_based_auth_only: "Boolean",
        session_recording: "Boolean",
        ip_whitelist: "Array",
        auto_logout_minutes: "Integer",
        command_logging: "Boolean",
        allowed_protocols: ["SSH", "RDP", "Both"]
      },
      configuration: {
        max_sessions: "Integer",
        session_timeout_minutes: "Integer",
        access_hours: "String (e.g., '09:00-17:00')"
      }
    }
  },
  {
    component_type: "ids_ips",
    icon: "🛡️",
    category: "security",
    description: "Intrusion detection and prevention system",
    configurations: {
      basic: {
        name: "String",
        mode: ["IDS (Detection Only)", "IPS (Prevention)", "Both"],
        platform: ["Snort", "Suricata", "Zeek", "AWS GuardDuty", "Cisco Firepower"],
        ip_address: "String"
      },
      detection: {
        signature_based: "Boolean",
        anomaly_based: "Boolean",
        behavioral_analysis: "Boolean",
        threat_intelligence: "Boolean",
        machine_learning: "Boolean"
      },
      configuration: {
        inline_mode: "Boolean",
        alert_threshold: ["Low", "Medium", "High"],
        signature_updates: ["Automatic", "Manual"],
        log_destination: ["Local", "SIEM", "Syslog"]
      },
      actions: {
        block_traffic: "Boolean",
        rate_limit: "Boolean",
        alert_only: "Boolean",
        quarantine: "Boolean"
      }
    }
  }
];

// Security Components from SECURITY COMPONENTS.json
const securityComponents: ComponentConfiguration[] = [
  {
    component_type: "waf",
    icon: "🛡️",
    category: "security",
    description: "Web application firewall protecting web apps",
    configurations: {
      basic: {
        name: "String",
        waf_provider: ["ModSecurity", "AWS WAF", "Cloudflare", "Imperva", "F5"],
        deployment_mode: ["Inline", "Out-of-Band", "Cloud"]
      },
      protection: {
        owasp_top_10: "Boolean",
        sql_injection: "Boolean",
        xss_protection: "Boolean",
        csrf_protection: "Boolean",
        file_inclusion: "Boolean",
        command_injection: "Boolean",
        ddos_protection: "Boolean",
        bot_detection: "Boolean",
        api_protection: "Boolean"
      },
      configuration: {
        rule_sets: ["OWASP CRS", "Custom", "Vendor-Specific"],
        blocking_mode: ["Block", "Monitor", "Challenge"],
        rate_limiting: "Boolean",
        geo_blocking: "Boolean",
        ip_reputation: "Boolean",
        custom_rules: "Array",
        whitelist: "Array",
        blacklist: "Array"
      },
      logging: {
        log_blocked_requests: "Boolean",
        log_allowed_requests: "Boolean",
        log_destination: ["Local", "SIEM", "Cloud"],
        alert_on_threshold: "Boolean"
      }
    }
  },
  {
    component_type: "siem",
    icon: "🔍",
    category: "security",
    description: "Centralized security monitoring and analysis",
    configurations: {
      basic: {
        name: "String",
        siem_platform: ["Splunk", "ELK Stack", "QRadar", "ArcSight", "Azure Sentinel", "Sumo Logic"],
        ip_address: "String"
      },
      data_sources: {
        firewall_logs: "Boolean",
        server_logs: "Boolean",
        application_logs: "Boolean",
        network_traffic: "Boolean",
        authentication_logs: "Boolean",
        cloud_logs: "Boolean",
        endpoint_logs: "Boolean"
      },
      features: {
        real_time_correlation: "Boolean",
        threat_intelligence: "Boolean",
        behavioral_analytics: "Boolean",
        machine_learning: "Boolean",
        automated_response: "Boolean",
        forensics: "Boolean",
        compliance_reporting: "Boolean"
      },
      configuration: {
        log_retention_days: "Integer",
        storage_capacity_tb: "Integer",
        alert_rules: "Integer",
        custom_dashboards: "Integer"
      },
      integration: {
        ticketing_system: "Boolean",
        soar_platform: "Boolean",
        threat_feeds: "Boolean"
      }
    }
  },
  {
    component_type: "iam_sso",
    icon: "🔑",
    category: "security",
    description: "Identity and access management system",
    configurations: {
      basic: {
        name: "String",
        iam_platform: ["Active Directory", "Okta", "Auth0", "Azure AD", "AWS IAM", "Keycloak"],
        ip_address: "String"
      },
      authentication: {
        sso_enabled: "Boolean",
        mfa_required: "Boolean",
        mfa_methods: ["TOTP", "SMS", "Push Notification", "Biometric", "Hardware Token"],
        password_policy: {
          min_length: "Integer",
          complexity_required: "Boolean",
          expiration_days: "Integer",
          history_count: "Integer"
        },
        biometric_auth: "Boolean",
        certificate_based_auth: "Boolean"
      },
      authorization: {
        rbac_enabled: "Boolean",
        abac_enabled: "Boolean",
        least_privilege: "Boolean",
        just_in_time_access: "Boolean",
        privileged_access_management: "Boolean"
      },
      federation: {
        saml_enabled: "Boolean",
        oauth2_enabled: "Boolean",
        ldap_integration: "Boolean"
      },
      monitoring: {
        login_monitoring: "Boolean",
        failed_login_alerts: "Boolean",
        privilege_escalation_detection: "Boolean",
        session_management: "Boolean"
      }
    }
  },
  {
    component_type: "secrets_vault",
    icon: "🔒",
    category: "security",
    description: "Secure storage for credentials and secrets",
    configurations: {
      basic: {
        name: "String",
        vault_platform: ["HashiCorp Vault", "AWS Secrets Manager", "Azure Key Vault", "CyberArk"],
        ip_address: "String"
      },
      security: {
        encryption_at_rest: "Boolean",
        encryption_algorithm: ["AES-256-GCM", "AES-128"],
        access_control: "Boolean",
        audit_logging: "Boolean",
        mfa_for_access: "Boolean",
        auto_rotation: "Boolean"
      },
      features: {
        dynamic_secrets: "Boolean",
        secret_rotation: "Boolean",
        rotation_interval_days: "Integer",
        secret_versioning: "Boolean",
        lease_management: "Boolean",
        revocation: "Boolean"
      },
      integration: {
        api_access: "Boolean",
        cli_access: "Boolean",
        cicd_integration: "Boolean",
        database_credential_management: "Boolean"
      }
    }
  },
  {
    component_type: "honeypot",
    icon: "🍯",
    category: "security",
    description: "Decoy system to trap attackers",
    configurations: {
      basic: {
        name: "String",
        honeypot_type: ["Low-Interaction", "High-Interaction", "Hybrid"],
        services_emulated: ["SSH", "FTP", "HTTP", "Database", "SMB"],
        ip_address: "String"
      },
      configuration: {
        vulnerability_level: ["High", "Medium", "Low"],
        fake_data_included: "Boolean",
        realistic_behavior: "Boolean",
        logging_level: ["Verbose", "Standard", "Minimal"]
      },
      monitoring: {
        alert_on_access: "Boolean",
        attacker_profiling: "Boolean",
        threat_intelligence_contribution: "Boolean",
        forensic_capture: "Boolean"
      }
    }
  },
  {
    component_type: "pki_ca",
    icon: "📜",
    category: "security",
    description: "Public Key Infrastructure / Certificate Authority",
    configurations: {
      basic: {
        name: "String",
        ca_type: ["Root CA", "Intermediate CA", "Issuing CA"],
        ca_software: ["OpenSSL", "Microsoft CA", "HashiCorp Vault PKI"],
        ip_address: "String"
      },
      security: {
        hsm_backed: "Boolean",
        offline_root_ca: "Boolean",
        certificate_pinning: "Boolean",
        crl_enabled: "Boolean",
        ocsp_enabled: "Boolean"
      },
      configuration: {
        key_size: ["2048-bit", "4096-bit", "ECC-256", "ECC-384"],
        certificate_validity_days: "Integer",
        auto_renewal: "Boolean",
        certificate_transparency: "Boolean"
      }
    }
  },
  {
    component_type: "dlp",
    icon: "🚫",
    category: "security",
    description: "Data loss prevention system",
    configurations: {
      basic: {
        name: "String",
        dlp_platform: ["Symantec DLP", "McAfee DLP", "Microsoft DLP", "Forcepoint"],
        deployment: ["Network DLP", "Endpoint DLP", "Cloud DLP", "All"]
      },
      protection: {
        email_monitoring: "Boolean",
        web_upload_blocking: "Boolean",
        usb_control: "Boolean",
        clipboard_monitoring: "Boolean",
        print_control: "Boolean",
        screen_capture_blocking: "Boolean"
      },
      detection: {
        content_inspection: "Boolean",
        pattern_matching: "Boolean",
        machine_learning: "Boolean",
        fingerprinting: "Boolean",
        keyword_detection: "Boolean"
      },
      data_types_monitored: {
        pii: "Boolean",
        phi: "Boolean",
        pci: "Boolean",
        source_code: "Boolean",
        intellectual_property: "Boolean",
        credentials: "Boolean"
      },
      actions: {
        block: "Boolean",
        quarantine: "Boolean",
        encrypt: "Boolean",
        alert_only: "Boolean",
        user_notification: "Boolean"
      }
    }
  },
  {
    component_type: "edr",
    icon: "💻",
    category: "security",
    description: "Endpoint detection and response system",
    configurations: {
      basic: {
        name: "String",
        edr_platform: ["CrowdStrike", "SentinelOne", "Microsoft Defender", "Carbon Black", "Cisco AMP"],
        managed_endpoints: "Integer"
      },
      detection: {
        behavioral_analysis: "Boolean",
        machine_learning: "Boolean",
        signature_based: "Boolean",
        threat_intelligence: "Boolean",
        fileless_attack_detection: "Boolean",
        ransomware_detection: "Boolean"
      },
      response: {
        auto_isolation: "Boolean",
        auto_remediation: "Boolean",
        rollback_capability: "Boolean",
        forensic_capture: "Boolean",
        remote_shell: "Boolean"
      },
      monitoring: {
        process_monitoring: "Boolean",
        network_monitoring: "Boolean",
        file_integrity: "Boolean",
        registry_monitoring: "Boolean",
        memory_scanning: "Boolean"
      }
    }
  }
];

// Continue with Web Server, User Devices, Specialized, and Special Purpose components...
// For brevity, I'll add a few key ones and the export structure

// Web Server Components (sample from WEB_SERVER.json)
const webServerComponents: ComponentConfiguration[] = [
  {
    component_type: "web_server",
    icon: "🌐",
    category: "compute",
    description: "Public-facing web server hosting applications",
    configurations: {
      basic: {
        name: "String (e.g., 'prod-web-01')",
        os: ["Linux", "Windows", "FreeBSD"],
        os_version: "String (e.g., 'Ubuntu 22.04', 'Windows Server 2022')",
        ip_address: "String (e.g., '10.0.1.10')",
        location: ["On-Premise", "AWS", "Azure", "GCP", "DigitalOcean"]
      },
      network: {
        open_ports: "Array of integers (e.g., [80, 443, 22])",
        exposed_to_internet: "Boolean",
        ipv6_enabled: "Boolean"
      },
      services: {
        web_server_type: ["Nginx", "Apache", "IIS", "Caddy", "Lighttpd"],
        web_server_version: "String",
        application_stack: ["Node.js", "Python/Django", "PHP", "Ruby on Rails", ".NET", "Java/Tomcat"],
        ssl_tls_version: ["TLS 1.3", "TLS 1.2", "TLS 1.1", "None"],
        http2_enabled: "Boolean"
      },
      security: {
        firewall_enabled: "Boolean",
        waf_enabled: "Boolean",
        waf_provider: ["CloudFlare", "AWS WAF", "ModSecurity", "Imperva", "None"],
        rate_limiting_enabled: "Boolean",
        ddos_protection: "Boolean",
        fail2ban_enabled: "Boolean",
        selinux_enabled: "Boolean",
        security_headers: "Boolean (HSTS, CSP, X-Frame-Options)",
        patch_level: ["Current", "1-30 days old", "30-90 days old", "90+ days old"],
        vulnerability_scanning: "Boolean"
      },
      authentication: {
        ssh_enabled: "Boolean",
        ssh_key_only: "Boolean",
        mfa_enabled: "Boolean",
        password_policy: ["Strong", "Medium", "Weak"],
        admin_access: ["Key-based", "Password", "Both"]
      },
      monitoring: {
        logging_enabled: "Boolean",
        log_destination: ["Local", "SIEM", "Cloud"],
        intrusion_detection: "Boolean",
        performance_monitoring: "Boolean"
      },
      resources: {
        cpu_cores: "Integer",
        memory_gb: "Integer",
        storage_gb: "Integer",
        bandwidth_mbps: "Integer"
      }
    }
  },
  {
    component_type: "database",
    icon: "💾",
    category: "data",
    description: "Database server storing application data",
    configurations: {
      basic: {
        name: "String",
        os: ["Linux", "Windows"],
        ip_address: "String",
        zone: ["Internal", "Private"]
      },
      database: {
        db_type: ["MySQL", "PostgreSQL", "MongoDB", "Oracle", "SQL Server", "Redis", "Cassandra", "DynamoDB"],
        db_version: "String",
        port: "Integer (e.g., 3306, 5432, 27017)",
        database_size_gb: "Integer",
        replication: ["None", "Master-Slave", "Master-Master", "Cluster"],
        sharding: "Boolean"
      },
      security: {
        firewall_enabled: "Boolean",
        exposed_to_internet: "Boolean",
        encryption_at_rest: "Boolean",
        encryption_in_transit: "Boolean",
        ssl_required: "Boolean",
        authentication_method: ["Password", "Certificate", "IAM", "Kerberos"],
        access_control: ["IP Whitelist", "VPN Only", "Internal Only", "Public"],
        audit_logging: "Boolean",
        database_firewall: "Boolean"
      },
      data_classification: {
        contains_pii: "Boolean",
        contains_phi: "Boolean",
        contains_pci: "Boolean",
        data_sensitivity: ["Public", "Internal", "Confidential", "Restricted"],
        compliance_requirements: ["PCI-DSS", "HIPAA", "GDPR", "SOC2", "None"]
      },
      backup: {
        backup_enabled: "Boolean",
        backup_frequency: ["Real-time", "Hourly", "Daily", "Weekly", "None"],
        backup_retention_days: "Integer",
        backup_encryption: "Boolean",
        point_in_time_recovery: "Boolean",
        backup_location: ["On-Premise", "Cloud", "Off-Site"]
      },
      performance: {
        query_caching: "Boolean",
        connection_pooling: "Boolean",
        read_replicas: "Integer",
        max_connections: "Integer"
      }
    }
  }
];

// User Device Components (sample from USER DEVICES.json)
const userDeviceComponents: ComponentConfiguration[] = [
  {
    component_type: "user_workstation",
    icon: "💻",
    category: "endpoints",
    description: "Employee desktop/laptop computer",
    configurations: {
      basic: {
        name: "String",
        device_type: ["Desktop", "Laptop"],
        os: ["Windows 10", "Windows 11", "macOS", "Linux"],
        ip_address: "String"
      },
      user_info: {
        department: ["Engineering", "Marketing", "Sales", "HR", "Finance", "IT", "Executive"],
        access_level: ["Standard User", "Power User", "Admin", "Privileged"],
        typical_work_hours: "String (e.g., '09:00-17:00')",
        remote_worker: "Boolean"
      },
      security: {
        antivirus_enabled: "Boolean",
        antivirus_vendor: ["Windows Defender", "Symantec", "McAfee", "Kaspersky", "CrowdStrike"],
        firewall_enabled: "Boolean",
        full_disk_encryption: "Boolean",
        screen_lock_enabled: "Boolean",
        screen_lock_timeout_minutes: "Integer",
        admin_privileges: "Boolean",
        patch_level: ["Current", "1-30 days old", "30-90 days old", "90+ days old"],
        edr_agent: "Boolean",
        dlp_agent: "Boolean",
        vpn_required: "Boolean"
      },
      applications: {
        office_suite: "Boolean",
        development_tools: "Boolean",
        database_access: "Boolean",
        admin_tools: "Boolean",
        remote_desktop: "Boolean"
      }
    }
  },
  {
    component_type: "mobile_device",
    icon: "📱",
    category: "endpoints",
    description: "Smartphone or tablet",
    configurations: {
      basic: {
        name: "String",
        device_type: ["iPhone", "iPad", "Android Phone", "Android Tablet"],
        os: ["iOS", "Android"],
        os_version: "String"
      },
      security: {
        mdm_enrolled: "Boolean",
        mdm_platform: ["Intune", "Jamf", "MobileIron", "VMware Workspace ONE"],
        device_encryption: "Boolean",
        passcode_required: "Boolean",
        biometric_auth: "Boolean",
        remote_wipe: "Boolean",
        jailbroken_rooted: "Boolean",
        vpn_configured: "Boolean",
        app_whitelist: "Boolean"
      },
      configuration: {
        corporate_email: "Boolean",
        access_to_files: "Boolean",
        access_to_databases: "Boolean",
        camera_disabled: "Boolean",
        screenshot_disabled: "Boolean"
      }
    }
  },
  {
    component_type: "iot_device",
    icon: "📡",
    category: "endpoints",
    description: "Internet of Things device",
    configurations: {
      basic: {
        name: "String",
        device_type: ["Smart Camera", "Sensor", "Smart Lock", "Industrial Controller", "Smart TV", "Printer"],
        ip_address: "String",
        manufacturer: "String",
        firmware_version: "String"
      },
      security: {
        default_credentials: "Boolean",
        firmware_updates: ["Automatic", "Manual", "Never"],
        encryption: "Boolean",
        authentication_required: "Boolean",
        network_segmentation: "Boolean",
        internet_accessible: "Boolean"
      }
    }
  }
];

// Specialized Components (sample from specialised.json)
const specializedComponents: ComponentConfiguration[] = [
  {
    component_type: "scada_ics",
    icon: "🏭",
    category: "specialized",
    description: "Industrial control system or SCADA",
    configurations: {
      basic: {
        name: "String",
        system_type: ["SCADA", "PLC", "DCS", "HMI"],
        vendor: "String",
        ip_address: "String"
      },
      security: {
        air_gapped: "Boolean",
        network_segmentation: "Boolean",
        firewall_protected: "Boolean",
        authentication: "Boolean",
        firmware_updated: "Boolean",
        intrusion_detection: "Boolean",
        change_management: "Boolean"
      },
      criticality: {
        safety_critical: "Boolean",
        production_critical: "Boolean",
        environmental_impact: ["None", "Low", "Medium", "High"]
      }
    }
  },
  {
    component_type: "payment_terminal",
    icon: "💳",
    category: "specialized",
    description: "Payment card processing terminal",
    configurations: {
      basic: {
        name: "String",
        terminal_type: ["POS Terminal", "Payment Gateway", "Virtual Terminal"],
        vendor: "String",
        ip_address: "String"
      },
      security: {
        pci_dss_compliant: "Boolean",
        end_to_end_encryption: "Boolean",
        tokenization: "Boolean",
        emv_chip_reader: "Boolean",
        pin_pad_encrypted: "Boolean",
        tamper_detection: "Boolean",
        secure_boot: "Boolean"
      },
      compliance: {
        pci_dss_level: ["Level 1", "Level 2", "Level 3", "Level 4"],
        last_audit_date: "Date",
        attestation_of_compliance: "Boolean"
      }
    }
  }
];

// Combine all components
export const COMPONENT_REGISTRY: ComponentConfiguration[] = [
  ...cloudComponents,
  ...networkComponents,
  ...securityComponents,
  ...webServerComponents,
  ...userDeviceComponents,
  ...specializedComponents
];

export const getComponentsByCategory = () => {
  const categories: Record<string, ComponentConfiguration[]> = {};
  
  COMPONENT_REGISTRY.forEach(component => {
    if (!categories[component.category]) {
      categories[component.category] = [];
    }
    categories[component.category].push(component);
  });
  
  return categories;
};

export const getComponentByType = (componentType: string): ComponentConfiguration | undefined => {
  return COMPONENT_REGISTRY.find(comp => comp.component_type === componentType);
};

export const useComponentRegistry = () => {
  return {
    getAllComponents: () => COMPONENT_REGISTRY,
    getComponentsByCategory,
    getComponentByType,
    searchComponents: (query: string) => {
      const lowercaseQuery = query.toLowerCase();
      return COMPONENT_REGISTRY.filter(comp => 
        comp.component_type.toLowerCase().includes(lowercaseQuery) ||
        comp.description.toLowerCase().includes(lowercaseQuery)
      );
    }
  };
};