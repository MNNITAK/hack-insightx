/**
 * COMPLETE Component Registry - All 56+ Components
 * Updated with full configurations for comprehensive architecture building
 */

import { ComponentConfiguration } from '../types';

// ============================================================================
// COMPUTE RESOURCES (14 Components)
// ============================================================================

const computeComponents: ComponentConfiguration[] = [
  {
    component_type: "web_server",
    icon: "🌐",
    category: "compute",
    description: "Public-facing web server hosting applications",
    configurations: {
      basic: {
        name: "String",
        os: ["Linux", "Windows", "FreeBSD"],
        os_version: "String",
        ip_address: "String",
        location: ["On-Premise", "AWS", "Azure", "GCP", "DigitalOcean"]
      },
      network: {
        open_ports: "Array",
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
        security_headers: "Boolean",
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
    },
    common_vulnerabilities: [
      "Exposed admin panel",
      "Outdated web server version",
      "Missing security headers",
      "SSL/TLS misconfiguration",
      "Directory listing enabled",
      "Default credentials",
      "Unpatched CVEs"
    ]
  },
  {
    component_type: "application_server",
    icon: "💼",
    category: "compute",
    description: "Server running business logic and application code",
    configurations: {
      basic: {
        name: "String",
        os: ["Linux", "Windows"],
        os_version: "String",
        ip_address: "String",
        zone: ["DMZ", "Internal", "Private"]
      },
      application: {
        runtime: ["Java/JVM", "Node.js", ".NET Core", "Python", "Go", "Ruby"],
        runtime_version: "String",
        application_server: ["Tomcat", "JBoss", "WebLogic", "WildFly", "WebSphere"],
        container_runtime: ["Docker", "containerd", "None"],
        microservices: "Boolean"
      },
      security: {
        firewall_enabled: "Boolean",
        api_security: "Boolean",
        input_validation: "Boolean",
        output_encoding: "Boolean",
        secrets_management: ["Vault", "AWS Secrets Manager", "Azure Key Vault", "Environment Variables", "Hardcoded"],
        dependency_scanning: "Boolean",
        code_signing: "Boolean"
      },
      performance: {
        auto_scaling: "Boolean",
        load_balancer_backend: "Boolean",
        caching_enabled: "Boolean",
        session_management: ["In-Memory", "Redis", "Database", "Sticky Sessions"]
      }
    },
    common_vulnerabilities: [
      "Insecure dependencies",
      "Hardcoded secrets",
      "Missing input validation",
      "Vulnerable application server version"
    ]
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
        port: "Integer",
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
    },
    common_vulnerabilities: [
      "Exposed to internet",
      "Weak authentication",
      "Missing encryption in transit",
      "SQL injection vulnerabilities",
      "Default credentials"
    ]
  },
  {
    component_type: "api_gateway",
    icon: "🔌",
    category: "compute",
    description: "API gateway managing API requests and authentication",
    configurations: {
      basic: {
        name: "String",
        provider: ["Kong", "AWS API Gateway", "Azure API Management", "Apigee", "Custom"],
        ip_address: "String"
      },
      security: {
        authentication: ["OAuth 2.0", "JWT", "API Keys", "Basic Auth", "mTLS", "None"],
        authorization: "Boolean",
        rate_limiting: "Boolean",
        rate_limit_per_minute: "Integer",
        ip_whitelisting: "Boolean",
        cors_enabled: "Boolean",
        api_key_rotation: "Boolean"
      },
      features: {
        request_validation: "Boolean",
        response_transformation: "Boolean",
        caching: "Boolean",
        logging: "Boolean",
        analytics: "Boolean",
        throttling: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Missing authentication",
      "No rate limiting",
      "Exposed admin endpoints",
      "Insufficient input validation"
    ]
  },
  {
    component_type: "cache_server",
    icon: "🗄️",
    category: "data",
    description: "Caching layer for performance optimization",
    configurations: {
      basic: {
        name: "String",
        cache_type: ["Redis", "Memcached", "Varnish", "CDN Edge Cache"],
        ip_address: "String",
        port: "Integer"
      },
      security: {
        password_protected: "Boolean",
        encryption_in_transit: "Boolean",
        acl_enabled: "Boolean",
        exposed_to_internet: "Boolean"
      },
      performance: {
        memory_size_gb: "Integer",
        eviction_policy: ["LRU", "LFU", "FIFO", "TTL"],
        persistence: "Boolean",
        clustering: "Boolean"
      }
    },
    common_vulnerabilities: [
      "No authentication",
      "Exposed to public internet",
      "Cache poisoning vulnerabilities"
    ]
  },
  {
    component_type: "message_queue",
    icon: "📮",
    category: "infrastructure",
    description: "Message broker for asynchronous communication",
    configurations: {
      basic: {
        name: "String",
        queue_type: ["RabbitMQ", "Kafka", "AWS SQS", "Azure Service Bus", "Redis Pub/Sub"],
        ip_address: "String"
      },
      security: {
        authentication_enabled: "Boolean",
        encryption_in_transit: "Boolean",
        acl_per_queue: "Boolean",
        message_encryption: "Boolean"
      },
      configuration: {
        message_persistence: "Boolean",
        message_ttl_seconds: "Integer",
        dead_letter_queue: "Boolean",
        replication: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Unauthenticated access",
      "Message tampering",
      "Missing encryption"
    ]
  },
  {
    component_type: "file_storage",
    icon: "☁️",
    category: "data",
    description: "File and object storage system",
    configurations: {
      basic: {
        name: "String",
        storage_type: ["AWS S3", "Azure Blob", "Google Cloud Storage", "MinIO", "NFS", "CIFS/SMB"],
        storage_size_tb: "Integer"
      },
      security: {
        public_access: "Boolean",
        encryption_at_rest: "Boolean",
        encryption_in_transit: "Boolean",
        access_control: ["IAM", "ACL", "Bucket Policy", "Public"],
        versioning: "Boolean",
        mfa_delete: "Boolean",
        access_logging: "Boolean"
      },
      data_classification: {
        contains_pii: "Boolean",
        data_sensitivity: ["Public", "Internal", "Confidential", "Restricted"]
      },
      backup: {
        backup_enabled: "Boolean",
        cross_region_replication: "Boolean",
        lifecycle_policies: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Public bucket exposure",
      "Missing encryption",
      "Overly permissive ACLs",
      "No versioning"
    ]
  },
  {
    component_type: "dns_server",
    icon: "🌐",
    category: "infrastructure",
    description: "Domain Name System server",
    configurations: {
      basic: {
        name: "String",
        dns_provider: ["BIND", "PowerDNS", "Route53", "Cloudflare", "Azure DNS"],
        ip_address: "String"
      },
      security: {
        dnssec_enabled: "Boolean",
        dns_over_https: "Boolean",
        dns_over_tls: "Boolean",
        rate_limiting: "Boolean",
        query_logging: "Boolean",
        response_rate_limiting: "Boolean"
      },
      configuration: {
        zones_managed: "Integer",
        public_facing: "Boolean",
        recursive_queries: "Boolean",
        caching: "Boolean"
      }
    },
    common_vulnerabilities: [
      "DNS amplification attacks",
      "Cache poisoning",
      "Zone transfer vulnerabilities",
      "Missing DNSSEC"
    ]
  },
  {
    component_type: "container_registry",
    icon: "🐳",
    category: "infrastructure",
    description: "Docker/container image registry",
    configurations: {
      basic: {
        name: "String",
        registry_type: ["Docker Hub", "AWS ECR", "Azure ACR", "Google GCR", "Harbor", "JFrog"],
        access: ["Public", "Private"]
      },
      security: {
        authentication_required: "Boolean",
        image_scanning: "Boolean",
        vulnerability_scanning: "Boolean",
        image_signing: "Boolean",
        access_control: "Boolean",
        encryption_at_rest: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Vulnerable base images",
      "Missing image scanning",
      "Public registry exposure",
      "Unsigned images"
    ]
  },
  {
    component_type: "cicd_server",
    icon: "⚙️",
    category: "infrastructure",
    description: "Continuous Integration/Deployment server",
    configurations: {
      basic: {
        name: "String",
        cicd_platform: ["Jenkins", "GitLab CI", "GitHub Actions", "CircleCI", "Azure DevOps", "TeamCity"],
        ip_address: "String"
      },
      security: {
        authentication: "Boolean",
        rbac_enabled: "Boolean",
        secrets_management: ["Vault", "Built-in", "Environment Variables"],
        code_signing: "Boolean",
        artifact_scanning: "Boolean",
        pipeline_approval: "Boolean"
      },
      features: {
        auto_deployment: "Boolean",
        rollback_capability: "Boolean",
        audit_logging: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Exposed credentials",
      "Insecure pipeline configuration",
      "Missing code review",
      "Unsecured webhooks"
    ]
  },
  {
    component_type: "email_server",
    icon: "📧",
    category: "infrastructure",
    description: "Mail server for sending/receiving emails",
    configurations: {
      basic: {
        name: "String",
        email_server: ["Postfix", "Sendmail", "Exchange", "Gmail Workspace", "Office 365"],
        ip_address: "String"
      },
      security: {
        spf_enabled: "Boolean",
        dkim_enabled: "Boolean",
        dmarc_enabled: "Boolean",
        tls_encryption: "Boolean",
        spam_filtering: "Boolean",
        virus_scanning: "Boolean",
        phishing_protection: "Boolean",
        email_encryption: ["None", "S/MIME", "PGP"],
        attachment_filtering: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Missing SPF/DKIM/DMARC",
      "Open relay configuration",
      "Weak authentication",
      "No spam filtering"
    ]
  },
  {
    component_type: "backup_server",
    icon: "💿",
    category: "infrastructure",
    description: "Centralized backup and recovery system",
    configurations: {
      basic: {
        name: "String",
        backup_solution: ["Veeam", "Commvault", "AWS Backup", "Custom"],
        storage_capacity_tb: "Integer"
      },
      security: {
        encryption: "Boolean",
        encryption_algorithm: ["AES-256", "AES-128"],
        immutable_backups: "Boolean",
        air_gapped: "Boolean",
        access_control: "Boolean"
      },
      configuration: {
        backup_retention_days: "Integer",
        backup_frequency: ["Real-time", "Hourly", "Daily", "Weekly"],
        offsite_backup: "Boolean",
        backup_testing: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Unencrypted backups",
      "Accessible to ransomware",
      "Missing backup testing",
      "Single point of failure"
    ]
  },
  {
    component_type: "monitoring_server",
    icon: "📊",
    category: "infrastructure",
    description: "System monitoring and observability",
    configurations: {
      basic: {
        name: "String",
        monitoring_tool: ["Prometheus", "Grafana", "Datadog", "New Relic", "Nagios", "Zabbix"],
        ip_address: "String"
      },
      security: {
        authentication_enabled: "Boolean",
        encrypted_communication: "Boolean",
        rbac: "Boolean"
      },
      features: {
        log_aggregation: "Boolean",
        metrics_collection: "Boolean",
        alerting: "Boolean",
        dashboards: "Boolean",
        apm_enabled: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Exposed dashboards",
      "Weak authentication",
      "Sensitive data in logs"
    ]
  },
  {
    component_type: "serverless_function",
    icon: "⚡",
    category: "compute",
    description: "Serverless computing function",
    configurations: {
      basic: {
        name: "String",
        provider: ["AWS Lambda", "Azure Functions", "Google Cloud Functions", "Cloudflare Workers"],
        runtime: ["Node.js", "Python", "Go", "Java", ".NET", "Ruby"]
      },
      security: {
        iam_role: "String",
        vpc_enabled: "Boolean",
        environment_variables_encrypted: "Boolean",
        secrets_manager: "Boolean",
        function_url_auth: ["IAM", "None"]
      },
      configuration: {
        memory_mb: "Integer",
        timeout_seconds: "Integer",
        concurrent_executions: "Integer",
        triggers: ["API Gateway", "S3", "EventBridge", "SQS", "HTTP"]
      }
    },
    common_vulnerabilities: [
      "Overly permissive IAM roles",
      "Secrets in environment variables",
      "Missing input validation",
      "Excessive timeout"
    ]
  }
];

// ============================================================================
// NETWORK COMPONENTS (10 Components)
// ============================================================================

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
      rules: "Array",
      security: {
        intrusion_prevention: "Boolean",
        threat_intelligence: "Boolean",
        ssl_inspection: "Boolean",
        logging_enabled: "Boolean",
        log_destination: ["Local", "SIEM", "Syslog"]
      }
    },
    common_vulnerabilities: [
      "Overly permissive rules",
      "Disabled logging",
      "Outdated firmware",
      "Default credentials"
    ]
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
    },
    common_vulnerabilities: [
      "Weak SSL/TLS configuration",
      "Missing health checks",
      "No DDoS protection",
      "Exposed management interface"
    ]
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
    },
    common_vulnerabilities: [
      "Weak encryption",
      "Missing MFA",
      "PPTP protocol use",
      "Exposed VPN server"
    ]
  },
  {
    component_type: "proxy_server",
    icon: "🚪",
    category: "network",
    description: "Forward or reverse proxy server",
    configurations: {
      basic: {
        name: "String",
        proxy_type: ["Forward Proxy", "Reverse Proxy", "Transparent Proxy"],
        software: ["Squid", "Nginx", "HAProxy", "Apache"],
        ip_address: "String"
      },
      security: {
        authentication_required: "Boolean",
        ssl_inspection: "Boolean",
        content_filtering: "Boolean",
        url_filtering: "Boolean",
        malware_scanning: "Boolean",
        access_logging: "Boolean"
      },
      configuration: {
        caching_enabled: "Boolean",
        cache_size_gb: "Integer",
        allowed_domains: "Array",
        blocked_domains: "Array"
      }
    },
    common_vulnerabilities: [
      "Open proxy configuration",
      "Weak authentication",
      "SSL/TLS interception issues",
      "Cache poisoning"
    ]
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
        private_subnet: "String",
        port_forwarding_rules: "Array"
      },
      security: {
        logging_enabled: "Boolean",
        connection_tracking: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Exposed internal IPs",
      "Misconfigured port forwarding",
      "Missing logging"
    ]
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
    },
    common_vulnerabilities: [
      "Default SNMP community strings",
      "Missing ACLs",
      "Outdated firmware",
      "Weak authentication"
    ]
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
        vlans_configured: "Array",
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
    },
    common_vulnerabilities: [
      "VLAN hopping",
      "ARP spoofing",
      "CAM table overflow",
      "Spanning tree attacks"
    ]
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
        origin_server: "String"
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
        edge_locations: "Array",
        compression_enabled: "Boolean",
        http2_enabled: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Cache poisoning",
      "Origin exposure",
      "Missing WAF",
      "Weak SSL/TLS"
    ]
  },
  {
    component_type: "bastion_host",
    icon: "🏰",
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
        access_hours: "String"
      }
    },
    common_vulnerabilities: [
      "Weak authentication",
      "Missing MFA",
      "No session recording",
      "Overly broad IP whitelist"
    ]
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
    },
    common_vulnerabilities: [
      "Outdated signatures",
      "False positive tuning",
      "Bypassed by encryption",
      "Performance bottlenecks"
    ]
  }
];

// ============================================================================
// SECURITY COMPONENTS (8 Components)
// ============================================================================

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
    },
    common_vulnerabilities: [
      "Misconfigured rules",
      "False positives",
      "Bypass techniques",
      "Monitor-only mode"
    ]
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
        correlation_rules: "Boolean",
        threat_intelligence: "Boolean",
        user_behavior_analytics: "Boolean",
        automated_response: "Boolean",
        incident_management: "Boolean",
        compliance_reporting: "Boolean",
        real_time_alerting: "Boolean"
      },
      security: {
        encryption_at_rest: "Boolean",
        encryption_in_transit: "Boolean",
        rbac: "Boolean",
        audit_trail: "Boolean"
      },
      performance: {
        events_per_second: "Integer",
        retention_days: "Integer",
        storage_tb: "Integer"
      }
    },
    common_vulnerabilities: [
      "Insufficient log sources",
      "Poor correlation rules",
      "Alert fatigue",
      "Weak access controls"
    ]
  },
  {
    component_type: "identity_provider",
    icon: "🔑",
    category: "security",
    description: "Identity and access management system",
    configurations: {
      basic: {
        name: "String",
        idp_type: ["Active Directory", "Okta", "Azure AD", "Auth0", "Keycloak", "LDAP"],
        ip_address: "String"
      },
      authentication: {
        mfa_enabled: "Boolean",
        mfa_methods: ["TOTP", "SMS", "Push", "Biometric", "Hardware Token"],
        sso_enabled: "Boolean",
        saml_enabled: "Boolean",
        oauth_enabled: "Boolean",
        passwordless: "Boolean"
      },
      security: {
        password_policy: {
          min_length: "Integer",
          complexity_required: "Boolean",
          expiration_days: "Integer",
          history_count: "Integer"
        },
        account_lockout: "Boolean",
        lockout_threshold: "Integer",
        session_timeout_minutes: "Integer",
        ip_restriction: "Boolean"
      },
      features: {
        user_provisioning: "Boolean",
        role_based_access: "Boolean",
        conditional_access: "Boolean",
        privileged_access_management: "Boolean",
        audit_logging: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Weak password policies",
      "Missing MFA",
      "Overly broad permissions",
      "Poor session management"
    ]
  },
  {
    component_type: "secrets_manager",
    icon: "🔐",
    category: "security",
    description: "Centralized secrets and credentials management",
    configurations: {
      basic: {
        name: "String",
        vault_type: ["HashiCorp Vault", "AWS Secrets Manager", "Azure Key Vault", "CyberArk"],
        ip_address: "String"
      },
      security: {
        encryption_at_rest: "Boolean",
        encryption_in_transit: "Boolean",
        access_control: "Boolean",
        audit_logging: "Boolean",
        auto_rotation: "Boolean",
        rotation_period_days: "Integer"
      },
      features: {
        dynamic_secrets: "Boolean",
        secret_versioning: "Boolean",
        lease_management: "Boolean",
        api_access: "Boolean",
        cli_access: "Boolean"
      },
      integration: {
        cicd_integration: "Boolean",
        kubernetes_integration: "Boolean",
        cloud_integration: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Weak access policies",
      "No secret rotation",
      "Poor audit trail",
      "Exposed API endpoints"
    ]
  },
  {
    component_type: "dlp_system",
    icon: "🚫",
    category: "security",
    description: "Data Loss Prevention system",
    configurations: {
      basic: {
        name: "String",
        dlp_solution: ["Symantec DLP", "McAfee DLP", "Forcepoint", "Digital Guardian", "Microsoft Purview"],
        deployment: ["Network", "Endpoint", "Cloud", "Hybrid"]
      },
      detection: {
        content_inspection: "Boolean",
        contextual_analysis: "Boolean",
        pattern_matching: "Boolean",
        fingerprinting: "Boolean",
        machine_learning: "Boolean"
      },
      data_types: {
        pii_detection: "Boolean",
        phi_detection: "Boolean",
        pci_detection: "Boolean",
        intellectual_property: "Boolean",
        custom_patterns: "Array"
      },
      actions: {
        block: "Boolean",
        quarantine: "Boolean",
        encrypt: "Boolean",
        alert: "Boolean",
        log: "Boolean"
      },
      channels: {
        email_monitoring: "Boolean",
        web_monitoring: "Boolean",
        usb_control: "Boolean",
        cloud_apps: "Boolean",
        file_transfer: "Boolean"
      }
    },
    common_vulnerabilities: [
      "False positive tuning",
      "Bypass techniques",
      "Insufficient coverage",
      "Poor policy enforcement"
    ]
  },
  {
    component_type: "certificate_authority",
    icon: "📜",
    category: "security",
    description: "PKI Certificate Authority",
    configurations: {
      basic: {
        name: "String",
        ca_type: ["Internal CA", "Public CA", "Private CA"],
        ca_software: ["OpenSSL", "Microsoft CA", "AWS Private CA", "Let's Encrypt"]
      },
      certificates: {
        certificate_types: ["SSL/TLS", "Code Signing", "Email", "Client Auth"],
        validity_period_days: "Integer",
        key_size: ["2048", "4096"],
        algorithm: ["RSA", "ECDSA", "EdDSA"]
      },
      security: {
        hsm_backed: "Boolean",
        crl_enabled: "Boolean",
        ocsp_enabled: "Boolean",
        auto_renewal: "Boolean",
        certificate_transparency: "Boolean"
      },
      management: {
        certificate_lifecycle: "Boolean",
        revocation_checking: "Boolean",
        expiry_alerts: "Boolean",
        audit_logging: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Weak key sizes",
      "Missing revocation checking",
      "Poor certificate lifecycle",
      "Exposed private keys"
    ]
  },
  {
    component_type: "vulnerability_scanner",
    icon: "🔬",
    category: "security",
    description: "Vulnerability assessment and scanning tool",
    configurations: {
      basic: {
        name: "String",
        scanner_type: ["Nessus", "Qualys", "OpenVAS", "Rapid7", "Tenable.io"],
        scan_scope: ["Network", "Web Application", "Container", "Cloud"]
      },
      scanning: {
        scan_frequency: ["Continuous", "Daily", "Weekly", "Monthly"],
        authenticated_scans: "Boolean",
        compliance_scanning: "Boolean",
        patch_detection: "Boolean",
        configuration_audit: "Boolean"
      },
      features: {
        prioritization: "Boolean",
        risk_scoring: "Boolean",
        remediation_guidance: "Boolean",
        integration_with_ticketing: "Boolean",
        reporting: "Boolean"
      },
      security: {
        scanner_hardening: "Boolean",
        encrypted_credentials: "Boolean",
        audit_logging: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Infrequent scans",
      "Limited scope",
      "Unpatched scanner",
      "No remediation follow-up"
    ]
  },
  {
    component_type: "endpoint_protection",
    icon: "💻",
    category: "security",
    description: "Endpoint security and protection",
    configurations: {
      basic: {
        name: "String",
        edr_solution: ["CrowdStrike", "Carbon Black", "Microsoft Defender", "SentinelOne", "Sophos"],
        deployment: ["Agent-based", "Agentless"]
      },
      protection: {
        antivirus: "Boolean",
        anti_malware: "Boolean",
        ransomware_protection: "Boolean",
        exploit_protection: "Boolean",
        behavioral_analysis: "Boolean",
        machine_learning: "Boolean"
      },
      features: {
        edr_capabilities: "Boolean",
        threat_hunting: "Boolean",
        incident_response: "Boolean",
        forensics: "Boolean",
        remediation: "Boolean",
        quarantine: "Boolean"
      },
      management: {
        centralized_management: "Boolean",
        policy_enforcement: "Boolean",
        reporting: "Boolean",
        integration_with_siem: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Outdated definitions",
      "Disabled protection",
      "Poor configuration",
      "Agent tampering"
    ]
  },
  {
    component_type: "penetration_testing",
    icon: "🎯",
    category: "security",
    description: "Penetration testing and red team operations",
    configurations: {
      basic: {
        name: "String",
        test_type: ["Internal", "External", "Web Application", "Social Engineering", "Physical"],
        methodology: ["OWASP", "PTES", "OSSTMM", "Custom"]
      },
      scope: {
        network_testing: "Boolean",
        application_testing: "Boolean",
        wireless_testing: "Boolean",
        social_engineering: "Boolean",
        physical_security: "Boolean"
      },
      approach: {
        black_box: "Boolean",
        white_box: "Boolean",
        gray_box: "Boolean",
        automated_scanning: "Boolean",
        manual_testing: "Boolean"
      },
      reporting: {
        executive_summary: "Boolean",
        technical_details: "Boolean",
        remediation_guidance: "Boolean",
        risk_scoring: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Insufficient scope",
      "No follow-up testing",
      "Poor documentation",
      "Unrealistic scenarios"
    ]
  }
];

// ============================================================================
// CLOUD SERVICES (8 Components)
// ============================================================================

const cloudComponents: ComponentConfiguration[] = [
  {
    component_type: "kubernetes_cluster",
    icon: "☸️",
    category: "infrastructure",
    description: "Container orchestration platform",
    configurations: {
      basic: {
        name: "String",
        platform: ["EKS", "AKS", "GKE", "Self-Managed", "OpenShift"],
        version: "String",
        node_count: "Integer"
      },
      compute: {
        node_type: "String",
        auto_scaling: "Boolean",
        min_nodes: "Integer",
        max_nodes: "Integer"
      },
      security: {
        rbac_enabled: "Boolean",
        pod_security_policies: "Boolean",
        network_policies: "Boolean",
        secrets_encryption: "Boolean",
        audit_logging: "Boolean",
        admission_controllers: "Boolean",
        vulnerability_scanning: "Boolean"
      },
      networking: {
        cni_plugin: ["Calico", "Flannel", "Weave", "Cilium"],
        service_mesh: ["Istio", "Linkerd", "None"],
        ingress_controller: ["Nginx", "Traefik", "HAProxy", "Kong"]
      },
      monitoring: {
        prometheus: "Boolean",
        logging: "Boolean",
        tracing: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Misconfigured RBAC",
      "Exposed API server",
      "Privileged containers",
      "Missing network policies"
    ]
  },
  {
    component_type: "virtual_machine",
    icon: "🖥️",
    category: "compute",
    description: "Virtual machine instance",
    configurations: {
      basic: {
        name: "String",
        provider: ["AWS EC2", "Azure VM", "GCP Compute", "VMware", "Hyper-V"],
        os: ["Linux", "Windows"],
        os_version: "String",
        ip_address: "String"
      },
      compute: {
        instance_type: "String",
        cpu_cores: "Integer",
        memory_gb: "Integer",
        storage_gb: "Integer"
      },
      security: {
        security_groups: "Array",
        firewall_enabled: "Boolean",
        encryption_at_rest: "Boolean",
        ssh_key_only: "Boolean",
        monitoring_enabled: "Boolean",
        backup_enabled: "Boolean"
      },
      networking: {
        public_ip: "Boolean",
        vpc: "String",
        subnet: "String",
        elastic_ip: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Publicly exposed",
      "Unencrypted volumes",
      "Missing security patches",
      "Weak access controls"
    ]
  },
  {
    component_type: "object_storage",
    icon: "🪣",
    category: "data",
    description: "Cloud object storage service",
    configurations: {
      basic: {
        name: "String",
        provider: ["AWS S3", "Azure Blob", "GCS", "MinIO"],
        storage_class: ["Standard", "Infrequent Access", "Glacier", "Archive"]
      },
      security: {
        public_access_blocked: "Boolean",
        encryption_at_rest: "Boolean",
        encryption_key_type: ["AWS-Managed", "Customer-Managed", "Customer-Provided"],
        versioning: "Boolean",
        mfa_delete: "Boolean",
        access_logging: "Boolean",
        bucket_policy: "String",
        cors_enabled: "Boolean"
      },
      management: {
        lifecycle_policies: "Boolean",
        replication: "Boolean",
        replication_type: ["Same-Region", "Cross-Region"],
        object_lock: "Boolean",
        inventory: "Boolean"
      },
      monitoring: {
        cloudwatch_metrics: "Boolean",
        access_analyzer: "Boolean",
        cloudtrail_enabled: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Public bucket",
      "Missing encryption",
      "Overly permissive policies",
      "No versioning"
    ]
  },
  {
    component_type: "auto_scaling_group",
    icon: "📈",
    category: "infrastructure",
    description: "Auto-scaling compute group",
    configurations: {
      basic: {
        name: "String",
        provider: ["AWS ASG", "Azure VMSS", "GCP MIG"],
        instance_template: "String"
      },
      scaling: {
        min_instances: "Integer",
        max_instances: "Integer",
        desired_capacity: "Integer",
        scaling_policy: ["Target Tracking", "Step Scaling", "Simple Scaling", "Scheduled"],
        cooldown_period_seconds: "Integer"
      },
      health: {
        health_check_type: ["EC2", "ELB", "Custom"],
        health_check_grace_period: "Integer",
        replace_unhealthy: "Boolean"
      },
      configuration: {
        launch_template: "String",
        availability_zones: "Array",
        load_balancer_attached: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Improper scaling metrics",
      "No health checks",
      "Insecure launch template",
      "Missing monitoring"
    ]
  },
  {
    component_type: "managed_database",
    icon: "🗄️",
    category: "data",
    description: "Managed cloud database service",
    configurations: {
      basic: {
        name: "String",
        service: ["AWS RDS", "Azure SQL", "Cloud SQL", "DynamoDB", "CosmosDB"],
        engine: ["MySQL", "PostgreSQL", "SQL Server", "Oracle", "MariaDB"],
        version: "String"
      },
      compute: {
        instance_class: "String",
        storage_type: ["SSD", "Provisioned IOPS", "Magnetic"],
        allocated_storage_gb: "Integer",
        multi_az: "Boolean"
      },
      security: {
        publicly_accessible: "Boolean",
        encryption_at_rest: "Boolean",
        encryption_in_transit: "Boolean",
        iam_authentication: "Boolean",
        vpc_security_groups: "Array",
        parameter_group: "String",
        audit_logging: "Boolean"
      },
      backup: {
        automated_backups: "Boolean",
        backup_retention_days: "Integer",
        backup_window: "String",
        snapshot_enabled: "Boolean",
        point_in_time_recovery: "Boolean"
      },
      performance: {
        read_replicas: "Integer",
        performance_insights: "Boolean",
        enhanced_monitoring: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Publicly accessible",
      "Weak authentication",
      "Missing encryption",
      "Poor backup strategy"
    ]
  },
  {
    component_type: "cloud_function",
    icon: "⚡",
    category: "compute",
    description: "Serverless cloud function",
    configurations: {
      basic: {
        name: "String",
        provider: ["AWS Lambda", "Azure Functions", "Cloud Functions", "Cloud Run"],
        runtime: ["Node.js", "Python", "Go", "Java", ".NET", "Ruby", "Custom"]
      },
      configuration: {
        memory_mb: "Integer",
        timeout_seconds: "Integer",
        concurrent_executions: "Integer",
        reserved_concurrency: "Integer",
        environment_variables: "Object"
      },
      security: {
        execution_role: "String",
        vpc_config: "Boolean",
        encryption: "Boolean",
        resource_policy: "String",
        secrets_manager: "Boolean"
      },
      triggers: {
        trigger_type: ["API Gateway", "S3", "EventBridge", "SQS", "SNS", "HTTP", "CloudWatch"],
        trigger_config: "Object"
      },
      monitoring: {
        cloudwatch_logs: "Boolean",
        x_ray_tracing: "Boolean",
        metrics: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Overly permissive IAM",
      "Secrets in environment",
      "No VPC isolation",
      "Excessive timeout"
    ]
  },
  {
    component_type: "queue_service",
    icon: "📬",
    category: "infrastructure",
    description: "Managed message queue service",
    configurations: {
      basic: {
        name: "String",
        service: ["AWS SQS", "Azure Queue", "Cloud Pub/Sub", "EventBridge"],
        queue_type: ["Standard", "FIFO"]
      },
      configuration: {
        message_retention_seconds: "Integer",
        visibility_timeout_seconds: "Integer",
        delay_seconds: "Integer",
        max_message_size_kb: "Integer",
        receive_wait_time_seconds: "Integer"
      },
      security: {
        encryption_at_rest: "Boolean",
        encryption_in_transit: "Boolean",
        access_policy: "String",
        dead_letter_queue: "Boolean",
        max_receive_count: "Integer"
      },
      monitoring: {
        cloudwatch_alarms: "Boolean",
        message_age_alert: "Boolean",
        queue_depth_alert: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Unencrypted messages",
      "Overly permissive access",
      "No dead letter queue",
      "Missing monitoring"
    ]
  },
  {
    component_type: "cloud_storage_gateway",
    icon: "🌉",
    category: "infrastructure",
    description: "Hybrid cloud storage gateway",
    configurations: {
      basic: {
        name: "String",
        gateway_type: ["File Gateway", "Volume Gateway", "Tape Gateway"],
        provider: ["AWS Storage Gateway", "Azure StorSimple"]
      },
      configuration: {
        cache_size_gb: "Integer",
        bandwidth_limit_mbps: "Integer",
        protocol: ["NFS", "SMB", "iSCSI"],
        storage_backend: "String"
      },
      security: {
        encryption_in_transit: "Boolean",
        encryption_at_rest: "Boolean",
        access_control: "Boolean",
        audit_logging: "Boolean"
      },
      performance: {
        cache_refresh: "Boolean",
        bandwidth_optimization: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Unencrypted data",
      "Weak access controls",
      "Poor cache management",
      "Network exposure"
    ]
  }
];

// ============================================================================
// USER ACCESS COMPONENTS (6 Components)
// ============================================================================

const userAccessComponents: ComponentConfiguration[] = [
  {
    component_type: "user_device",
    icon: "💻",
    category: "endpoint",
    description: "End-user device (laptop, desktop, mobile)",
    configurations: {
      basic: {
        name: "String",
        device_type: ["Laptop", "Desktop", "Mobile", "Tablet"],
        os: ["Windows", "macOS", "Linux", "iOS", "Android"],
        os_version: "String",
        managed: "Boolean"
      },
      security: {
        antivirus_installed: "Boolean",
        firewall_enabled: "Boolean",
        disk_encryption: "Boolean",
        screen_lock: "Boolean",
        password_protected: "Boolean",
        biometric_auth: "Boolean",
        mdm_enrolled: "Boolean",
        patch_level: ["Current", "Outdated"]
      },
      compliance: {
        company_owned: "Boolean",
        byod: "Boolean",
        compliance_check: "Boolean",
        remote_wipe_capability: "Boolean"
      },
      network: {
        vpn_required: "Boolean",
        network_access: ["Corporate", "Public", "Home"]
      }
    },
    common_vulnerabilities: [
      "Unpatched OS",
      "No encryption",
      "Weak passwords",
      "Missing endpoint protection"
    ]
  },
  {
    component_type: "admin_workstation",
    icon: "👨‍💼",
    category: "endpoint",
    description: "Privileged administrative workstation",
    configurations: {
      basic: {
        name: "String",
        os: ["Windows", "Linux", "macOS"],
        purpose: ["System Administration", "Security Operations", "DevOps"]
      },
      security: {
        hardened: "Boolean",
        dedicated_admin_use: "Boolean",
        privileged_access_workstation: "Boolean",
        application_whitelisting: "Boolean",
        credential_guard: "Boolean",
        mfa_required: "Boolean",
        session_recording: "Boolean"
      },
      access: {
        jump_box_only: "Boolean",
        vpn_required: "Boolean",
        network_isolated: "Boolean",
        privileged_account_only: "Boolean"
      },
      monitoring: {
        enhanced_logging: "Boolean",
        anomaly_detection: "Boolean",
        audit_trail: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Not dedicated for admin use",
      "Missing hardening",
      "Weak MFA",
      "Insufficient monitoring"
    ]
  },
  {
    component_type: "mobile_device_management",
    icon: "📱",
    category: "security",
    description: "MDM system for mobile device management",
    configurations: {
      basic: {
        name: "String",
        mdm_solution: ["Intune", "Jamf", "MobileIron", "VMware Workspace ONE", "Kandji"],
        platform_support: ["iOS", "Android", "Windows", "macOS"]
      },
      policies: {
        password_policy: "Boolean",
        encryption_required: "Boolean",
        app_whitelisting: "Boolean",
        app_blacklisting: "Boolean",
        data_loss_prevention: "Boolean",
        containerization: "Boolean"
      },
      features: {
        remote_wipe: "Boolean",
        geofencing: "Boolean",
        app_distribution: "Boolean",
        certificate_management: "Boolean",
        vpn_configuration: "Boolean",
        compliance_monitoring: "Boolean"
      },
      security: {
        jailbreak_detection: "Boolean",
        device_attestation: "Boolean",
        conditional_access: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Weak policies",
      "No compliance enforcement",
      "Missing encryption",
      "Poor app management"
    ]
  },
  {
    component_type: "remote_access_portal",
    icon: "🌐",
    category: "network",
    description: "Secure remote access portal",
    configurations: {
      basic: {
        name: "String",
        portal_type: ["VPN", "Zero Trust", "RDP Gateway", "SSH Gateway"],
        provider: ["Citrix", "VMware Horizon", "Guacamole", "Custom"]
      },
      security: {
        mfa_required: "Boolean",
        certificate_based_auth: "Boolean",
        device_compliance_check: "Boolean",
        geo_restrictions: "Boolean",
        session_timeout_minutes: "Integer",
        concurrent_session_limit: "Integer"
      },
      access_control: {
        rbac: "Boolean",
        conditional_access: "Boolean",
        time_based_access: "Boolean",
        ip_whitelisting: "Boolean"
      },
      monitoring: {
        session_recording: "Boolean",
        activity_logging: "Boolean",
        anomaly_detection: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Weak authentication",
      "No MFA",
      "Missing session controls",
      "Poor logging"
    ]
  },
  {
    component_type: "privileged_access_management",
    icon: "🔐",
    category: "security",
    description: "PAM system for privileged account management",
    configurations: {
      basic: {
        name: "String",
        pam_solution: ["CyberArk", "BeyondTrust", "Thycotic", "Delinea", "HashiCorp Boundary"]
      },
      features: {
        password_vaulting: "Boolean",
        session_management: "Boolean",
        credential_rotation: "Boolean",
        just_in_time_access: "Boolean",
        elevation_control: "Boolean",
        privileged_session_monitoring: "Boolean"
      },
      security: {
        mfa_for_access: "Boolean",
        approval_workflow: "Boolean",
        session_recording: "Boolean",
        keystroke_logging: "Boolean",
        break_glass_access: "Boolean"
      },
      integration: {
        ad_integration: "Boolean",
        siem_integration: "Boolean",
        ticketing_integration: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Shared admin passwords",
      "No session monitoring",
      "Missing approval workflows",
      "Poor audit trails"
    ]
  },
  {
    component_type: "wireless_access_point",
    icon: "📡",
    category: "network",
    description: "Wireless network access point",
    configurations: {
      basic: {
        name: "String",
        vendor: ["Cisco", "Ubiquiti", "Aruba", "Ruckus", "Meraki"],
        wifi_standard: ["WiFi 6E", "WiFi 6", "WiFi 5", "WiFi 4"]
      },
      security: {
        encryption: ["WPA3", "WPA2", "WPA", "Open"],
        authentication: ["802.1X", "PSK", "Captive Portal"],
        radius_server: "Boolean",
        client_isolation: "Boolean",
        rogue_ap_detection: "Boolean"
      },
      network: {
        ssid_count: "Integer",
        guest_network: "Boolean",
        vlan_segmentation: "Boolean",
        bandwidth_limit: "Integer"
      },
      management: {
        centralized_management: "Boolean",
        firmware_auto_update: "Boolean",
        logging_enabled: "Boolean"
      }
    },
    common_vulnerabilities: [
      "WEP/WPA encryption",
      "Default credentials",
      "Open guest network",
      "No client isolation"
    ]
  }
];

// ============================================================================
// EXTERNAL THIRD-PARTY COMPONENTS (6 Components)
// ============================================================================

const externalComponents: ComponentConfiguration[] = [
  {
    component_type: "third_party_api",
    icon: "🔗",
    category: "external",
    description: "External third-party API service",
    configurations: {
      basic: {
        name: "String",
        provider: "String",
        service_type: ["Payment", "Authentication", "Analytics", "Communication", "Data"],
        api_endpoint: "String"
      },
      security: {
        authentication_method: ["API Key", "OAuth 2.0", "JWT", "mTLS", "Basic Auth"],
        encryption_in_transit: "Boolean",
        ip_whitelisting: "Boolean",
        rate_limiting: "Boolean",
        api_key_rotation: "Boolean"
      },
      integration: {
        data_flow: ["Inbound", "Outbound", "Bidirectional"],
        data_sensitivity: ["Public", "Internal", "Confidential", "Restricted"],
        webhook_enabled: "Boolean",
        webhook_verification: "Boolean"
      },
      compliance: {
        sla_defined: "Boolean",
        data_residency: "String",
        compliance_certifications: "Array",
        vendor_assessment_completed: "Boolean"
      },
      monitoring: {
        uptime_monitoring: "Boolean",
        error_tracking: "Boolean",
        performance_monitoring: "Boolean",
        cost_tracking: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Weak API authentication",
      "No rate limiting",
      "Unencrypted communication",
      "Missing webhook validation"
    ]
  },
  {
    component_type: "payment_gateway",
    icon: "💳",
    category: "external",
    description: "Payment processing gateway",
    configurations: {
      basic: {
        name: "String",
        provider: ["Stripe", "PayPal", "Square", "Braintree", "Authorize.net"],
        supported_methods: ["Credit Card", "Debit Card", "ACH", "Digital Wallet"]
      },
      security: {
        pci_dss_compliant: "Boolean",
        tokenization: "Boolean",
        encryption: "Boolean",
        fraud_detection: "Boolean",
        "3d_secure": "Boolean"
      },
      integration: {
        integration_method: ["Hosted", "API", "SDK", "iFrame"],
        webhook_notifications: "Boolean",
        recurring_billing: "Boolean",
        refund_capability: "Boolean"
      },
      compliance: {
        pci_level: ["Level 1", "Level 2", "Level 3", "Level 4"],
        audit_trail: "Boolean",
        transaction_logging: "Boolean"
      },
      monitoring: {
        transaction_monitoring: "Boolean",
        failure_alerts: "Boolean",
        reconciliation: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Non-PCI compliant integration",
      "Storing card data",
      "Missing fraud detection",
      "Weak webhook security"
    ]
  },
  {
    component_type: "cdn_provider",
    icon: "🌎",
    category: "external",
    description: "Third-party CDN service provider",
    configurations: {
      basic: {
        name: "String",
        provider: ["Cloudflare", "Akamai", "Fastly", "AWS CloudFront", "Azure CDN"],
        origin_server: "String"
      },
      security: {
        ddos_protection: "Boolean",
        waf_enabled: "Boolean",
        ssl_tls: "Boolean",
        bot_management: "Boolean",
        rate_limiting: "Boolean",
        geo_blocking: "Boolean"
      },
      caching: {
        cache_ttl_seconds: "Integer",
        edge_locations: "Array",
        cache_purge: "Boolean",
        cache_key_customization: "Boolean"
      },
      performance: {
        http2_enabled: "Boolean",
        http3_enabled: "Boolean",
        compression: "Boolean",
        image_optimization: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Origin server exposure",
      "Cache poisoning",
      "Missing WAF rules",
      "Weak SSL configuration"
    ]
  },
  {
    component_type: "cloud_provider",
    icon: "☁️",
    category: "external",
    description: "External cloud service provider",
    configurations: {
      basic: {
        name: "String",
        provider: ["AWS", "Azure", "GCP", "DigitalOcean", "Oracle Cloud"],
        services_used: "Array",
        region: "String"
      },
      security: {
        iam_configured: "Boolean",
        mfa_enabled: "Boolean",
        encryption_default: "Boolean",
        network_segmentation: "Boolean",
        security_groups_configured: "Boolean",
        cloudtrail_enabled: "Boolean"
      },
      compliance: {
        compliance_certifications: ["SOC2", "ISO 27001", "PCI-DSS", "HIPAA", "FedRAMP"],
        data_residency: "String",
        shared_responsibility_model: "Boolean"
      },
      monitoring: {
        cloud_monitoring: "Boolean",
        cost_monitoring: "Boolean",
        security_monitoring: "Boolean",
        config_compliance: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Misconfigured IAM",
      "Public resources",
      "Missing encryption",
      "Inadequate logging"
    ]
  },
  {
    component_type: "saas_application",
    icon: "📦",
    category: "external",
    description: "Third-party SaaS application",
    configurations: {
      basic: {
        name: "String",
        vendor: "String",
        application_type: ["CRM", "ERP", "HR", "Collaboration", "Marketing", "Analytics"],
        url: "String"
      },
      security: {
        sso_enabled: "Boolean",
        mfa_required: "Boolean",
        data_encryption: "Boolean",
        api_access: "Boolean",
        api_authentication: "String",
        audit_logging: "Boolean"
      },
      data: {
        data_stored: ["Customer", "Employee", "Financial", "None"],
        data_classification: ["Public", "Internal", "Confidential", "Restricted"],
        data_backup: "Boolean",
        data_export_capability: "Boolean"
      },
      compliance: {
        vendor_assessment: "Boolean",
        sla_defined: "Boolean",
        compliance_certifications: "Array",
        data_processing_agreement: "Boolean"
      },
      integration: {
        api_integration: "Boolean",
        webhook_integration: "Boolean",
        directory_sync: "Boolean"
      }
    },
    common_vulnerabilities: [
      "No SSO integration",
      "Weak access controls",
      "Missing vendor assessment",
      "Data residency issues"
    ]
  },
  {
    component_type: "dns_provider",
    icon: "🌐",
    category: "external",
    description: "External DNS service provider",
    configurations: {
      basic: {
        name: "String",
        provider: ["Cloudflare", "Route53", "Azure DNS", "Google Cloud DNS", "Namecheap"],
        managed_domains: "Array"
      },
      security: {
        dnssec_enabled: "Boolean",
        registry_lock: "Boolean",
        two_factor_auth: "Boolean",
        access_control: "Boolean",
        audit_logging: "Boolean"
      },
      features: {
        ddos_protection: "Boolean",
        geo_routing: "Boolean",
        health_checks: "Boolean",
        failover: "Boolean",
        cname_flattening: "Boolean"
      },
      monitoring: {
        query_analytics: "Boolean",
        uptime_monitoring: "Boolean",
        change_notifications: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Missing DNSSEC",
      "Weak account security",
      "No registry lock",
      "Domain hijacking risk"
    ]
  }
];

// ============================================================================
// SPECIALIZED COMPONENTS (4 Components)
// ============================================================================

const specializedComponents: ComponentConfiguration[] = [
  {
    component_type: "iot_device",
    icon: "📡",
    category: "endpoint",
    description: "Internet of Things device",
    configurations: {
      basic: {
        name: "String",
        device_type: ["Sensor", "Camera", "Gateway", "Controller", "Smart Device"],
        manufacturer: "String",
        firmware_version: "String"
      },
      network: {
        connectivity: ["WiFi", "Ethernet", "Cellular", "LoRa", "Zigbee", "Bluetooth"],
        ip_address: "String",
        network_segment: "String",
        internet_access: "Boolean"
      },
      security: {
        default_credentials_changed: "Boolean",
        encryption_enabled: "Boolean",
        firmware_signed: "Boolean",
        auto_updates: "Boolean",
        certificate_based_auth: "Boolean",
        network_isolated: "Boolean"
      },
      data: {
        data_collected: "Array",
        data_sensitivity: ["Public", "Internal", "Confidential"],
        data_encrypted_at_rest: "Boolean",
        data_encrypted_in_transit: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Default credentials",
      "Outdated firmware",
      "No encryption",
      "Network exposure"
    ]
  },
  {
    component_type: "data_warehouse",
    icon: "🏢",
    category: "data",
    description: "Enterprise data warehouse",
    configurations: {
      basic: {
        name: "String",
        platform: ["Snowflake", "Redshift", "BigQuery", "Azure Synapse", "Teradata"],
        data_size_tb: "Integer"
      },
      security: {
        encryption_at_rest: "Boolean",
        encryption_in_transit: "Boolean",
        network_isolation: "Boolean",
        role_based_access: "Boolean",
        column_level_security: "Boolean",
        row_level_security: "Boolean",
        data_masking: "Boolean",
        audit_logging: "Boolean"
      },
      data_classification: {
        contains_pii: "Boolean",
        contains_phi: "Boolean",
        data_sensitivity: ["Public", "Internal", "Confidential", "Restricted"],
        compliance_requirements: "Array"
      },
      performance: {
        partitioning: "Boolean",
        clustering: "Boolean",
        materialized_views: "Boolean",
        query_optimization: "Boolean"
      },
      backup: {
        backup_enabled: "Boolean",
        backup_frequency: "String",
        point_in_time_recovery: "Boolean",
        cross_region_backup: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Excessive permissions",
      "Missing data classification",
      "No column-level security",
      "Inadequate audit logging"
    ]
  },
  {
    component_type: "blockchain_node",
    icon: "⛓️",
    category: "infrastructure",
    description: "Blockchain network node",
    configurations: {
      basic: {
        name: "String",
        blockchain: ["Ethereum", "Bitcoin", "Hyperledger", "Corda", "Custom"],
        node_type: ["Full Node", "Light Node", "Archive Node", "Validator"],
        network: ["Mainnet", "Testnet", "Private"]
      },
      security: {
        private_key_management: ["HSM", "Key Vault", "Software"],
        encrypted_communication: "Boolean",
        firewall_rules: "Boolean",
        access_control: "Boolean",
        monitoring: "Boolean"
      },
      configuration: {
        sync_status: ["Synced", "Syncing", "Behind"],
        storage_gb: "Integer",
        peer_count: "Integer",
        rpc_enabled: "Boolean",
        rpc_authentication: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Exposed RPC endpoints",
      "Poor key management",
      "Missing access controls",
      "Network attacks"
    ]
  },
  {
    component_type: "ml_pipeline",
    icon: "🤖",
    category: "infrastructure",
    description: "Machine learning pipeline",
    configurations: {
      basic: {
        name: "String",
        platform: ["SageMaker", "Azure ML", "Vertex AI", "Databricks", "Kubeflow"],
        model_type: "String"
      },
      data: {
        training_data_source: "String",
        data_preprocessing: "Boolean",
        feature_store: "Boolean",
        data_versioning: "Boolean",
        data_validation: "Boolean"
      },
      security: {
        data_encryption: "Boolean",
        model_encryption: "Boolean",
        access_control: "Boolean",
        audit_logging: "Boolean",
        adversarial_testing: "Boolean"
      },
      deployment: {
        model_versioning: "Boolean",
        a_b_testing: "Boolean",
        canary_deployment: "Boolean",
        rollback_capability: "Boolean",
        monitoring: "Boolean"
      },
      compliance: {
        model_explainability: "Boolean",
        bias_detection: "Boolean",
        privacy_preserving: "Boolean"
      }
    },
    common_vulnerabilities: [
      "Training data poisoning",
      "Model theft",
      "Adversarial attacks",
      "Data leakage"
    ]
  }
];

// ============================================================================
// EXPORT ALL COMPONENTS
// ============================================================================

export const ALL_COMPONENTS: ComponentConfiguration[] = [
  ...computeComponents,
  ...networkComponents,
  ...securityComponents,
  ...cloudComponents,
  ...userAccessComponents,
  ...externalComponents,
  ...specializedComponents
];

// Export by category for easier filtering
export const COMPONENTS_BY_CATEGORY = {
  compute: computeComponents,
  network: networkComponents,
  security: securityComponents,
  cloud: cloudComponents,
  user_access: userAccessComponents,
  external: externalComponents,
  specialized: specializedComponents,
  
  // Additional groupings
  data: ALL_COMPONENTS.filter(c => c.category === 'data'),
  infrastructure: ALL_COMPONENTS.filter(c => c.category === 'infrastructure'),
  endpoint: ALL_COMPONENTS.filter(c => c.category === 'endpoint')
};

// Component lookup by type
export const getComponentByType = (type: string): ComponentConfiguration | undefined => {
  return ALL_COMPONENTS.find(c => c.component_type === type);
};

// Get all component types
export const getAllComponentTypes = (): string[] => {
  return ALL_COMPONENTS.map(c => c.component_type);
};

// Get components by category
export const getComponentsByCategory = (category: string): ComponentConfiguration[] => {
  return ALL_COMPONENTS.filter(c => c.category === category);
};

// Summary
export const COMPONENT_SUMMARY = {
  total_components: ALL_COMPONENTS.length,
  categories: {
    compute: computeComponents.length,
    network: networkComponents.length,
    security: securityComponents.length,
    cloud: cloudComponents.length,
    user_access: userAccessComponents.length,
    external: externalComponents.length,
    specialized: specializedComponents.length,
    data: ALL_COMPONENTS.filter(c => c.category === 'data').length,
    infrastructure: ALL_COMPONENTS.filter(c => c.category === 'infrastructure').length,
    endpoint: ALL_COMPONENTS.filter(c => c.category === 'endpoint').length
  }
};

// React hook for accessing component registry
export const useComponentRegistry = () => {
  // Search components by query
  const searchComponents = (query: string): ComponentConfiguration[] => {
    const searchTerm = query.toLowerCase();
    return ALL_COMPONENTS.filter(component =>
      component.component_type.toLowerCase().includes(searchTerm) ||
      component.description.toLowerCase().includes(searchTerm) ||
      component.category.toLowerCase().includes(searchTerm)
    );
  };

  // Get all categories with their components
  const getComponentsByCategory = () => {
    return COMPONENTS_BY_CATEGORY;
  };

  return {
    allComponents: ALL_COMPONENTS,
    getComponentByType,
    getComponentsByCategory,
    getAllComponentTypes,
    searchComponents,
    componentsByCategory: COMPONENTS_BY_CATEGORY,
    summary: COMPONENT_SUMMARY
  };
};

/**
 * COMPONENT BREAKDOWN:
 * 
 * COMPUTE RESOURCES (14):
 * - web_server, application_server, database, api_gateway, cache_server
 * - message_queue, file_storage, dns_server, container_registry, cicd_server
 * - email_server, backup_server, monitoring_server, serverless_function
 * 
 * NETWORK COMPONENTS (10):
 * - firewall, load_balancer, vpn_gateway, proxy_server, nat_gateway
 * - router, switch, cdn, bastion_host, ids_ips
 * 
 * SECURITY COMPONENTS (8):
 * - waf, siem, identity_provider, secrets_manager, dlp_system
 * - certificate_authority, vulnerability_scanner, endpoint_protection
 * 
 * CLOUD SERVICES (8):
 * - kubernetes_cluster, virtual_machine, object_storage, auto_scaling_group
 * - managed_database, cloud_function, queue_service, cloud_storage_gateway
 * 
 * USER ACCESS (6):
 * - user_device, admin_workstation, mobile_device_management, remote_access_portal
 * - privileged_access_management, wireless_access_point
 * 
 * EXTERNAL THIRD-PARTY (6):
 * - third_party_api, payment_gateway, cdn_provider, cloud_provider
 * - saas_application, dns_provider
 * 
 * SPECIALIZED (4):
 * - iot_device, data_warehouse, blockchain_node, ml_pipeline
 * 
 * TOTAL: 56 Components
 */