# Rule-Based Security Agent - Complete Explanation

## 🎯 Overview

The `security_agent_rulebased.py` file is a **FastAPI server** that provides 100% rule-based security analysis and attack simulation. It orchestrates 5 different rule engines to analyze architectures and validate attacks.

## 📊 System Architecture

```
┌────────────────────────────────────────────────────────────────┐
│         security_agent_rulebased.py (FastAPI Server)          │
│                                                                │
│  Endpoints:                                                    │
│  • /api/analyze            - Full security analysis           │
│  • /api/heal               - Generate healed architecture     │
│  • /api/validate-attack    - Check if attack possible         │
│  • /api/correct-architecture - Generate secured architecture  │
└────────────┬───────────────────────────────────────────────────┘
             │
             │ Uses 2 main components:
             │
    ┌────────┴────────┐
    │                 │
    ▼                 ▼
┌─────────────┐   ┌──────────────────┐
│  scanner    │   │ attack_simulator │
│  (Scanner)  │   │   (Simulator)    │
└─────┬───────┘   └────────┬─────────┘
      │                    │
      │                    │
      │ Uses:              │ Uses:
      │                    │
      ▼                    ▼
┌──────────────────────────────────────────┐
│        Rule Engines (4 engines)          │
├──────────────────────────────────────────┤
│ 1. OWASP Rules (owasp_rules.py)          │
│    • 23+ vulnerability rules             │
│    • Component detection                 │
│    • CVSS scoring                        │
│                                          │
│ 2. STRIDE Rules (stride_rules.py)       │
│    • 16+ threat patterns                 │
│    • Threat modeling                     │
│                                          │
│ 3. MITRE ATT&CK (mitre_attack_mapper.py)│
│    • 25+ attack techniques               │
│    • Attack path generation              │
│                                          │
│ 4. Security Scanner (security_scanner.py)│
│    • Orchestrates above 3                │
│    • Risk scoring (0-100)                │
│    • Compliance checking                 │
└──────────────────────────────────────────┘
```

## 🔄 How Each Endpoint Uses the Rules

### 1️⃣ `/api/analyze` - Full Security Analysis

**What it does:** Analyzes entire architecture for vulnerabilities

**How it uses rules:**

```python
# Step 1: Receive architecture
architecture_dict = {
    "nodes": [...],        # Components (web server, database, etc.)
    "connections": [...],  # How they connect
    "network_zones": [...] # Network segmentation
}

# Step 2: Run through Security Scanner
assessment = scanner.scan_architecture(architecture_dict)

# What scanner does internally:
┌─────────────────────────────────┐
│ scanner.scan_architecture()     │
├─────────────────────────────────┤
│ 1. Run OWASP Rules:             │
│    → Check A01 (Access Control) │
│    → Check A02 (Crypto Failures)│
│    → Check A03 (Injection)      │
│    → ... (all 10 categories)    │
│    → Result: List of findings   │
│                                 │
│ 2. Run STRIDE Rules:            │
│    → Check Spoofing threats     │
│    → Check Tampering threats    │
│    → Check Repudiation          │
│    → ... (all 6 categories)     │
│    → Result: List of threats    │
│                                 │
│ 3. Run MITRE ATT&CK:            │
│    → Check T1190 (Exploit)      │
│    → Check T1078 (Valid Accts)  │
│    → ... (25+ techniques)       │
│    → Result: Possible techniques│
│                                 │
│ 4. Calculate Risk Score:        │
│    → Count findings by severity │
│    → Apply weighted scoring     │
│    → Result: 0-100 score        │
│                                 │
│ 5. Generate Recommendations:    │
│    → Prioritize by severity     │
│    → Estimate effort/cost       │
│    → Result: Action items       │
└─────────────────────────────────┘

# Step 3: Return results
{
    "risk_assessment": {
        "total_score": 73.5,
        "risk_level": "HIGH",
        "owasp_violations": 12,
        "stride_threats": 8,
        "mitre_techniques": 15
    },
    "owasp_findings": [...],
    "stride_threats": [...],
    "mitre_attack_techniques": [...],
    "recommendations": [...]
}
```

**Example Rule Application:**

```python
# OWASP Rule: "Check for unencrypted database connections"
Rule: A02_CRYPTO_FAILURES_DB_NO_ENCRYPTION
Input: Database node with "encryption": false
Output: {
    "rule_id": "A02_CRYPTO_01",
    "title": "Unencrypted Database Connection",
    "severity": "HIGH",
    "cvss_score": 7.5,
    "affected_components": ["db1"],
    "mitigation": "Enable TLS encryption"
}
```

### 2️⃣ `/api/heal` - Generate Healed Architecture

**What it does:** Creates improved architecture with security controls added

**How it uses rules:**

```python
# Step 1: Run analysis first
assessment = scanner.scan_architecture(architecture_dict)

# Step 2: Based on findings, add security components
if any('firewall' in f.title.lower() for f in assessment.owasp_findings):
    # OWASP rule found missing firewall → Add firewall node
    add_firewall_node()

if any('injection' in f.title.lower() for f in assessment.owasp_findings):
    # OWASP rule found injection vulnerability → Add WAF
    add_waf_node()

if any('authentication' in f.title.lower() for f in assessment.owasp_findings):
    # OWASP rule found auth issue → Add MFA
    add_mfa_node()

# Step 3: Return healed architecture
{
    "healed_architecture": {
        "nodes": [...original + new security components...],
        "connections": [...updated connections...]
    },
    "changes_summary": {
        "components_added": ["Firewall", "WAF", "MFA"],
        "security_improvements": [...]
    }
}
```

### 3️⃣ `/api/validate-attack` - Attack Validation ⭐ NEW

**What it does:** Checks if a specific attack can succeed on the architecture

**How it uses rules:**

```python
# Step 1: Receive attack and architecture
attack_name = "SQL Injection"
architecture_dict = {...}

# Step 2: Run full security scan
assessment = scanner.scan_architecture(architecture_dict)
# This gives us all OWASP/STRIDE/MITRE findings

# Step 3: Use Attack Simulator to validate
validation_result = attack_simulator.validate_attack(
    attack_name, 
    architecture_dict, 
    assessment
)

# What attack_simulator does internally:
┌──────────────────────────────────────────────────────────┐
│ attack_simulator.validate_attack()                       │
├──────────────────────────────────────────────────────────┤
│ 1. Load attack definition from catalog:                  │
│    SQL_INJECTION = {                                     │
│        required_owasp: ["A03_INJECTION"],                │
│        required_components: ["database", "web server"],  │
│        blocked_by: ["waf", "input validation"],          │
│        mitre_technique: "T1190"                          │
│    }                                                     │
│                                                          │
│ 2. Check if required components exist:                  │
│    ✅ Found: "Web Server" (web1)                        │
│    ✅ Found: "Database" (db1)                           │
│    → Components present: TRUE                            │
│                                                          │
│ 3. Check if OWASP vulnerabilities exist:                │
│    Loop through assessment.owasp_findings:               │
│    ✅ Found: A03_INJECTION_SQL finding on db1           │
│    → Vulnerabilities present: TRUE                       │
│                                                          │
│ 4. Check if blocking controls exist:                    │
│    Loop through architecture nodes:                      │
│    ❌ No WAF found                                       │
│    ❌ No input validation found                         │
│    → Blocking controls absent: TRUE                      │
│                                                          │
│ 5. Calculate confidence score:                          │
│    confidence = (                                        │
│        component_score * 0.3 +    # 100% found = 0.3    │
│        vulnerability_score * 0.4 + # 100% found = 0.4   │
│        control_absence * 0.3       # 100% absent = 0.3  │
│    ) = 1.0 (100% confident)                             │
│                                                          │
│ 6. Generate attack path:                                │
│    path = [                                             │
│        "1. User sends SQL in input field",              │
│        "2. Web server forwards to database",            │
│        "3. Database executes malicious query",          │
│        "4. Data exfiltration successful"                │
│    ]                                                    │
│                                                          │
│ 7. List vulnerable components:                          │
│    vulnerable = ["web1", "db1"]                         │
└──────────────────────────────────────────────────────────┘

# Step 4: Return validation result
{
    "can_proceed": true,              # Attack possible!
    "attack_possible": true,
    "security_analysis": {
        "attack_feasibility": "HIGH",
        "confidence_score": 100.0,    # 100% confident
        "vulnerable_components": ["web1", "db1"],
        "reasons": [
            "Database lacks input validation",
            "Web server vulnerable to injection",
            "No WAF protection"
        ],
        "recommended_controls": ["WAF", "Input Validation"]
    }
}
```

**Rule Flow Example:**

```
User Request: "Is SQL Injection possible?"
                    │
                    ▼
        ┌───────────────────────┐
        │ Load Attack Catalog   │
        │ SQL Injection rules:  │
        │ - Needs A03 vuln      │
        │ - Needs database      │
        │ - Blocked by WAF      │
        └───────┬───────────────┘
                │
                ▼
        ┌───────────────────────┐
        │ Run OWASP Scanner     │
        │ Finds:                │
        │ ✅ A03_INJECTION      │
        │ ✅ A07_AUTH_FAIL      │
        │ ✅ A02_CRYPTO_FAIL    │
        └───────┬───────────────┘
                │
                ▼
        ┌───────────────────────┐
        │ Check Components      │
        │ ✅ Database found     │
        │ ✅ Web server found   │
        └───────┬───────────────┘
                │
                ▼
        ┌───────────────────────┐
        │ Check Controls        │
        │ ❌ No WAF             │
        │ ❌ No validation      │
        └───────┬───────────────┘
                │
                ▼
        ┌───────────────────────┐
        │ Calculate Confidence  │
        │ 85% confident         │
        │ attack is possible    │
        └───────┬───────────────┘
                │
                ▼
        Result: ATTACK POSSIBLE ⚠️
```

### 4️⃣ `/api/correct-architecture` - Attack-Specific Correction ⭐ NEW

**What it does:** Generates architecture that blocks the specific attack

**How it uses rules:**

```python
# Step 1: Validate attack first
validation_result = attack_simulator.validate_attack(...)

# Step 2: Generate attack-specific corrections
corrected_arch = _generate_attack_specific_correction(
    architecture_dict,
    attack_name,
    validation_result,
    assessment
)

# What _generate_attack_specific_correction does:
┌────────────────────────────────────────────────────────┐
│ Attack-Specific Correction Logic                       │
├────────────────────────────────────────────────────────┤
│ if 'sql injection' in attack_name.lower():            │
│     # Rule: SQL Injection blocked by WAF               │
│     add_component({                                    │
│         "type": "Web Application Firewall",            │
│         "rules": ["OWASP ModSecurity CRS"],            │
│         "features": ["SQL Injection Prevention"]       │
│     })                                                 │
│                                                        │
│ if 'ddos' in attack_name.lower():                     │
│     # Rule: DDoS blocked by Load Balancer             │
│     add_component({                                    │
│         "type": "Load Balancer",                       │
│         "features": ["Rate limiting", "DDoS mitigation"]│
│     })                                                 │
│                                                        │
│ if 'mitm' in attack_name.lower():                     │
│     # Rule: MITM blocked by VPN/TLS                   │
│     add_component({                                    │
│         "type": "VPN Gateway",                         │
│         "encryption": "AES-256",                       │
│         "protocols": ["TLS 1.3"]                       │
│     })                                                 │
│                                                        │
│ if 'brute force' in attack_name.lower():              │
│     # Rule: Brute force blocked by MFA                │
│     add_component({                                    │
│         "type": "MFA System",                          │
│         "methods": ["TOTP", "Biometric"]               │
│     })                                                 │
│                                                        │
│ # Always add general security if missing:             │
│ if not has_firewall():                                │
│     add_firewall()                                     │
│ if not has_siem():                                    │
│     add_siem()                                        │
└────────────────────────────────────────────────────────┘

# Step 3: Return corrected architecture
{
    "new_architecture": {
        "nodes": [...original + WAF + Firewall + SIEM...],
        "connections": [...]
    },
    "change_summary": {
        "added_components": ["WAF", "Firewall", "SIEM"],
        "security_improvements": [
            "Blocks SQL injection attacks",
            "Network segmentation",
            "Real-time monitoring"
        ]
    },
    "attack_mitigation": {
        "attack_name": "SQL Injection",
        "prevented": true,
        "confidence": 0.95
    }
}
```

## 🎯 Complete Workflow Example

Let's trace a complete SQL Injection attack simulation:

### Step 1: User Selects "SQL Injection" Attack

```
Frontend → POST /api/validate-attack
{
    "attack": {"attack_name": "SQL Injection"},
    "architecture": {
        "nodes": [
            {"id": "web1", "type": "Web Server"},
            {"id": "db1", "type": "Database", "encryption": false}
        ]
    }
}
```

### Step 2: Security Scanner Runs (OWASP Rules)

```python
# OWASP Scanner runs through all rules:

Rule A03_INJECTION_SQL:
    Input: Database node "db1" with no input validation
    Check: Does web server connect to database? YES
    Check: Is parameterized query used? NO
    Result: VULNERABILITY FOUND
    Output: {
        "rule_id": "A03_INJECTION_01",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "affected_components": ["db1", "web1"]
    }

Rule A02_CRYPTO_FAILURES:
    Input: Database with "encryption": false
    Check: Is data sensitive? YES (database)
    Result: VULNERABILITY FOUND
    Output: {
        "rule_id": "A02_CRYPTO_02",
        "severity": "HIGH",
        "cvss_score": 7.5
    }
```

### Step 3: Attack Simulator Validates

```python
# Load SQL Injection definition:
SQL_INJECTION = {
    "required_owasp": ["A03_INJECTION"],
    "required_components": ["database", "web server"],
    "blocked_by": ["waf", "input validation"]
}

# Check 1: Components
✅ "Web Server" found (web1)
✅ "Database" found (db1)

# Check 2: OWASP Vulnerabilities
✅ A03_INJECTION found (from scanner)

# Check 3: Blocking Controls
❌ No "waf" found in nodes
❌ No "input validation" in properties

# Calculate Confidence:
confidence = 0.85 (85% sure attack possible)

# Result:
{
    "is_possible": true,
    "confidence": 0.85,
    "vulnerable_components": ["web1", "db1"],
    "reasons": [
        "Database lacks input validation",
        "No WAF protection installed",
        "A03 Injection vulnerability present"
    ]
}
```

### Step 4: Frontend Shows "Attack Possible ⚠️"

User sees:
- ⚠️ Attack is possible with 85% confidence
- 2 vulnerable components
- 3 reasons why it's vulnerable

### Step 5: User Clicks "Generate Corrected Architecture"

```
Frontend → POST /api/correct-architecture
```

### Step 6: Correction Logic Runs

```python
# Attack-specific correction for SQL Injection:

1. Add WAF (primary defense):
   waf_node = {
       "id": "waf_1730896543",
       "type": "Web Application Firewall",
       "properties": {
           "rules": ["OWASP ModSecurity CRS", "SQL Injection Prevention"]
       }
   }

2. Add Firewall (network defense):
   firewall_node = {
       "id": "firewall_1730896543",
       "type": "Next-Gen Firewall",
       "properties": {
           "features": ["Deep packet inspection", "IPS"]
       }
   }

3. Add SIEM (monitoring):
   siem_node = {
       "id": "siem_1730896543",
       "type": "SIEM",
       "properties": {
           "features": ["Log aggregation", "Threat detection"]
       }
   }

# New architecture = Original + 3 security components
```

### Step 7: Frontend Shows Before/After Comparison

```
BEFORE:                      AFTER:
User → Web → Database        User → WAF → Web → Database
                             ↓           ↓
                          Firewall    SIEM
                                    (monitoring)

Risk Score: 85/100          Risk Score: 15/100
Status: VULNERABLE          Status: SECURED ✅
```

## 🔍 How Rules Are Structured

### OWASP Rule Example

```python
# In owasp_rules.py:

class OWASPRule:
    rule_id: str = "A03_INJECTION_01"
    owasp_category: str = "A03:2021-Injection"
    title: str = "Unvalidated Database Input"
    severity: str = "CRITICAL"
    cvss_score: float = 9.8
    
    def check(self, architecture):
        findings = []
        
        # Rule logic:
        for node in architecture.nodes:
            if node.type == "Database":
                # Check if web server connects to it
                connections = find_connections_to(node.id)
                
                for conn in connections:
                    if not has_input_validation(conn):
                        # VIOLATION FOUND!
                        findings.append({
                            "affected_components": [node.id],
                            "description": "Database lacks input validation",
                            "mitigation": "Add WAF or parameterized queries"
                        })
        
        return findings
```

### STRIDE Rule Example

```python
# In stride_rules.py:

class STRIDEThreat:
    category: str = "Tampering"
    threat_id: str = "T_TAMPERING_01"
    title: str = "Data Tampering in Transit"
    
    def check(self, architecture):
        threats = []
        
        # Rule logic:
        for connection in architecture.connections:
            if not connection.properties.get("encrypted"):
                # THREAT FOUND!
                threats.append({
                    "affected_asset": connection.id,
                    "description": "Unencrypted connection allows tampering",
                    "mitigation": "Enable TLS encryption"
                })
        
        return threats
```

### Attack Catalog Example

```python
# In attack_simulator.py:

ATTACK_CATALOG = {
    "SQL Injection": {
        "required_owasp": ["A03_INJECTION"],
        "required_components": ["database", "web server"],
        "blocked_by": ["waf", "input validation"],
        "mitre_technique": "T1190",
        "severity": "CRITICAL",
        "attack_path": [
            "1. Attacker sends malicious SQL input",
            "2. Web server forwards to database",
            "3. Database executes query",
            "4. Data exfiltration"
        ]
    },
    
    "DDoS Attack": {
        "required_owasp": ["A04_INSECURE_DESIGN"],
        "required_components": ["web server"],
        "blocked_by": ["load balancer", "rate limiter", "ddos protection"],
        "mitre_technique": "T1499",
        "severity": "HIGH",
        "attack_path": [
            "1. Flood server with requests",
            "2. Exhaust resources",
            "3. Service becomes unavailable"
        ]
    }
}
```

## 🎓 Key Concepts

### 1. Rule-Based = Deterministic
```
Same input → Same rules → Same output (always!)

vs LLM:
Same input → LLM reasoning → Different output (varies)
```

### 2. Layered Analysis
```
Layer 1: OWASP Rules → Find vulnerabilities
Layer 2: STRIDE Rules → Find threats
Layer 3: MITRE ATT&CK → Map attack techniques
Layer 4: Attack Simulator → Validate specific attacks
```

### 3. Confidence Scoring
```python
confidence = weighted_sum([
    component_match_score * 0.3,      # Are required components present?
    vulnerability_score * 0.4,         # Are required vulnerabilities present?
    control_absence_score * 0.3        # Are blocking controls absent?
])

# Example:
# Components: 100% match → 0.3
# Vulnerabilities: 100% match → 0.4
# Controls: 100% absent → 0.3
# Total confidence: 1.0 (100%)
```

### 4. Attack-Specific Mitigation
```
Attack Type → Specific Security Control

SQL Injection → WAF
DDoS → Load Balancer
MITM → VPN/TLS
Brute Force → MFA
Ransomware → Backup System
Phishing → Email Security
```

## 🎯 Summary: How Rules Are Used

1. **`/api/analyze`**: Runs OWASP + STRIDE + MITRE rules to find ALL issues
2. **`/api/heal`**: Uses rule findings to add appropriate security components
3. **`/api/validate-attack`**: Uses attack catalog + rule findings to check if SPECIFIC attack possible
4. **`/api/correct-architecture`**: Uses attack type + rules to add SPECIFIC security controls

**All without LLM - just pure rule-based logic!** 🎉

The rules are the "brain" of the system - they contain all the security knowledge encoded as if-then logic, pattern matching, and scoring algorithms.
