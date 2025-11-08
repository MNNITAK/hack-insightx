# 🩹 Architecture Healing Feature - Complete Guide

## Overview

The **Architecture Healing** feature is the MVP feature of InsightX that provides comprehensive security analysis and automated remediation for cloud architectures. It runs all 20 attack simulations, detects vulnerabilities, and generates a secured architecture with detailed recommendations.

---

## 🎯 Key Features

### 1. **Comprehensive Vulnerability Scanning**
- Runs all 20 attack types automatically
- Analyzes architecture against every possible attack vector
- Provides detailed vulnerability reports with severity ratings

### 2. **AI-Powered Security Analysis**
- Uses Groq AI (qwen-2.5-72b-instruct) to analyze architecture
- Identifies exploit paths and affected components
- Calculates overall risk score (0-100)
- Categorizes vulnerabilities by severity (Critical/High/Medium/Low)

### 3. **Automated Architecture Healing**
- Generates fully secured architecture
- Adds necessary security components (WAF, Firewall, IDS/IPS, etc.)
- Implements defense-in-depth strategies
- Ensures compliance with security standards

### 4. **Visual Comparison View**
- Side-by-side comparison of vulnerable vs. secured architecture
- Color-coded components (Red = Vulnerable, Green = Secured)
- Interactive React Flow diagrams
- Detailed analysis panel with metrics

### 5. **Actionable Recommendations**
- Prioritized action items (Critical → Low)
- Implementation timeline estimates
- Cost estimates for each remediation
- Compliance requirements mapping

### 6. **PDF Report Generation** *(Coming Soon)*
- Downloadable comprehensive security report
- Vulnerability analysis details
- Architecture diagrams
- Step-by-step remediation guide

---

## 🚀 How to Use

### Step 1: Design Your Architecture
1. Open InsightX Architecture Builder
2. Drag and drop components onto the canvas
3. Connect components to create your system architecture
4. Configure component properties

### Step 2: Initiate Healing
1. Click the **🩹 Heal Architecture** button in the toolbar
2. Review the healing process overview
3. Click **🩹 Start Healing Process**

### Step 3: Wait for Analysis (30-60 seconds)
The healing agent will:
- ✅ Scan architecture for vulnerabilities
- ✅ Run all 20 attack simulations
- ✅ Generate secure architecture design
- ✅ Compile vulnerability report

### Step 4: Review Results
The Healing Modal displays:
- **Risk Score**: Overall security posture (0-100)
- **Vulnerabilities Found**: Count by severity
- **Vulnerable Attack Vectors**: Detailed list with impacts
- **Immediate Actions**: Critical fixes required
- **Remediation Summary**: Components added, timeline, cost

### Step 5: Compare Architectures
Click **View Comparison** to see:
- **Split View**: Vulnerable (left) vs. Secured (right)
- **Analysis Panel**: Risk assessment, vulnerabilities, improvements
- **Security Enhancements**: New components added
- **Implementation Details**: Timeline and cost estimates

### Step 6: Accept or Reject
- **✅ Accept**: Replace current architecture with secured version
- **❌ Reject**: Keep original architecture
- **📄 Download Report**: Get detailed PDF analysis

---

## 🔧 Technical Architecture

### Backend (FastAPI)
**File**: `backend/api/security_agent.py`

#### New Endpoint: `/heal`
```python
POST /heal
{
  "architecture": {
    "metadata": {...},
    "nodes": [...],
    "connections": [...]
  }
}
```

**Response**:
```json
{
  "healing_summary": {
    "total_vulnerabilities_found": 15,
    "overall_risk_score": 75,
    "security_posture": "HIGH",
    "mitigations_applied": 8
  },
  "vulnerability_analysis": {
    "vulnerable_attacks": [
      {
        "attack_id": "ATK001",
        "attack_name": "SQL Injection",
        "vulnerable": true,
        "severity": "HIGH",
        "affected_components": ["database", "web_server"],
        "exploit_path": "...",
        "impact": "Data breach"
      }
    ],
    "architecture_weaknesses": [...],
    "compliance_violations": [...]
  },
  "healed_architecture": {
    "nodes": [...],
    "connections": [...]
  },
  "recommendations": {
    "immediate_actions": [...],
    "implementation_timeline": "4-6 weeks",
    "estimated_total_cost": "$50,000",
    "risk_reduction": "85%"
  }
}
```

### Frontend (Next.js + React)

#### Components Created:

**1. HealingModal.tsx**
- Location: `app/components/healing/HealingModal.tsx`
- Features:
  - Progress indicator (4 stages)
  - Real-time status updates
  - Vulnerability summary cards
  - Risk score visualization
  - Immediate actions list

**2. HealingComparisonView.tsx**
- Location: `app/components/healing/HealingComparisonView.tsx`
- Features:
  - React Flow integration
  - Split/Single view toggle
  - Color-coded components
  - Interactive architecture diagrams
  - Analysis panel with metrics
  - Accept/Reject workflow

#### Integration Points:

**ArchitectureBuilder.tsx**:
```tsx
// New imports
import { HealingModal, HealingResult } from './components/healing/HealingModal';
import { HealingComparisonView } from './components/healing/HealingComparisonView';

// New state
const [isHealingModalOpen, setIsHealingModalOpen] = useState(false);
const [isHealingComparisonOpen, setIsHealingComparisonOpen] = useState(false);
const [healingResult, setHealingResult] = useState<HealingResult | null>(null);

// Toolbar button
<Button onClick={() => setIsHealingModalOpen(true)}>
  🩹 Heal Architecture
</Button>
```

---

## 📊 Attack Catalog (20 Types)

The healing agent tests against all these attacks:

| ID | Attack Name | Category |
|----|------------|----------|
| ATK001 | SQL Injection | injection |
| ATK002 | Cross-Site Scripting (XSS) | injection |
| ATK003 | DDoS Attack | availability |
| ATK004 | Man-in-the-Middle (MITM) | interception |
| ATK005 | Brute Force Attack | authentication |
| ATK006 | Zero-Day Exploit | exploitation |
| ATK007 | Ransomware | malware |
| ATK008 | Phishing | social_engineering |
| ATK009 | Privilege Escalation | privilege |
| ATK010 | Data Exfiltration | data_theft |
| ATK011 | API Abuse | application |
| ATK012 | Container Escape | container |
| ATK013 | Supply Chain Attack | supply_chain |
| ATK014 | Insider Threat | insider |
| ATK015 | Cloud Misconfiguration | configuration |
| ATK016 | IoT Device Compromise | iot |
| ATK017 | Credential Stuffing | authentication |
| ATK018 | DNS Spoofing | network |
| ATK019 | Session Hijacking | session |
| ATK020 | Cryptojacking | resource_abuse |

---

## 🛡️ Security Components Added

The healing agent may add these security components:

- **🛡️ WAF (Web Application Firewall)**: Blocks OWASP Top 10 attacks
- **🔥 Firewall**: Network traffic filtering
- **🚨 IDS/IPS**: Intrusion detection and prevention
- **🔐 VPN Gateway**: Secure remote access
- **🔍 SIEM**: Security monitoring and logging
- **🔑 Identity Provider**: Multi-factor authentication
- **📜 Certificate Authority**: SSL/TLS encryption
- **💻 Endpoint Protection**: Antivirus and EDR
- **🚫 DLP System**: Data loss prevention
- **🔐 Secrets Manager**: Secure credential storage

---

## 💰 Cost & Timeline Estimates

The healing agent provides realistic estimates:

### Example Output:
```json
{
  "estimated_total_cost": "$50,000 - $100,000",
  "implementation_timeline": "4-6 weeks",
  "risk_reduction": "85%",
  "immediate_actions": [
    {
      "action": "Deploy Web Application Firewall",
      "priority": "CRITICAL",
      "effort": "2-4 hours",
      "cost": "$5,000/year",
      "impact": "Blocks 90% of web attacks"
    }
  ]
}
```

---

## 🔄 Workflow Diagram

```
User Creates Architecture
         ↓
Clicks "Heal" Button
         ↓
Healing Modal Opens
         ↓
Backend Receives Architecture
         ↓
AI Analyzes 20 Attack Vectors
         ↓
Generates Vulnerability Report
         ↓
Creates Secured Architecture
         ↓
Returns Healing Result
         ↓
Comparison View Opens
         ↓
User Reviews Side-by-Side
         ↓
User Accepts/Rejects
         ↓
[Accept] → Architecture Updated & Saved
[Reject] → Original Architecture Retained
```

---

## 🧪 Testing the Feature

### 1. Start Backend Server
```bash
cd backend/api
python security_agent.py
```
Server runs on: `http://localhost:5000`

### 2. Start Frontend
```bash
cd client/src/my-next-app
npm run dev
```
Frontend runs on: `http://localhost:3000`

### 3. Create Vulnerable Architecture
Add these components:
- User Device
- Web Server (no WAF)
- Application Server
- Database (no encryption)
- File Storage

### 4. Run Healing
1. Click **🩹 Heal Architecture**
2. Wait 30-60 seconds
3. Review vulnerability analysis
4. View comparison
5. Accept secured architecture

### Expected Result:
- Risk score: ~75 → ~25
- Vulnerabilities: 10-15 → 0-2
- New components: WAF, Firewall, Encryption, IDS/IPS
- Timeline: 4-6 weeks
- Cost: $30,000 - $60,000

---

## 📄 PDF Export Feature (TODO)

### Planned Features:
1. **Executive Summary**
   - Risk score before/after
   - Total vulnerabilities found
   - Remediation ROI

2. **Detailed Vulnerability Report**
   - Each attack vector analyzed
   - Exploit paths documented
   - Affected components listed

3. **Architecture Diagrams**
   - Before: Vulnerable architecture
   - After: Secured architecture
   - Visual diff highlighting changes

4. **Remediation Roadmap**
   - Prioritized action items
   - Implementation timeline
   - Cost breakdown
   - Resource requirements

5. **Compliance Mapping**
   - OWASP Top 10
   - CIS Controls
   - PCI-DSS
   - GDPR
   - HIPAA

### Implementation Plan:
- Use **jsPDF** or **pdfkit** for generation
- Export React Flow diagrams as images
- Add company branding/logo support
- Include executive summary page
- Add download button in HealingModal

---

## 🎨 UI/UX Highlights

### Color Scheme:
- **Red/Pink**: Vulnerable components and high-risk areas
- **Green/Emerald**: Secured components and improvements
- **Blue**: Information and analysis
- **Orange**: Warnings and medium priority

### Interactive Elements:
- **Toggle Views**: Split / Vulnerable Only / Secured Only
- **Risk Score Gauge**: Visual representation of security posture
- **Severity Badges**: Color-coded vulnerability categories
- **Progress Indicator**: 4-stage healing process
- **Animated Connections**: Encrypted connections pulse

### Accessibility:
- Clear visual hierarchy
- High contrast colors
- Descriptive button labels
- Keyboard navigation support

---

## 🚀 Future Enhancements

### Phase 2:
- [ ] PDF export with detailed reports
- [ ] Email notifications for healing completion
- [ ] Scheduled automated healing scans
- [ ] Historical trend analysis
- [ ] Cost comparison calculator

### Phase 3:
- [ ] Custom attack vector definitions
- [ ] Industry-specific compliance templates
- [ ] Multi-architecture batch healing
- [ ] Integration with JIRA/ServiceNow
- [ ] Real-time monitoring integration

---

## 📞 Support & Documentation

### Key Files:
- Backend: `backend/api/security_agent.py`
- Frontend: `app/components/healing/*.tsx`
- Main Integration: `app/ArchitectureBuilder.tsx`

### API Documentation:
Available at: `http://localhost:5000/docs` (FastAPI auto-generated)

### Questions?
- Check `ATTACK_SIMULATION_GUIDE.md` for attack details
- Review component JSONs in `app/component_json/`
- See architecture examples in `public/sample-architectures/`

---

## 🎉 Success Metrics

The Healing feature is successful when:
- ✅ All 20 attacks are tested
- ✅ Risk score reduces by 70%+
- ✅ Critical vulnerabilities: 0
- ✅ Security components properly configured
- ✅ User can understand and implement recommendations
- ✅ Comparison view clearly shows improvements
- ✅ PDF report is comprehensive and actionable

---

**Built with ❤️ by the InsightX Team**

*Making cybersecurity accessible and automated for everyone.*
