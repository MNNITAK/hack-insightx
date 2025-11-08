# InsightX Cyber Attack Simulation System - Complete Documentation

## 🎯 System Overview
Complete end-to-end cyber attack simulation system with AI-powered architecture validation and correction.

## 🏗️ Architecture


```


┌─────────────────────────────────────────────────────────────────┐
│                     Frontend (Next.js + React)                   │
│  ┌────────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │ Architecture   │  │   Attack     │  │   Comparison        │ │
│  │    Builder     │→ │ Simulation   │→ │      View           │ │
│  │                │  │    Modal     │  │                     │ │
│  └────────────────┘  └──────────────┘  └─────────────────────┘ │
│           ↓                 ↓                      ↑            │
│  ┌────────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │   Storage      │  │   Agent      │  │   Versioning        │ │
│  │   (localStorage)│  │   Service    │  │      UI             │ │
│  └────────────────┘  └──────────────┘  └─────────────────────┘ │
└─────────────────────────────────│───────────────────────────────┘
                                  │ HTTP API
                                  ↓
┌─────────────────────────────────────────────────────────────────┐
│                  Backend (FastAPI + LangGraph)                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              SecurityAgent (Groq AI)                       │ │
│  │  ┌──────────────────┐      ┌──────────────────────┐      │ │
│  │  │ Validator Graph  │      │  Corrector Graph     │      │ │
│  │  │  • validate      │      │  • analyze           │      │ │
│  │  │  • analyze       │      │  • design            │      │ │
│  │  │                  │      │  • recommend         │      │ │
│  │  └──────────────────┘      └──────────────────────┘      │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## 📋 Features

### ✅ Completed Features

#### 1. Attack Simulation System
- **20 Attack Types**: Comprehensive catalog from `at.json`
  - Network: Port Scanning, DDoS, Man-in-the-Middle
  - Application: SQL Injection, XSS, CSRF
  - Infrastructure: Ransomware, Botnet, Zero-Day Exploit
  - And 11 more attack vectors

#### 2. Attack Configuration Modal
- Dark-themed UI with attack catalog browser
- Category filtering and search
- Dynamic parameter inputs (text, select, node_selector)
- Node selection from current architecture
- Attack preview and configuration

#### 3. AI-Powered Validation Agent
- Validates if attack is possible on current architecture
- Analyzes security vulnerabilities
- Identifies missing security components
- Provides vulnerability scoring (0-100)

#### 4. Architecture Correction Agent
- Generates improved architecture with security enhancements
- Adds security components (Firewall, IDS, WAF, etc.)
- Modifies existing components with security configurations
- Creates new secure connections
- Provides detailed change summary

#### 5. Comparison View
- Side-by-side architecture comparison
- Original vs. Improved architecture display
- Change summary with color-coded indicators:
  - 🟢 Green: Added components
  - 🟡 Yellow: Modified components
  - 🔵 Blue: New connections
- Security improvements list
- Mitigated vulnerabilities tracking
- Accept/Reject workflow

#### 6. Architecture Versioning
- Save architecture snapshots
- Timeline view of all versions
- Version metadata tracking
- Load previous versions
- Delete unwanted versions
- Compare versions (UI ready, logic pending)

#### 7. Storage System
- localStorage for persistence
- Attack history tracking
- Architecture snapshots
- Version management

## 🔧 Technical Stack

### Frontend
- **Framework**: Next.js 16.0.0 with Turbopack
- **UI Library**: React 19.2.0
- **Diagram Library**: React Flow 11.11.4
- **Language**: TypeScript
- **Styling**: Tailwind CSS (dark theme)
- **State Management**: React hooks + localStorage

### Backend
- **Framework**: FastAPI 0.115.5
- **AI**: Groq AI with ChatGroq
- **Model**: `qwen-2.5-72b-instruct`
- **Workflow**: LangGraph 0.2.58 with StateGraph
- **Language**: Python 3.8+
- **Validation**: Pydantic 2.10.3

## 📁 Project Structure

```
client/src/my-next-app/
├── app/
│   ├── components/
│   │   ├── AttackSimulationModal.tsx      # Attack configuration UI (415 lines)
│   │   ├── ComparisonView.tsx              # Architecture comparison (350 lines)
│   │   ├── ArchitectureVersioning.tsx      # Version management (380 lines)
│   │   └── flow/
│   │       ├── FlowCanvas.tsx
│   │       └── ComponentSidebar.tsx
│   ├── types/
│   │   ├── attack.ts                       # Attack type definitions (274 lines)
│   │   └── index.ts                        # Core types
│   ├── utils/
│   │   ├── attackStorage.ts                # localStorage management (255 lines)
│   │   ├── agentService.ts                 # API client (276 lines)
│   │   └── architectureStorage.ts
│   └── ArchitectureBuilder.tsx             # Main app (1000+ lines)
│
backend/
├── api/
│   └── security_agent.py                   # FastAPI server (566 lines)
├── requirements.txt                         # Python dependencies
└── README.md                               # Backend documentation
```

## 🚀 Getting Started

### Frontend Setup

1. **Navigate to client directory**:
```bash
cd client/src/my-next-app
```

2. **Install dependencies**:
```bash
npm install
```

3. **Run development server**:
```bash
npm run dev
```

Frontend will be available at: **http://localhost:3000**

### Backend Setup

1. **Navigate to backend directory**:
```bash
cd backend
```

2. **Create virtual environment**:
```bash
python -m venv venv
venv\Scripts\activate  # Windows
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Start server**:
```bash
cd api
uvicorn security_agent:app --reload --port 5000
```

Backend will be available at: **http://localhost:5000**

## 🔄 Complete Workflow

### Step 1: Build Architecture
1. Open ArchitectureBuilder at `localhost:3000`
2. Add components from sidebar (Web Server, Database, Load Balancer, etc.)
3. Connect components by dragging edges
4. Configure component properties

### Step 2: Configure Attack
1. Click **⚡ Cyber Attacks** button in toolbar
2. Browse 20 attack types by category
3. Select attack (e.g., "SQL Injection")
4. Configure attack parameters:
   - Select target node
   - Set attack vector
   - Configure payload options
5. Click **Run Attack Simulation**

### Step 3: AI Validation (Backend)
1. Frontend sends attack config + architecture to `/api/validate-attack`
2. Backend LangGraph validator workflow executes:
   - **validate_attack node**: Checks if attack is possible
   - **analyze_security node**: Analyzes vulnerabilities
3. Returns validation result with vulnerability score

### Step 4: Architecture Correction (Backend)
1. If attack is valid, frontend calls `/api/correct-architecture`
2. Backend LangGraph corrector workflow executes:
   - **analyze_vulnerabilities**: Identifies weaknesses
   - **design_architecture**: Creates improved layout
   - **generate_recommendations**: Lists security improvements
3. Returns corrected architecture with change summary

### Step 5: Review Comparison
1. ComparisonView opens with side-by-side display
2. User reviews:
   - Original vs. Improved architecture
   - Added components (Firewall, IDS, WAF)
   - Modified configurations
   - New secure connections
   - Security improvements list
   - Mitigated vulnerabilities
3. User can:
   - **Accept**: Apply improved architecture
   - **Reject**: Keep original architecture

### Step 6: Version Management
1. Click **📚 Versions** button in toolbar
2. Save current architecture as new version
3. View version timeline with metadata
4. Load previous versions
5. Compare different versions

## 🎨 UI Components

### Attack Simulation Modal
- **Dark theme** with gradient backgrounds
- **Search bar** for filtering attacks
- **Category tabs**: Network, Application, Infrastructure, etc.
- **Attack cards** with icons, names, and descriptions
- **Dynamic parameter form** adapts to attack type
- **Node selector** for targeting specific components
- **Configuration preview** before execution

### Comparison View
- **Three tabs**:
  1. **Side-by-Side**: Dual React Flow canvases
  2. **Changes Summary**: Detailed change list
  3. **Security Improvements**: Recommendations
- **Color-coded changes**:
  - 🟢 Added components
  - 🟡 Modified components
  - 🔵 New connections
- **Action buttons**: Accept/Reject
- **Statistics**: Total changes, improvements count

### Architecture Versioning
- **Timeline list** with version cards
- **Version details panel**:
  - Metadata (name, timestamp, description)
  - Statistics (components, connections, security features)
  - Component list
  - Security improvements
- **Actions**: Load, Delete, Compare
- **Save current** as new version

## 📊 Data Models

### Attack Configuration
```typescript
interface ConfiguredAttack {
  attack_id: string;
  attack_name: string;
  attack_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  parameters: {
    target_node?: string;
    attack_vector?: string;
    [key: string]: any;
  };
  target_nodes: string[];
  metadata: {
    configured_at: string;
  };
}
```

### Attack Validation Result
```typescript
interface AttackValidationResult {
  is_valid: boolean;
  vulnerability_score: number;
  vulnerabilities: string[];
  missing_components?: string[];
}
```

### Suggested Architecture
```typescript
interface SuggestedArchitecture {
  new_architecture: {
    components: Array<{
      id: string;
      type: string;
      label: string;
      properties: Record<string, any>;
      position: { x: number; y: number };
    }>;
    connections: Array<{
      id: string;
      source: string;
      target: string;
      type: string;
    }>;
  };
  change_summary: {
    total_changes: number;
    added_components: Array<{
      type: string;
      label: string;
      reason: string;
    }>;
    modified_components: Array<{
      id: string;
      changes: string[];
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
    attack_name: string;
    prevented: boolean;
    mitigation_techniques: string[];
  };
}
```

## 🔌 API Endpoints

### POST `/api/validate-attack`
Validates if attack is possible on current architecture.

**Request:**
```json
{
  "attack": { /* ConfiguredAttack */ },
  "architecture": { /* Architecture */ }
}
```

**Response:**
```json
{
  "is_valid": true,
  "vulnerability_score": 75,
  "vulnerabilities": ["Open ports", "No firewall"],
  "missing_components": []
}
```

### POST `/api/correct-architecture`
Generates improved architecture with security enhancements.

**Request:**
```json
{
  "attack": { /* ConfiguredAttack */ },
  "architecture": { /* Architecture */ }
}
```

**Response:**
```json
{
  "new_architecture": { /* ImprovedArchitecture */ },
  "change_summary": { /* ChangeDetails */ },
  "attack_mitigation": { /* MitigationInfo */ }
}
```

## 🛡️ Security Features Added by AI

### Common Security Components
1. **Firewall**: Packet filtering, port blocking
2. **IDS/IPS**: Intrusion detection and prevention
3. **WAF**: Web application firewall
4. **Load Balancer**: Traffic distribution with security rules
5. **VPN**: Encrypted connections
6. **DMZ**: Demilitarized zone for public-facing services
7. **Security Monitoring**: Real-time threat detection
8. **Backup Systems**: Data redundancy
9. **Access Control**: Authentication and authorization
10. **Encryption**: Data protection at rest and in transit

### Example Security Improvements
For **SQL Injection Attack**:
- Add WAF before web server
- Implement input validation
- Add database firewall
- Enable query parameterization
- Add security monitoring
- Implement backup system

For **DDoS Attack**:
- Add load balancer with rate limiting
- Implement CDN
- Add DDoS protection service
- Configure auto-scaling
- Add traffic filtering

## 📈 Future Enhancements

### Planned Features
1. **Version Comparison**: Visual diff between two versions
2. **Attack Replay**: Re-run previous attacks
3. **Export Reports**: PDF/JSON export of analysis
4. **Real-time Monitoring**: Live attack simulation
5. **Multi-Attack Scenarios**: Combine multiple attacks
6. **Cost Analysis**: Estimate security implementation costs
7. **Compliance Checks**: GDPR, HIPAA, PCI-DSS validation
8. **Threat Intelligence**: Integration with threat feeds

### Potential Improvements
1. **Better AI Prompts**: More detailed and context-aware
2. **Caching**: Cache validation results
3. **Batch Operations**: Validate multiple attacks
4. **Visual Diff**: Highlight changes on canvas
5. **Animation**: Animate attack flow
6. **Collaboration**: Multi-user editing
7. **Templates**: Pre-built secure architectures
8. **Learning Mode**: Educational attack explanations

## 🐛 Known Issues & Limitations

### Current Limitations
1. **No Database**: All data in localStorage (browser-specific)
2. **Single User**: No authentication or multi-user support
3. **AI Dependency**: Requires Groq API key and internet
4. **JSON Parsing**: AI sometimes returns non-JSON text
5. **No Validation**: Limited input validation on parameters
6. **Performance**: Large architectures may be slow

### Workarounds
1. **Fallback Logic**: Frontend has simulation mode if backend fails
2. **Error Handling**: Try-catch blocks with user-friendly messages
3. **JSON Extraction**: Backend attempts to extract JSON from AI text
4. **Default Architecture**: Backend provides fallback if AI fails

## 🧪 Testing

### Manual Testing Checklist
- [ ] Attack modal opens and displays 20 attacks
- [ ] Attack configuration with node selection works
- [ ] Backend validates attack correctly
- [ ] Backend generates corrected architecture
- [ ] Comparison view shows changes correctly
- [ ] Accept button applies improved architecture
- [ ] Reject button keeps original architecture
- [ ] Version saving works
- [ ] Version loading works
- [ ] localStorage persists data across refresh

### Test Scenarios
1. **Port Scanning**: Target web server → Should add firewall
2. **SQL Injection**: Target database → Should add WAF and input validation
3. **DDoS**: Target load balancer → Should add DDoS protection
4. **Ransomware**: Target server → Should add backup and monitoring

## 📞 Support & Documentation

### Additional Resources
- **Frontend**: `client/src/my-next-app/README.md`
- **Backend**: `backend/README.md`
- **API Docs**: `http://localhost:5000/docs` (when backend is running)
- **Type Definitions**: See `app/types/attack.ts` and `app/types/index.ts`

### Configuration Files
- **Next.js**: `next.config.ts`
- **TypeScript**: `tsconfig.json`
- **Python Dependencies**: `requirements.txt`
- **FastAPI**: `security_agent.py`

## 🎉 Conclusion

This comprehensive cyber attack simulation system provides:
- **20 attack types** with configurable parameters
- **AI-powered validation** using Groq's advanced model
- **Intelligent architecture correction** with detailed recommendations
- **Visual comparison** of before/after architectures
- **Version management** for tracking improvements
- **Complete workflow** from attack to mitigation

The system is ready for:
- 🎓 **Educational purposes**: Learn about cyber attacks and defenses
- 🔬 **Security testing**: Validate architecture security
- 🏢 **Enterprise use**: Plan security improvements
- 🛠️ **Development**: Extend with more features

**Status**: ✅ All three requested features completed and integrated!
