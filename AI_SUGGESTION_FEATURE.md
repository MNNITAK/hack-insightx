# 🤖 AI Architecture Suggestion Feature

## Overview
The AI Suggestion feature allows users to generate complete system architectures from natural language descriptions using AI. Simply describe your company type, requirements, and components, and the AI will design a complete architecture with proper connections and positioning.

---

## Features

✅ **Natural Language Input** - Describe your system in plain English
✅ **Smart Component Selection** - AI chooses appropriate components based on description
✅ **Logical Connections** - Automatically creates realistic connections between components
✅ **Proper Positioning** - Components are positioned in logical tiers (user → web → app → data)
✅ **Auto-Save** - Generated architecture is automatically saved to localStorage
✅ **Canvas Display** - Immediately visible on the React Flow canvas

---

## How to Use

### 1. Click AI Suggestion Button
Located in the toolbar: **🤖 AI Suggestion** (purple button)

### 2. Describe Your Architecture
Enter a description like:
- "E-commerce platform with web servers, product database, payment gateway, and user authentication"
- "Healthcare system with patient records database, secure API, HIPAA-compliant storage"
- "SaaS application with multi-tenant architecture, microservices, Redis cache, and monitoring"

### 3. Generate & Review
- Click **Generate Architecture**
- AI analyzes your requirements (~10-20 seconds)
- Architecture appears on canvas
- Auto-saved to localStorage

---

## Backend Implementation

### Endpoint: `POST /api/generate-architecture`

**Location**: `backend/api/security_agent.py` (lines ~1275-1390)

**Request Body**:
```json
{
  "prompt": "Your architecture description here..."
}
```

**Response**:
```json
{
  "metadata": {
    "company_name": "E-commerce Platform",
    "architecture_type": "e-commerce",
    "created_at": "2025-01-16T14:30:00",
    "security_level": "high",
    "description": "Multi-tier e-commerce system"
  },
  "nodes": [
    {
      "id": "node_1",
      "type": "component",
      "name": "Load Balancer",
      "properties": {
        "component_type": "load_balancer",
        "description": "Distributes traffic across web servers",
        "tier": "web"
      },
      "position": {"x": 400, "y": 200}
    }
  ],
  "connections": [
    {
      "id": "conn_1",
      "source": "node_1",
      "target": "node_2",
      "type": "connection",
      "properties": {
        "protocol": "HTTPS",
        "encrypted": true,
        "description": "Encrypted web traffic"
      }
    }
  ]
}
```

### AI Prompt Strategy

**Component Types Available**:
- Web tier: web_server, load_balancer, cdn, api_gateway
- Application tier: app_server, microservice, container
- Data tier: database, cache_server, file_storage
- Security: firewall, waf, ids_ips, vpn_gateway
- Network: router, switch, proxy_server, dns_server
- Monitoring: monitoring_service, log_aggregator, siem
- User devices: user_workstation, mobile_device, iot_device

**Positioning Logic**:
- User tier: y=100
- Web tier: y=200
- Application tier: y=300
- Data tier: y=400
- Security: varied based on function
- X positions: spread horizontally to avoid overlap

**Guidelines**:
- 5-15 nodes depending on complexity
- Realistic connections (not everything to everything)
- Include security components for production systems
- Add caching if performance mentioned
- Add monitoring/logging for production

---

## Frontend Implementation

### Modal Component: `AISuggestionModal.tsx`

**Location**: `app/components/ai-suggestion/AISuggestionModal.tsx`

**Props**:
```typescript
interface AISuggestionModalProps {
  isOpen: boolean;
  onClose: () => void;
  onArchitectureGenerated: (architecture: any) => void;
}
```

**Features**:
- Large textarea (140 chars height) for prompt input
- Character counter (0/1000)
- 4 example prompts (click to use)
- Loading spinner during generation
- Error display with details
- Disabled state during generation

**Example Prompts Provided**:
1. E-commerce platform with payment gateway
2. Healthcare system with HIPAA compliance
3. SaaS with microservices and caching
4. Financial trading platform with real-time data

---

### Integration in ArchitectureBuilder

**State Management**:
```typescript
const [isAISuggestionModalOpen, setIsAISuggestionModalOpen] = useState(false);
```

**Handler Function**: `handleAIArchitectureGenerated(architecture)`
- Converts AI JSON to React Flow `Node<CustomNodeData>[]`
- Maps component_type to proper icons using `getComponentByType()`
- Creates `CustomEdgeData` for connections
- Updates canvas with `setNodes()` and `setEdges()`
- Updates architecture name
- Auto-saves after 500ms delay

**Conversion Logic**:
```typescript
const newNodes: Node<CustomNodeData>[] = architecture.nodes.map((node: any) => {
  const componentType = node.properties?.component_type || node.type || 'server';
  const componentConfig = getComponentByType(componentType);
  
  return {
    id: node.id,
    type: 'custom',
    position: node.position || { x: Math.random() * 500, y: Math.random() * 400 },
    data: {
      id: node.id,
      type: 'custom',
      component_type: componentType,
      name: node.name,
      icon: componentConfig?.icon || '📦',
      description: node.properties?.description || '',
      properties: node.properties || {},
      category: node.properties?.tier || 'infrastructure',
      configured: true
    } as CustomNodeData
  };
});
```

---

## Usage Examples

### Example 1: E-commerce Platform
**Prompt**:
```
I need an e-commerce platform with web servers, product catalog database, 
Redis cache for sessions, payment gateway integration, and secure user authentication.
```

**Generated Components**:
- Load Balancer (web tier)
- 2x Web Servers (web tier)
- Redis Cache (application tier)
- Application Servers (application tier)
- Product Database (data tier)
- User Auth Service (application tier)
- Payment Gateway (external integration)
- Firewall (security)

---

### Example 2: Healthcare System
**Prompt**:
```
Healthcare system with patient records database, secure API, 
HIPAA-compliant storage, and mobile access with encryption
```

**Generated Components**:
- API Gateway with WAF (web tier)
- Secure API Server (application tier)
- Patient Records Database (encrypted, data tier)
- File Storage (HIPAA-compliant, data tier)
- VPN Gateway (for mobile access)
- IDS/IPS (security monitoring)
- SIEM (compliance logging)
- Encryption Gateway

---

### Example 3: SaaS Application
**Prompt**:
```
SaaS application with multi-tenant architecture, microservices, 
Redis cache, and monitoring
```

**Generated Components**:
- CDN (content delivery)
- Load Balancer
- 3x Microservices (auth, api, worker)
- Redis Cache Cluster
- Multi-tenant Database (with isolation)
- Message Queue (for async processing)
- Monitoring Service
- Log Aggregator

---

## Error Handling

### Backend Errors
- **400**: Empty prompt provided
- **500**: AI failed to generate valid JSON
- **500**: JSON parsing failed

**Example Error Response**:
```json
{
  "detail": "Failed to parse generated architecture: Invalid JSON format"
}
```

### Frontend Error Display
```tsx
{error && (
  <div className="bg-red-50 border border-red-200 rounded-lg p-4">
    <span className="text-red-600">⚠️</span>
    <h4 className="font-semibold text-red-900">Error</h4>
    <p className="text-sm text-red-800">{error}</p>
  </div>
)}
```

---

## Testing

### Manual Test Steps

1. **Start Backend**:
```bash
cd backend/api
python security_agent.py
```

2. **Start Frontend**:
```bash
cd client/src/my-next-app
npm run dev
```

3. **Test Generation**:
   - Click "🤖 AI Suggestion" button
   - Enter test prompt: "Simple web app with database"
   - Click "Generate Architecture"
   - Wait for generation (~10-15 seconds)
   - Verify components appear on canvas
   - Check browser console for logs

4. **Test Auto-Save**:
   - After generation, click "💾 Save"
   - Refresh page
   - Click "📂 Load"
   - Verify architecture is saved

### Expected Output
- ✅ 3-8 nodes appear on canvas
- ✅ Nodes have proper icons and names
- ✅ Connections between nodes are visible
- ✅ Architecture name updates to generated name
- ✅ No console errors

---

## Troubleshooting

### Issue: "Failed to generate architecture"
**Cause**: Backend not running or AI error

**Solution**:
1. Check backend is running: `http://localhost:5000/health`
2. Check terminal for Python errors
3. Verify Groq API key is set
4. Try simpler prompt

### Issue: "Components overlap on canvas"
**Cause**: Position calculation overlap

**Solution**:
- Manually drag components to adjust
- Components can be repositioned after generation
- Future: Improve auto-layout algorithm

### Issue: "Invalid component types"
**Cause**: AI generated unknown component type

**Solution**:
- Check `getComponentByType()` in componentRegistry
- Falls back to generic '📦' icon
- Component still functional

### Issue: "No connections generated"
**Cause**: AI didn't create connections array

**Solution**:
- Manually add connections by dragging
- Connections array initialized as empty if missing
- Re-generate with more explicit prompt

---

## Future Enhancements

🔮 **Planned Features**:
- [ ] Architecture templates (starter prompts)
- [ ] Multi-step wizard for guided generation
- [ ] Preview mode before applying to canvas
- [ ] Edit generated architecture before accepting
- [ ] Save prompt history for reuse
- [ ] Generate variations from same prompt
- [ ] Import existing architecture and enhance with AI
- [ ] Cost estimation for generated architecture
- [ ] Compliance check (HIPAA, PCI-DSS, GDPR)

---

## Architecture Flow

```
┌─────────────────┐
│   User Input    │
│   (Prompt)      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Frontend Modal │
│  Send to API    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Backend API    │
│  /api/generate- │
│  architecture   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Groq AI LLM   │
│  (qwen model)   │
│  Analyze prompt │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  JSON Response  │
│  - metadata     │
│  - nodes        │
│  - connections  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Frontend       │
│  Convert to     │
│  React Flow     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Display on     │
│  Canvas         │
│  + Auto-save    │
└─────────────────┘
```

---

## Related Files

- **Backend**: `backend/api/security_agent.py` (lines 1275-1390)
- **Frontend Modal**: `app/components/ai-suggestion/AISuggestionModal.tsx`
- **Integration**: `app/ArchitectureBuilder.tsx` (handleAIArchitectureGenerated)
- **Types**: `app/types/index.ts` (CustomNodeData, CustomEdgeData)
- **Component Registry**: `app/utils/componentRegistry.ts` (getComponentByType)

---

**Feature Status**: ✅ Complete and Ready to Use
**Last Updated**: 2025-01-16
