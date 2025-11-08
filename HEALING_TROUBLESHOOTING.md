# 🩹 Healing Feature - Troubleshooting Guide

## Common Issues and Solutions

### Issue 1: "Healing Failed" Error

**Symptoms:**
- Clicking "🩹 Heal Architecture" shows "Healing Failed"
- Error message in modal

**Solutions:**

#### 1. Backend Server Not Running
```bash
# Start the backend server
cd backend/api
python security_agent.py
```

Expected output:
```
🚀 Starting InsightX Security Agent API Server...
📡 Model: qwen/qwen-2.5-72b-instruct
🔗 API will be available at: http://localhost:5000
📖 Docs available at: http://localhost:5000/docs
INFO:     Uvicorn running on http://0.0.0.0:5000
```

#### 2. Check Backend Health
Open browser: `http://localhost:5000/health`

Expected response:
```json
{
  "status": "healthy",
  "model": "qwen/qwen-2.5-72b-instruct"
}
```

#### 3. CORS Issues
If you see CORS errors in browser console, check `security_agent.py`:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Should match your frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

#### 4. Check Groq API Key
In `security_agent.py`, verify:
```python
GROQ_API_KEY = "gsk_..."  # Should be valid Groq API key
```

Test API key:
```bash
curl https://api.groq.com/openai/v1/models \
  -H "Authorization: Bearer YOUR_API_KEY"
```

#### 5. Port Conflicts
If port 5000 is in use:
```bash
# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Change port in security_agent.py:
uvicorn.run(app, host="0.0.0.0", port=5001)  # Use different port

# Update HealingModal.tsx:
fetch('http://localhost:5001/heal', ...)  # Match new port
```

### Issue 2: Architecture Not Loading

**Symptoms:**
- Healing completes but comparison view is empty
- No nodes showing in healed architecture

**Solutions:**

#### Check Architecture Format
The backend expects:
```json
{
  "architecture": {
    "metadata": {
      "company_name": "string",
      "version": "string",
      "created_at": "ISO date"
    },
    "nodes": [
      {
        "id": "string",
        "component_type": "string",
        "name": "string",
        "position": {"x": number, "y": number},
        "properties": {}
      }
    ],
    "connections": [
      {
        "id": "string",
        "source": "string",
        "target": "string",
        "type": "string"
      }
    ]
  }
}
```

#### Verify in HealingModal.tsx (line 101-120)
```typescript
const architectureData = {
  metadata: {
    company_name: "Current Architecture",
    version: "1.0",
    created_at: new Date().toISOString()
  },
  nodes: architecture.nodes.map(node => ({
    id: node.id,
    component_type: node.data.component_type,  // Must exist
    name: node.data.name || node.data.component_type,
    position: node.position,
    properties: node.data.properties || {}
  })),
  connections: architecture.edges.map(edge => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    type: edge.type || 'default'
  }))
};
```

### Issue 3: Slow Response / Timeout

**Symptoms:**
- Healing takes more than 2 minutes
- Eventually times out

**Solutions:**

#### 1. Check Groq API Rate Limits
Free tier: 30 requests/minute
- Healing makes 3 API calls (analysis, healing, recommendations)
- Wait a minute and try again

#### 2. Reduce Architecture Complexity
For testing, use simple architectures:
- 3-5 components
- 2-4 connections

#### 3. Check Backend Logs
Look for errors in terminal running `security_agent.py`:
```
❌ Error in healing: ...
```

### Issue 4: JSON Parse Errors

**Symptoms:**
- Backend returns 500 error
- Logs show "Failed to parse JSON"

**Solutions:**

#### 1. AI Response Not Valid JSON
The AI sometimes returns markdown or text before JSON.

Check backend logs for:
```python
ai_response = agent.model.invoke(messages)
print("RAW AI RESPONSE:", ai_response.content)  # Add this line
```

#### 2. Add JSON Extraction
In `security_agent.py`, add helper:
```python
def extract_json(text: str) -> dict:
    """Extract JSON from AI response that might have markdown"""
    import re
    # Try to find JSON block
    json_match = re.search(r'```json\n(.*?)\n```', text, re.DOTALL)
    if json_match:
        text = json_match.group(1)
    
    # Remove markdown code blocks
    text = re.sub(r'```[a-z]*\n?', '', text)
    text = re.sub(r'\n?```', '', text)
    
    return json.loads(text.strip())
```

Use it:
```python
vulnerability_analysis = extract_json(ai_response.content)
```

### Issue 5: Empty Vulnerabilities

**Symptoms:**
- Healing completes successfully
- But shows 0 vulnerabilities found
- Risk score is very low

**Solutions:**

#### Architecture Too Simple
Add more complexity:
- Multiple tiers (web, app, database)
- No security components (no WAF, firewall, etc.)
- Direct connections (no encryption)

#### Example Vulnerable Architecture:
```
user_device → web_server → database
```

Should find 10-15 vulnerabilities.

### Issue 6: Frontend Not Updating

**Symptoms:**
- Healing completes
- Accept button clicked
- Architecture doesn't update

**Solutions:**

#### Check ArchitectureBuilder.tsx (line 1060-1085)
The `onAccept` handler should:
1. Convert healed nodes to ReactFlow format
2. Call `setNodes(healedNodes)`
3. Call `setEdges(healedEdges)`
4. Call `handleSave()`

Verify console logs:
```typescript
console.log('Accepting healed architecture:', healingResult);
console.log('Converted nodes:', healedNodes);
console.log('Converted edges:', healedEdges);
```

### Issue 7: PDF Download Not Working

**Status:** 📄 PDF export is marked as TODO

**Temporary Solution:**
The modal shows: "PDF download will be implemented next!"

**Planned Implementation:**
```bash
npm install jspdf html2canvas
```

```typescript
import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';

const downloadPDF = async () => {
  const doc = new jsPDF();
  // Add vulnerability report
  // Add architecture diagrams
  // Add recommendations
  doc.save('architecture-healing-report.pdf');
};
```

## Debugging Checklist

Before opening an issue, verify:

- [ ] Backend server is running (`http://localhost:5000/health` returns 200)
- [ ] Frontend can reach backend (no CORS errors in console)
- [ ] Groq API key is valid
- [ ] Architecture has at least 2-3 components
- [ ] Browser console (F12) shows detailed errors
- [ ] Backend terminal shows request logs
- [ ] Network tab shows `/heal` request details
- [ ] Response body contains valid JSON

## Getting Detailed Logs

### Frontend (Browser Console - F12)
```javascript
// In HealingModal.tsx, add:
console.log('Architecture data being sent:', architectureData);
console.log('Fetch response status:', response.status);
console.log('Healing result received:', result);
```

### Backend (Terminal)
```python
# In security_agent.py, add:
print(f"📥 Received healing request")
print(f"📊 Architecture: {len(request.architecture.nodes)} nodes")
print(f"🤖 Calling Groq AI...")
print(f"✅ AI response length: {len(ai_response.content)}")
print(f"📤 Sending response")
```

## Test Backend Directly

Use curl or Postman:

```bash
curl -X POST http://localhost:5000/heal \
  -H "Content-Type: application/json" \
  -d '{
    "architecture": {
      "metadata": {
        "company_name": "Test",
        "version": "1.0",
        "created_at": "2025-01-01T00:00:00Z"
      },
      "nodes": [
        {
          "id": "node1",
          "component_type": "web_server",
          "name": "Web Server",
          "position": {"x": 100, "y": 100},
          "properties": {}
        },
        {
          "id": "node2",
          "component_type": "database",
          "name": "Database",
          "position": {"x": 300, "y": 100},
          "properties": {}
        }
      ],
      "connections": [
        {
          "id": "edge1",
          "source": "node1",
          "target": "node2",
          "type": "default"
        }
      ]
    }
  }'
```

Expected: JSON response with `healing_summary`, `vulnerability_analysis`, etc.

## Still Not Working?

1. **Check versions:**
   ```bash
   python --version  # Should be 3.8+
   node --version    # Should be 18+
   ```

2. **Reinstall dependencies:**
   ```bash
   # Backend
   cd backend/api
   pip install -r requirements.txt

   # Frontend
   cd client/src/my-next-app
   npm install
   ```

3. **Clear caches:**
   ```bash
   # Frontend
   rm -rf .next
   npm run dev

   # Browser
   Hard refresh: Ctrl+Shift+R
   ```

4. **Check firewall/antivirus:**
   - Allow Python through firewall
   - Allow Node.js through firewall
   - Whitelist localhost:3000 and localhost:5000

## Contact Support

If none of these solutions work:

1. Share backend terminal output
2. Share browser console errors (F12)
3. Share network tab details of `/heal` request
4. Share your architecture JSON
5. Share OS/browser version

---

**Last Updated:** October 30, 2025
