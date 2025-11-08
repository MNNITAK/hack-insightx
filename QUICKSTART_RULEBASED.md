# Quick Start Guide: Rule-Based Attack Simulation

## 🚀 Start the Server

```bash
# Navigate to backend directory
cd backend/api

# Start the rule-based server (Python 3.8+)
python security_agent_rulebased.py
```

Expected output:
```
🚀 Starting InsightX Rule-Based Security Agent...
🔒 Security Frameworks: OWASP Top 10, STRIDE, MITRE ATT&CK
⚡ Mode: 100% Rule-Based (No LLM dependency)
🔗 API will be available at: http://localhost:5000
📖 Docs available at: http://localhost:5000/docs
```

## ✅ Verify Server is Running

```bash
curl http://localhost:5000/health
```

Expected response:
```json
{
  "status": "healthy",
  "mode": "rule-based",
  "llm_dependency": false,
  "frameworks": ["OWASP Top 10 2021", "STRIDE", "MITRE ATT&CK"]
}
```

## 🧪 Test Attack Workflow

```bash
# Run the test script
python backend/test_attack_workflow.py
```

This will test:
1. ✅ SQL Injection validation and correction
2. ✅ DDoS Attack validation and correction
3. ✅ MITM Attack validation and correction

## 🎯 Use with Frontend

### Option 1: Use Existing Frontend (Recommended)
The frontend already calls `/api/validate-attack` and `/api/correct-architecture`. Just:

1. Make sure rule-based server is running on port 5000
2. Update frontend to point to port 5000 (if needed)
3. Use the attack simulation feature as normal!

### Option 2: Switch Between LLM and Rule-Based

**LLM Server (port 8000):**
```bash
python backend/api/security_agent.py
```

**Rule-Based Server (port 5000):**
```bash
python backend/api/security_agent_rulebased.py
```

Update `agentService.ts` to use desired port.

## 📝 Example API Calls

### Validate Attack
```bash
curl -X POST http://localhost:5000/api/validate-attack \
  -H "Content-Type: application/json" \
  -d '{
    "attack": {
      "attack_id": "sql_001",
      "attack_name": "SQL Injection",
      "category": "Injection",
      "configured_at": "2024-01-15T10:00:00Z",
      "parameters": {}
    },
    "architecture": {
      "metadata": {"company_name": "Test Co"},
      "nodes": [
        {"id": "web1", "type": "Web Server", "category": "Server"},
        {"id": "db1", "type": "Database", "category": "Database"}
      ],
      "connections": [
        {"id": "c1", "source": "web1", "target": "db1", "type": "TCP"}
      ],
      "network_zones": []
    }
  }'
```

### Get Corrected Architecture
```bash
curl -X POST http://localhost:5000/api/correct-architecture \
  -H "Content-Type: application/json" \
  -d '{
    "attack": {
      "attack_id": "sql_001",
      "attack_name": "SQL Injection",
      "category": "Injection",
      "configured_at": "2024-01-15T10:00:00Z",
      "parameters": {}
    },
    "architecture": {
      "metadata": {"company_name": "Test Co"},
      "nodes": [
        {"id": "web1", "type": "Web Server", "category": "Server"},
        {"id": "db1", "type": "Database", "category": "Database"}
      ],
      "connections": [
        {"id": "c1", "source": "web1", "target": "db1", "type": "TCP"}
      ],
      "network_zones": []
    }
  }'
```

## 🎬 Complete Workflow Example

```python
import requests

# 1. Define attack and architecture
attack = {
    "attack_id": "sql_001",
    "attack_name": "SQL Injection",
    "category": "Injection",
    "configured_at": "2024-01-15T10:00:00Z",
    "parameters": {}
}

architecture = {
    "metadata": {"company_name": "My Company"},
    "nodes": [
        {"id": "web1", "type": "Web Server", "category": "Server"},
        {"id": "db1", "type": "Database", "category": "Database"}
    ],
    "connections": [
        {"id": "c1", "source": "web1", "target": "db1", "type": "TCP"}
    ],
    "network_zones": []
}

# 2. Validate attack
validation = requests.post(
    "http://localhost:5000/api/validate-attack",
    json={"attack": attack, "architecture": architecture}
).json()

print(f"Attack possible: {validation['can_proceed']}")
print(f"Confidence: {validation['security_analysis']['confidence_score']}%")

# 3. Get corrected architecture
if validation['can_proceed']:
    correction = requests.post(
        "http://localhost:5000/api/correct-architecture",
        json={"attack": attack, "architecture": architecture}
    ).json()
    
    print(f"\nAdded {correction['change_summary']['components_added_count']} components:")
    for comp in correction['change_summary']['added_components']:
        print(f"  • {comp}")
    
    print(f"\nAttack now prevented: {correction['attack_mitigation']['prevented']}")
```

## 📚 Supported Attacks

Test any of these 20 attacks:

**Injection:** SQL Injection, XSS, Command Injection
**Network:** DDoS Attack, MITM, DNS Spoofing
**Auth:** Brute Force, Credential Stuffing, Session Hijacking
**Data:** Ransomware, Data Exfiltration, Cryptojacking
**Advanced:** Privilege Escalation, API Abuse, Container Escape, Supply Chain Attack, Insider Threat, Cloud Misconfiguration, IoT Compromise, Phishing

## 🔍 View API Documentation

Open in browser: http://localhost:5000/docs

Interactive Swagger UI with all endpoints and schemas.

## ❓ Troubleshooting

### Server won't start
```bash
# Check Python version (needs 3.8+)
python --version

# Install dependencies
pip install fastapi uvicorn

# Check if port 5000 is in use
netstat -ano | findstr :5000  # Windows
lsof -i :5000  # Mac/Linux
```

### Import errors
```bash
# Make sure you're in the right directory
cd backend/api
python security_agent_rulebased.py

# Or use absolute path
python c:/path/to/backend/api/security_agent_rulebased.py
```

### Test fails
```bash
# Make sure server is running first
curl http://localhost:5000/health

# Then run test
python backend/test_attack_workflow.py
```

## 🎉 Success Indicators

✅ Server starts without errors
✅ Health check returns "healthy"
✅ Test script completes all 3 attacks
✅ Validation returns confidence scores
✅ Correction adds security components
✅ Frontend shows attack simulation working

## 📊 Performance

- **Validation:** < 1 second
- **Correction:** 1-2 seconds
- **Full workflow:** 2-3 seconds total

vs LLM system: 15-20 seconds

## 💡 Next Steps

1. **Test with Frontend:** Use the attack simulation UI
2. **Try Different Attacks:** Test all 20 attack types
3. **Customize Rules:** Add company-specific rules in `backend/rules/`
4. **Export Results:** Save corrected architectures
5. **Compare Versions:** Use architecture versioning feature

## 🆘 Need Help?

- Check `RULE_BASED_ATTACK_WORKFLOW.md` for detailed documentation
- View API docs at http://localhost:5000/docs
- Run test script for examples
- Check server logs for errors

## 🎯 Key Takeaway

**Same workflow, 100% rule-based:**
1. Select attack → 2. Validate → 3. Get correction → 4. Compare!

No LLM needed, no API keys, works offline, 5-8x faster! 🚀
