# InsightX Cyber Attack Simulation Backend

## Overview
FastAPI backend server providing AI-powered cyber attack validation and architecture correction using Groq AI and LangGraph workflows.

## Features
- ✅ **Attack Validation**: Analyzes if configured attacks are possible on current architecture
- 🔧 **Architecture Correction**: Generates improved architecture with security enhancements
- 🤖 **Groq AI Integration**: Uses `qwen-2.5-72b-instruct` model for intelligent analysis
- 🔄 **LangGraph Workflows**: StateGraph implementation for multi-step agent logic
- 🌐 **CORS Enabled**: Ready for frontend integration from localhost:3000

## Setup

### Prerequisites
- Python 3.8+
- pip

### Installation

1. Navigate to the backend directory:
```bash
cd backend
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### Configuration
The Groq API key is already configured in the code:
- **API Key**: `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`
- **Model**: `qwen-2.5-72b-instruct`

## Running the Server

Start the FastAPI server:
```bash
cd api
uvicorn security_agent:app --reload --host 0.0.0.0 --port 5000
```

Server will be available at: **http://localhost:5000**

### Endpoints

#### 1. POST `/api/validate-attack`
Validates if an attack is possible on the current architecture.

**Request Body:**
```json
{
  "attack": {
    "attack_id": "port_scanning",
    "attack_name": "Port Scanning",
    "parameters": {
      "target_node": "node-1"
    }
  },
  "architecture": {
    "metadata": {},
    "nodes": [...],
    "connections": [...],
    "network_zones": []
  }
}
```

**Response:**
```json
{
  "is_valid": true,
  "vulnerability_score": 75,
  "vulnerabilities": [
    "Open ports detected",
    "No firewall protection"
  ],
  "missing_components": []
}
```

#### 2. POST `/api/correct-architecture`
Generates improved architecture with security enhancements.

**Request Body:**
```json
{
  "attack": {
    "attack_id": "sql_injection",
    "attack_name": "SQL Injection"
  },
  "architecture": {
    "metadata": {},
    "nodes": [...],
    "connections": [...],
    "network_zones": []
  }
}
```

**Response:**
```json
{
  "new_architecture": {
    "components": [...],
    "connections": [...]
  },
  "change_summary": {
    "total_changes": 5,
    "added_components": [...],
    "modified_components": [...],
    "added_connections": [...],
    "security_improvements": [...],
    "mitigated_vulnerabilities": [...]
  },
  "attack_mitigation": {
    "attack_name": "SQL Injection",
    "prevented": true,
    "mitigation_techniques": [...]
  }
}
```

## Architecture

### LangGraph Workflows

#### Validation Workflow (`validator_graph`)
```
validate_attack → analyze_security → END
```

1. **validate_attack**: Checks if attack is possible
2. **analyze_security**: Analyzes vulnerabilities and security gaps

#### Correction Workflow (`corrector_graph`)
```
analyze_vulnerabilities → design_architecture → generate_recommendations → END
```

1. **analyze_vulnerabilities**: Identifies security weaknesses
2. **design_architecture**: Creates improved component layout
3. **generate_recommendations**: Generates detailed security improvements

### SecurityAgent Class
Main agent class handling:
- Groq ChatGroq model integration
- State management with TypedDict
- Node execution for validation and correction
- Fallback architecture generation
- JSON parsing with error handling

## Dependencies
```
fastapi==0.115.5
uvicorn[standard]==0.32.1
pydantic==2.10.3
langchain==0.3.13
langgraph==0.2.58
langchain-groq==0.2.1
```

## Testing

### Test Attack Validation
```bash
curl -X POST http://localhost:5000/api/validate-attack \
  -H "Content-Type: application/json" \
  -d '{
    "attack": {
      "attack_id": "port_scanning",
      "attack_name": "Port Scanning",
      "parameters": {"target_node": "node-1"}
    },
    "architecture": {
      "metadata": {"company_name": "Test", "architecture_type": "web", "created_at": "2024-01-01", "security_level": "medium"},
      "nodes": [{"id": "node-1", "type": "web_server", "name": "Web Server", "properties": {}, "position": {"x": 0, "y": 0}}],
      "connections": [],
      "network_zones": []
    }
  }'
```

### Test Architecture Correction
```bash
curl -X POST http://localhost:5000/api/correct-architecture \
  -H "Content-Type: application/json" \
  -d '{
    "attack": {
      "attack_id": "sql_injection",
      "attack_name": "SQL Injection",
      "parameters": {"target_node": "node-1"}
    },
    "architecture": {
      "metadata": {"company_name": "Test", "architecture_type": "web", "created_at": "2024-01-01", "security_level": "medium"},
      "nodes": [{"id": "node-1", "type": "web_server", "name": "Web Server", "properties": {}, "position": {"x": 0, "y": 0}}],
      "connections": [],
      "network_zones": []
    }
  }'
```

## Troubleshooting

### CORS Issues
- Ensure frontend is running on `localhost:3000`
- Check CORS settings in `security_agent.py`

### Groq API Errors
- Verify API key is valid
- Check internet connection
- Ensure model name is correct: `qwen-2.5-72b-instruct`

### JSON Parsing Errors
- Backend includes fallback logic if AI response is not valid JSON
- Check server logs for detailed error messages

## Development

### Adding New Attack Types
1. Update attack validation logic in `validate_attack` node
2. Add corresponding mitigation techniques in `design_architecture` node
3. Test with new attack configurations

### Modifying AI Prompts
- Edit prompts in node functions within `SecurityAgent` class
- Adjust temperature/parameters in ChatGroq initialization

### Extending State Schema
- Update `AgentState` TypedDict class
- Ensure all nodes handle new state fields

## Production Deployment

### Environment Variables
Create `.env` file:
```
GROQ_API_KEY=your_api_key_here
MODEL_NAME=qwen-2.5-72b-instruct
PORT=5000
ALLOWED_ORIGINS=http://localhost:3000,https://your-frontend.com
```

### Docker Deployment
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["uvicorn", "api.security_agent:app", "--host", "0.0.0.0", "--port", "5000"]
```

## Support
For issues or questions, please check:
- Server logs in terminal
- Network tab in browser DevTools
- FastAPI auto-docs at `http://localhost:5000/docs`
