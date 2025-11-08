# 🚀 Virtual Cybersecurity Sandbox

## Revolutionary Live Container Testing Environment

The Virtual Cybersecurity Sandbox transforms InsightX from a theoretical security architecture analyzer into an **operational cyber range** where your architectures come to life as real Docker containers for comprehensive security testing.

## 🌟 Key Features

### 🏗️ **Live Container Deployment**
- **Automatic Architecture Mapping**: Every component in your architecture becomes a live Docker container
- **Rule-Based Provisioning**: Intelligent container selection based on component types and security levels
- **Network Zone Simulation**: Recreate complex network topologies with proper isolation
- **Security Configuration**: Deploy containers in "vulnerable" or "hardened" configurations

### ⚡ **Real Attack Simulation**
- **Actual Penetration Testing Tools**: Uses real tools like Nmap, SQLMap, Metasploit, Hydra
- **20+ Attack Types**: Complete MITRE ATT&CK coverage from reconnaissance to impact
- **Attack Scenarios**: Pre-built multi-stage attack chains (APT, Web App, Insider Threat)
- **Configurable Parameters**: Customize attack intensity and targeting

### 🛡️ **Automated Defense Responses**
- **Real-Time Monitoring**: Live detection of security events across all containers
- **Rule-Based Detection**: 10+ detection rules for various attack patterns
- **Automated Mitigation**: Immediate response actions (block IPs, isolate containers, etc.)
- **Forensic Capabilities**: Automatic snapshots and evidence collection

### 📊 **3D Network Visualization**
- **Live Topology View**: Real-time 3D visualization of network topology
- **Attack Propagation**: Visual representation of attack paths and impact
- **Status Indicators**: Color-coded nodes showing health and threat status
- **Interactive Controls**: Mouse-controlled navigation and real-time updates

## 🏛️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                 Virtual Cybersecurity Sandbox              │
├─────────────────┬─────────────────┬─────────────────────────┤
│  Container      │   Attack        │   Defense Agent        │
│  Orchestrator   │   Simulator     │   (Real-time)          │
│                 │                 │                         │
│ • Docker Mgmt   │ • Real Tools    │ • Event Detection      │
│ • Network Setup │ • Attack Chains │ • Auto Response        │
│ • Health Mon.   │ • MITRE Mapping │ • Forensic Snapshots   │
└─────────────────┴─────────────────┴─────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                                   │
    ┌────▼────┐                         ┌────▼────┐
    │  Live   │                         │   3D    │
    │Containers│                         │ Network │
    │         │                         │  Viz    │
    │🐳 Web   │                         │         │
    │🐳 DB    │                         │📊 Real  │
    │🐳 WAF   │                         │📊 Time  │
    │🐳 FW    │                         │📊 Topo  │
    └─────────┘                         └─────────┘
```

## 🚦 Getting Started

### Prerequisites
- **Docker**: Version 20.10+ with daemon running
- **Python**: 3.8+ with pip
- **Node.js**: 16+ for frontend components
- **System**: Linux/macOS (Windows with WSL2)

### Installation

1. **Install Docker Dependencies**
```bash
# Install Docker (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install docker.io docker-compose

# Start Docker daemon
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group
sudo usermod -aG docker $USER
```

2. **Install Python Dependencies**
```bash
cd backend/sandbox
pip install -r requirements.txt
```

3. **Install Frontend Dependencies**
```bash
cd client/src/my-next-app
npm install three
# Three.js for 3D visualization
```

### Quick Start

1. **Start the Backend**
```bash
cd backend/api
python security_agent.py
```

2. **Open InsightX Frontend**
```bash
cd client/src/my-next-app
npm run dev
```

3. **Create Architecture**
   - Build your architecture using the visual editor
   - Add components (web servers, databases, firewalls, etc.)
   - Connect components with network links

4. **Launch Virtual Sandbox**
   - Click "🚀 Virtual Sandbox" in the toolbar
   - Choose security level (vulnerable/hardened)
   - Click "Deploy Live Sandbox"

5. **Execute Attacks**
   - Select attack type (Port Scan, SQL Injection, etc.)
   - Choose target container
   - Execute single attacks or full scenarios

6. **Monitor Defense**
   - Real-time security events appear automatically
   - Watch automated defense responses
   - View 3D network visualization

## 🎯 Attack Types Supported

### **Reconnaissance**
- **ATK001**: Port Scanning (Nmap)
- **ATK002**: Network Discovery
- **ATK006**: Web Vulnerability Scanning (Nikto)

### **Initial Access**
- **ATK003**: SQL Injection (SQLMap)
- **ATK009**: Phishing Simulation
- **ATK006**: Cross-Site Scripting (XSS)

### **Credential Access**
- **ATK002**: Brute Force Authentication (Hydra)
- **ATK014**: Insider Threat Simulation

### **Lateral Movement**
- **ATK007**: Network Propagation (Metasploit)
- **ATK005**: Command & Control (C2)

### **Impact**
- **ATK004**: DDoS Attacks (hping3)
- **ATK011**: Ransomware Simulation
- **ATK008**: Data Exfiltration

## 🛡️ Defense Capabilities

### **Detection Rules**
- Port scan detection (50+ connections/min)
- Brute force detection (10+ failed attempts)
- SQL injection pattern matching
- DDoS traffic analysis (100+ req/sec)
- Lateral movement detection
- Data exfiltration monitoring

### **Response Actions**
- **Block Source IP**: Automatic iptables rules
- **Container Isolation**: Network disconnection
- **Rate Limiting**: Traffic throttling
- **Forensic Snapshots**: Evidence preservation
- **Alert Generation**: Admin notifications
- **Configuration Reversion**: Unauthorized changes

## 📊 API Endpoints

### **Sandbox Management**
```http
POST /api/sandbox/deploy
GET  /api/sandbox/{id}/status
DELETE /api/sandbox/{id}
GET  /api/sandbox/list
```

### **Attack Execution**
```http
POST /api/sandbox/{id}/attack
POST /api/sandbox/{id}/attack-scenario
GET  /api/attack/{execution_id}/status
GET  /api/scenario/{scenario_id}/status
```

### **Security Monitoring**
```http
GET  /api/sandbox/{id}/security-events
GET  /api/security-event/{event_id}
GET  /api/security-dashboard
POST /api/sandbox/{id}/start-monitoring
```

### **Visualization**
```http
POST /api/sandbox/{id}/network-visualization
GET  /api/sandbox/{id}/metrics
```

## 🔧 Configuration

### **Container Rules**
Containers are provisioned based on component types:

```python
CONTAINER_RULES = {
    "web_server": {
        "vulnerable": {"disable_security_headers": True},
        "hardened": {"enable_security_headers": True}
    },
    "database": {
        "vulnerable": {"weak_password": "123456"},
        "hardened": {"strong_password": "SecureP@ss123!"}
    }
}
```

### **Attack Scenarios**
Pre-configured multi-stage attack chains:

```python
ATTACK_SCENARIOS = {
    "apt_simulation": {
        "stages": ["ATK001", "ATK009", "ATK007", "ATK010", "ATK008", "ATK011"],
        "duration": "2-4 hours"
    }
}
```

### **Detection Thresholds**
Customizable security detection rules:

```python
DETECTION_RULES = {
    "port_scan_detection": {
        "threshold": {"connections_per_minute": 50, "unique_ports": 10}
    },
    "brute_force_detection": {
        "threshold": {"failed_attempts": 10, "time_window": 300}
    }
}
```

## 🎮 Usage Examples

### **Basic Security Testing**
```bash
# 1. Deploy vulnerable web application
POST /api/sandbox/deploy
{
  "architecture": {...},
  "security_level": "vulnerable"
}

# 2. Execute SQL injection attack
POST /api/sandbox/{id}/attack
{
  "attack_id": "ATK003",
  "target_container_id": "web_server_1"
}

# 3. Monitor results
GET /api/attack/{execution_id}/status
```

### **Advanced Penetration Testing**
```bash
# Execute full APT scenario
POST /api/sandbox/{id}/attack-scenario
{
  "scenario_name": "apt_simulation",
  "target_components": ["web_server_1", "database_1"]
}

# Monitor scenario progress
GET /api/scenario/{scenario_id}/status
```

### **Defense Testing**
```bash
# Start real-time monitoring
POST /api/sandbox/{id}/start-monitoring

# Execute attacks and observe automated responses
GET /api/security-dashboard
```

## 🧪 Testing Scenarios

### **Web Application Security**
1. Deploy LAMP stack architecture
2. Execute web application attack chain
3. Observe WAF detection and response
4. Analyze security event timeline

### **Network Penetration**
1. Deploy multi-tier network
2. Execute reconnaissance and lateral movement
3. Monitor network traffic analysis
4. Test network segmentation effectiveness

### **Insider Threat**
1. Deploy corporate network simulation
2. Execute insider threat scenario
3. Test DLP and monitoring systems
4. Analyze behavioral anomaly detection

## 🚀 Advanced Features

### **Custom Attack Development**
Add new attack types by extending the attack simulator:

```python
def _execute_custom_attack(self, target_ip: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
    # Implement custom attack logic
    command = f"custom_tool --target {target_ip}"
    result = subprocess.run(command.split(), capture_output=True, text=True)
    return {"success": True, "output": result.stdout}
```

### **Defense Rule Customization**
Create custom detection rules:

```python
"custom_detection": {
    "description": "Custom threat pattern",
    "pattern": "suspicious_activity_indicator",
    "severity": "high",
    "response_actions": ["custom_response_action"]
}
```

### **Integration with SIEM**
Forward security events to external SIEM systems:

```python
def _forward_to_siem(self, event: SecurityEvent):
    # Forward to Splunk, ELK, QRadar, etc.
    siem_payload = self._format_for_siem(event)
    requests.post(SIEM_ENDPOINT, json=siem_payload)
```

## 🔍 Troubleshooting

### **Common Issues**

**Docker Permission Denied**
```bash
sudo usermod -aG docker $USER
newgrp docker
```

**Container Deployment Fails**
```bash
# Check Docker daemon
sudo systemctl status docker

# Check available resources
docker system df
docker system prune
```

**Network Connectivity Issues**
```bash
# Check Docker networks
docker network ls
docker network inspect sandbox_default

# Reset Docker networking
sudo systemctl restart docker
```

**Attack Tools Not Found**
```bash
# Install penetration testing tools
sudo apt-get install nmap sqlmap nikto hydra hping3
```

### **Performance Optimization**

**Container Resource Limits**
```python
container = self.docker_client.containers.run(
    image,
    mem_limit="512m",
    cpu_quota=50000,  # 50% CPU
    detach=True
)
```

**Monitoring Frequency Tuning**
```python
# Adjust polling intervals based on system capacity
NETWORK_MONITOR_INTERVAL = 5  # seconds
LOG_ANALYSIS_INTERVAL = 10    # seconds
SYSTEM_MONITOR_INTERVAL = 15  # seconds
```

## 🤝 Contributing

### **Adding New Attack Types**
1. Add attack definition to `at.json`
2. Implement attack execution in `attack_simulator.py`
3. Add detection rules in `defense_agent.py`
4. Update frontend attack catalog

### **Extending Container Support**
1. Add container rules to `container_orchestrator.py`
2. Create Docker images for new component types
3. Update component registry mapping
4. Add configuration templates

### **Improving Visualizations**
1. Enhance 3D network topology algorithms
2. Add new attack visualization effects
3. Implement custom node rendering
4. Add interactive network manipulation

## 📜 License

MIT License - see LICENSE file for details.

## 🙏 Acknowledgments

- **MITRE ATT&CK**: Attack pattern framework
- **OWASP**: Security testing methodologies
- **Docker**: Container orchestration platform
- **Three.js**: 3D visualization library
- **FastAPI**: High-performance web framework

## 📞 Support

For questions, issues, or contributions:
- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: Comprehensive API and usage docs
- **Community**: Join our Discord for real-time support

---

**🚀 Transform your security architectures from theoretical designs into operational cyber ranges with the Virtual Cybersecurity Sandbox!**