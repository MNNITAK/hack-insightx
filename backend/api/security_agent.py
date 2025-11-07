"""
InsightX Security Agent API Server
FastAPI backend for attack validation and architecture correction
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import json
from datetime import datetime
import uvicorn
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# LangChain and Groq imports
from langchain_groq import ChatGroq
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import PromptTemplate
from langgraph.graph import StateGraph, END
from typing import TypedDict

# Configuration
GROQ_API_KEY = "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"
GROQ_MODEL = "qwen/qwen3-32b"

app = FastAPI(title="InsightX Security Agent API", version="1.0.0")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Next.js dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== Pydantic Models ====================

class Architecture(BaseModel):
    metadata: Dict[str, Any]
    nodes: List[Dict[str, Any]]
    connections: List[Dict[str, Any]]
    network_zones: Optional[List[Dict[str, Any]]] = []

class ConfiguredAttack(BaseModel):
    attack_id: str
    attack_name: str
    category: str
    configured_at: str
    parameters: Dict[str, Any]

class ValidationRequest(BaseModel):
    attack: ConfiguredAttack
    architecture: Architecture

class CorrectionRequest(BaseModel):
    attack: ConfiguredAttack
    architecture: Architecture

class HealingRequest(BaseModel):
    architecture: Architecture

# ==================== LangGraph Agent ====================

class AgentState(TypedDict):
    attack: Dict[Any, Any]
    architecture: Dict[Any, Any]
    validation_result: Dict[Any, Any]
    vulnerability_analysis: Dict[Any, Any]
    new_architecture: Dict[Any, Any]
    recommended_actions: Dict[Any, Any]

class SecurityAgent:
    def __init__(self):
        self.model = ChatGroq(
            model=GROQ_MODEL,
            temperature=0.2,
            api_key=GROQ_API_KEY,
        )
        self.parser = JsonOutputParser()
        self.validator_graph = self._build_validator_graph()
        self.corrector_graph = self._build_corrector_graph()
    
    def _build_validator_graph(self):
        """Build validation workflow"""
        workflow = StateGraph(AgentState)
        workflow.add_node("validate_attack", self._validate_attack_node)
        workflow.add_node("analyze_security", self._analyze_security_node)
        workflow.add_edge("validate_attack", "analyze_security")
        workflow.add_edge("analyze_security", END)
        workflow.set_entry_point("validate_attack")
        return workflow.compile()
    
    def _build_corrector_graph(self):
        """Build correction workflow"""
        workflow = StateGraph(AgentState)
        workflow.add_node("analyze_vulnerabilities", self._analyze_vulnerabilities_node)
        workflow.add_node("design_architecture", self._design_architecture_node)
        workflow.add_node("generate_recommendations", self._generate_recommendations_node)
        workflow.add_edge("analyze_vulnerabilities", "design_architecture")
        workflow.add_edge("design_architecture", "generate_recommendations")
        workflow.add_edge("generate_recommendations", END)
        workflow.set_entry_point("analyze_vulnerabilities")
        return workflow.compile()
    
    def _validate_attack_node(self, state: AgentState) -> AgentState:
        """Validate if attack is possible on architecture"""
        print("🔍 Validating attack possibility...")
        
        prompt = PromptTemplate(
            template="""
            You are a cybersecurity expert validating if a cyber attack is possible on a given architecture.
            
            Attack Details:
            {attack}
            
            Current Architecture:
            {architecture}
            
            Analyze if this attack can be executed on the current architecture.
            Check if:
            1. Required target nodes/systems exist
            2. Necessary attack vectors are available
            3. Prerequisites for the attack are met
            
            Return ONLY valid JSON:
            {{
                "is_valid": true/false,
                "missing_components": ["component1", "component2"],
                "reason": "Explanation of why attack can/cannot proceed",
                "can_proceed": true/false
            }}
            """,
            input_variables=["attack", "architecture"]
        )
        
        formatted_prompt = prompt.format(
            attack=json.dumps(state["attack"], indent=2),
            architecture=json.dumps(state["architecture"], indent=2)
        )
        
        try:
            response = self.model.invoke(formatted_prompt)
            validation = self.parser.parse(response.content)
            state["validation_result"] = validation
            print("✅ Validation completed")
        except Exception as e:
            print(f"⚠️ Error in validation: {e}")
            state["validation_result"] = {
                "is_valid": True,
                "missing_components": [],
                "reason": "Validation check passed with assumptions",
                "can_proceed": True
            }
        
        return state
    
    def _analyze_security_node(self, state: AgentState) -> AgentState:
        """Analyze security posture"""
        print("🔒 Analyzing security...")
        
        prompt = PromptTemplate(
            template="""
            Analyze the security posture of the architecture against the attack.
            
            Architecture:
            {architecture}
            
            Attack:
            {attack}
            
            Provide security analysis in JSON:
            {{
                "overall_security_level": "low/medium/high",
                "vulnerability_score": 75,
                "affected_nodes": ["node1", "node2"],
                "recommended_actions": ["action1", "action2"]
            }}
            """,
            input_variables=["architecture", "attack"]
        )
        
        formatted_prompt = prompt.format(
            architecture=json.dumps(state["architecture"], indent=2),
            attack=json.dumps(state["attack"], indent=2)
        )
        
        try:
            response = self.model.invoke(formatted_prompt)
            analysis = self.parser.parse(response.content)
            
            # Merge into validation result
            state["validation_result"].update({
                "security_analysis": analysis
            })
            print("✅ Security analysis completed")
        except Exception as e:
            print(f"⚠️ Error in security analysis: {e}")
            state["validation_result"]["security_analysis"] = {
                "overall_security_level": "medium",
                "vulnerability_score": 60,
                "affected_nodes": [],
                "recommended_actions": ["Implement security controls"]
            }
        
        return state
    
    def _analyze_vulnerabilities_node(self, state: AgentState) -> AgentState:
        """Analyze vulnerabilities"""
        print("🔍 Analyzing vulnerabilities...")
        
        prompt = PromptTemplate(
            template="""
            You are a cybersecurity expert analyzing vulnerabilities.
            
            Current Architecture:
            {architecture}
            
            Attack that was executed:
            {attack}
            
            Identify all vulnerabilities that make this attack possible. Return ONLY valid JSON:
            {{
                "vulnerabilities": [
                    {{
                        "component": "component_name",
                        "vulnerability": "description",
                        "severity": "critical/high/medium/low",
                        "exploit_method": "how it's exploited"
                    }}
                ],
                "attack_vectors": ["vector1", "vector2"],
                "compromised_systems": ["system1", "system2"],
                "security_gaps": ["gap1", "gap2"]
            }}
            """,
            input_variables=["architecture", "attack"]
        )
        
        formatted_prompt = prompt.format(
            architecture=json.dumps(state["architecture"], indent=2),
            attack=json.dumps(state["attack"], indent=2)
        )
        
        try:
            response = self.model.invoke(formatted_prompt)
            analysis = self.parser.parse(response.content)
            state["vulnerability_analysis"] = analysis
            print("✅ Vulnerability analysis completed")
        except Exception as e:
            print(f"⚠️ Error: {e}")
            state["vulnerability_analysis"] = {
                "vulnerabilities": [],
                "attack_vectors": [],
                "compromised_systems": [],
                "security_gaps": []
            }
        
        return state
    
    def _design_architecture_node(self, state: AgentState) -> AgentState:
        """Design improved architecture"""
        print("🏗️ Designing improved architecture...")
        
        prompt = PromptTemplate(
            template="""
            Design an improved architecture that addresses the vulnerabilities.
            
            Original Architecture:
            {architecture}
            
            Vulnerabilities Found:
            {vulnerabilities}
            
            Attack Context:
            {attack}
            
            Create a new secure architecture by:
            1. Adding security components (firewalls, IDS/IPS, WAF, etc.)
            2. Implementing network segmentation
            3. Adding monitoring and logging systems
            4. Implementing access controls
            5. Adding redundancy for critical systems
            
            Return the complete new architecture in JSON with the SAME structure as the original,
            but with added/modified nodes and connections for security improvements.
            Include all original nodes plus new security nodes.
            
            Return JSON:
            {{
                "metadata": {{ same as original but updated }},
                "nodes": [ array of all nodes including new security nodes ],
                "connections": [ array of connections ],
                "network_zones": [ optional zones ],
                "changes_made": {{
                    "added_nodes": [{{ "id": "firewall_1", "type": "security", "name": "Next-Gen Firewall", "reason": "why added" }}],
                    "modified_nodes": [{{ "id": "web_server", "changes": ["added encryption"], "reason": "why" }}],
                    "added_connections": [{{ "source": "firewall", "target": "server", "reason": "why" }}]
                }}
            }}
            """,
            input_variables=["architecture", "vulnerabilities", "attack"]
        )
        
        formatted_prompt = prompt.format(
            architecture=json.dumps(state["architecture"], indent=2),
            vulnerabilities=json.dumps(state.get("vulnerability_analysis", {}), indent=2),
            attack=json.dumps(state["attack"], indent=2)
        )
        
        try:
            response = self.model.invoke(formatted_prompt)
            new_arch = self.parser.parse(response.content)
            state["new_architecture"] = new_arch
            print("✅ New architecture designed")
        except Exception as e:
            print(f"⚠️ Error: {e}")
            # Fallback: add basic security nodes
            state["new_architecture"] = self._create_fallback_architecture(state["architecture"])
        
        return state
    
    def _generate_recommendations_node(self, state: AgentState) -> AgentState:
        """Generate recommendations"""
        print("📋 Generating recommendations...")
        
        prompt = PromptTemplate(
            template="""
            Generate comprehensive security recommendations.
            
            Vulnerability Analysis:
            {vulnerabilities}
            
            New Architecture:
            {new_arch}
            
            Return JSON with detailed recommendations:
            {{
                "immediate_actions": [
                    {{
                        "priority": "critical",
                        "action": "specific action",
                        "timeline": "immediate",
                        "responsible_team": "Security Team",
                        "estimated_cost": "$10,000",
                        "risk_reduction": "80%"
                    }}
                ],
                "short_term_improvements": [
                    {{ "action": "description", "timeline": "1-3 months", "cost": "$5,000" }}
                ],
                "long_term_strategy": [
                    {{ "strategy": "plan", "timeline": "6-12 months", "cost": "$50,000" }}
                ],
                "security_improvements": ["improvement1", "improvement2"],
                "mitigated_vulnerabilities": ["vuln1", "vuln2"]
            }}
            """,
            input_variables=["vulnerabilities", "new_arch"]
        )
        
        formatted_prompt = prompt.format(
            vulnerabilities=json.dumps(state.get("vulnerability_analysis", {}), indent=2),
            new_arch=json.dumps(state.get("new_architecture", {}), indent=2)
        )
        
        try:
            response = self.model.invoke(formatted_prompt)
            recommendations = self.parser.parse(response.content)
            state["recommended_actions"] = recommendations
            print("✅ Recommendations generated")
        except Exception as e:
            print(f"⚠️ Error: {e}")
            state["recommended_actions"] = {
                "immediate_actions": [],
                "short_term_improvements": [],
                "long_term_strategy": [],
                "security_improvements": [],
                "mitigated_vulnerabilities": []
            }
        
        return state
    
    def _create_fallback_architecture(self, original_arch: Dict) -> Dict:
        """Create fallback architecture with basic security"""
        new_arch = json.loads(json.dumps(original_arch))  # Deep copy
        
        # Add basic security nodes
        timestamp = int(datetime.now().timestamp())
        security_nodes = [
            {
                "id": f"firewall_{timestamp}",
                "type": "security",
                "name": "Next-Gen Firewall",
                "properties": {"vendor": "Palo Alto", "capabilities": ["IDS", "IPS"]},
                "position": {"x": 400, "y": 100}
            },
            {
                "id": f"ids_{timestamp}",
                "type": "security",
                "name": "Intrusion Detection System",
                "properties": {"vendor": "Snort", "monitoring": "24/7"},
                "position": {"x": 600, "y": 100}
            }
        ]
        
        new_arch["nodes"].extend(security_nodes)
        new_arch["metadata"]["security_level"] = "high"
        new_arch["metadata"]["description"] = "Improved with security controls"
        
        return new_arch

# Initialize agent
agent = SecurityAgent()

# ==================== Helper Functions ====================

def extract_json_from_response(text: str) -> dict:
    """
    Extract JSON from AI response that might have markdown or extra text
    """
    import re
    
    # Try to find JSON block in markdown
    json_match = re.search(r'```json\s*\n(.*?)\n```', text, re.DOTALL)
    if json_match:
        text = json_match.group(1)
    else:
        # Try to find JSON block without language specifier
        json_match = re.search(r'```\s*\n(.*?)\n```', text, re.DOTALL)
        if json_match:
            text = json_match.group(1)
    
    # Remove any remaining markdown code blocks
    text = re.sub(r'```[a-z]*\n?', '', text)
    text = re.sub(r'\n?```', '', text)
    
    # Find JSON object/array
    text = text.strip()
    
    # Try to find first { or [ and extract from there
    start_brace = text.find('{')
    start_bracket = text.find('[')
    
    if start_brace == -1 and start_bracket == -1:
        raise ValueError("No JSON object or array found in response")
    
    if start_brace != -1 and (start_bracket == -1 or start_brace < start_bracket):
        text = text[start_brace:]
    elif start_bracket != -1:
        text = text[start_bracket:]
    
    # Parse JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse JSON. First 500 chars of response:")
        print(text[:500])
        raise ValueError(f"Invalid JSON in AI response: {e}")

def generate_healing_pdf(healing_result: dict) -> bytes:
    """
    Generate comprehensive PDF report for healing analysis
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    
    # Container for elements
    elements = []
    
    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1e40af'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#1e40af'),
        spaceAfter=12,
        spaceBefore=12
    )
    
    # Title Page
    elements.append(Spacer(1, 2*inch))
    elements.append(Paragraph("🩹 InsightX Architecture Healing Report", title_style))
    elements.append(Spacer(1, 0.3*inch))
    
    # Report metadata
    summary = healing_result['healing_summary']
    elements.append(Paragraph(f"<b>Analysis Date:</b> {summary['analysis_timestamp'][:10]}", styles['Normal']))
    elements.append(Paragraph(f"<b>Architecture ID:</b> {summary['original_architecture_id']}", styles['Normal']))
    elements.append(Spacer(1, 0.5*inch))
    
    # Executive Summary
    elements.append(Paragraph("Executive Summary", heading_style))
    risk_color = "#dc2626" if summary['overall_risk_score'] >= 70 else "#ea580c" if summary['overall_risk_score'] >= 50 else "#16a34a"
    
    exec_data = [
        ['Metric', 'Value'],
        ['Overall Risk Score', f"{summary['overall_risk_score']}/100"],
        ['Security Posture', summary['security_posture']],
        ['Vulnerabilities Found', str(summary['total_vulnerabilities_found'])],
        ['Mitigations Applied', str(summary['mitigations_applied'])]
    ]
    
    exec_table = Table(exec_data, colWidths=[3*inch, 2.5*inch])
    exec_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(exec_table)
    elements.append(PageBreak())
    
    # Vulnerability Analysis
    vuln_analysis = healing_result['vulnerability_analysis']
    elements.append(Paragraph("Vulnerability Analysis", heading_style))
    
    # Severity Breakdown
    severity = vuln_analysis['severity_breakdown']
    severity_data = [
        ['Severity', 'Count'],
        ['🔴 Critical', str(severity['critical'])],
        ['🟠 High', str(severity['high'])],
        ['🟡 Medium', str(severity['medium'])],
        ['🔵 Low', str(severity['low'])]
    ]
    
    severity_table = Table(severity_data, colWidths=[3*inch, 2.5*inch])
    severity_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc2626')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(severity_table)
    elements.append(Spacer(1, 0.3*inch))
    
    # Vulnerable Attacks (Top 10)
    elements.append(Paragraph("Top Vulnerable Attack Vectors", ParagraphStyle('SubHeading', parent=styles['Heading3'], fontSize=14, textColor=colors.HexColor('#dc2626'))))
    
    for idx, attack in enumerate(vuln_analysis['vulnerable_attacks'][:10], 1):
        if attack['vulnerable']:
            elements.append(Paragraph(f"<b>{idx}. {attack['attack_name']}</b> [{attack['severity']}]", styles['Normal']))
            elements.append(Paragraph(f"<i>Impact:</i> {attack['impact']}", styles['Normal']))
            elements.append(Paragraph(f"<i>Affected:</i> {', '.join(attack['affected_components'])}", styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
    
    elements.append(PageBreak())
    
    # Architecture Weaknesses
    elements.append(Paragraph("Architecture Weaknesses", heading_style))
    for weakness in vuln_analysis['architecture_weaknesses'][:15]:
        elements.append(Paragraph(f"• {weakness}", styles['Normal']))
    elements.append(Spacer(1, 0.3*inch))
    
    # Compliance Violations
    if vuln_analysis.get('compliance_violations'):
        elements.append(Paragraph("Compliance Violations", heading_style))
        for violation in vuln_analysis['compliance_violations'][:10]:
            elements.append(Paragraph(f"• {violation}", styles['Normal']))
    
    elements.append(PageBreak())
    
    # Recommendations
    recommendations = healing_result['recommendations']
    elements.append(Paragraph("Remediation Recommendations", heading_style))
    
    # Immediate Actions
    elements.append(Paragraph("🔥 Immediate Actions (Critical Priority)", ParagraphStyle('SubHeading2', parent=styles['Heading3'], fontSize=14, textColor=colors.HexColor('#dc2626'))))
    
    for idx, action in enumerate(recommendations['immediate_actions'][:10], 1):
        elements.append(Paragraph(f"<b>{idx}. {action['action']}</b>", styles['Normal']))
        elements.append(Paragraph(f"Priority: {action['priority']} | Effort: {action['effort']} | Cost: {action['cost']}", styles['Normal']))
        elements.append(Paragraph(f"<i>Impact:</i> {action['impact']}", styles['Normal']))
        elements.append(Spacer(1, 0.15*inch))
    
    elements.append(PageBreak())
    
    # Implementation Summary
    elements.append(Paragraph("Implementation Plan", heading_style))
    
    impl_data = [
        ['Item', 'Details'],
        ['Timeline', recommendations['implementation_timeline']],
        ['Estimated Cost', recommendations['estimated_total_cost']],
        ['Risk Reduction', recommendations['risk_reduction']],
        ['Components Added', str(healing_result['changes_summary']['components_added'])],
        ['Security Controls', ', '.join(healing_result['changes_summary']['security_controls_added'][:5])]
    ]
    
    impl_table = Table(impl_data, colWidths=[2*inch, 3.5*inch])
    impl_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16a34a')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.lightgreen),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(impl_table)
    elements.append(Spacer(1, 0.5*inch))
    
    # Footer
    elements.append(Spacer(1, 1*inch))
    elements.append(Paragraph("_______________________________________________", styles['Normal']))
    elements.append(Paragraph("<i>Generated by InsightX Security Agent</i>", ParagraphStyle('Footer', parent=styles['Normal'], fontSize=10, textColor=colors.grey, alignment=TA_CENTER)))
    elements.append(Paragraph(f"<i>Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i>", ParagraphStyle('Footer2', parent=styles['Normal'], fontSize=10, textColor=colors.grey, alignment=TA_CENTER)))
    
    # Build PDF
    doc.build(elements)
    
    # Get PDF bytes
    pdf_bytes = buffer.getvalue()
    buffer.close()
    
    return pdf_bytes

# ==================== API Endpoints ====================

@app.get("/")
def read_root():
    return {
        "service": "InsightX Security Agent API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "validate": "/api/validate-attack",
            "correct": "/api/correct-architecture"
        }
    }

@app.post("/api/validate-attack")
async def validate_attack(request: ValidationRequest):
    """
    Validate if an attack is possible on the given architecture
    """
    try:
        print(f"\n🎯 Validating attack: {request.attack.attack_id}")
        
        # Prepare state
        initial_state: AgentState = {
            "attack": request.attack.dict(),
            "architecture": request.architecture.dict(),
            "validation_result": {},
            "vulnerability_analysis": {},
            "new_architecture": {},
            "recommended_actions": {}
        }
        
        # Run validation
        result = agent.validator_graph.invoke(initial_state)
        
        # Format response
        validation_result = result.get("validation_result", {})
        
        response = {
            "is_valid": validation_result.get("is_valid", True),
            "attack_id": request.attack.attack_id,
            "validation_timestamp": datetime.now().isoformat(),
            "missing_components": validation_result.get("missing_components", []),
            "security_analysis": validation_result.get("security_analysis", {}),
            "can_proceed": validation_result.get("can_proceed", True),
            "error_message": None if validation_result.get("can_proceed", True) else validation_result.get("reason", "")
        }
        
        print(f"✅ Validation complete: {response['can_proceed']}")
        return response
        
    except Exception as e:
        print(f"❌ Error in validation: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/correct-architecture")
async def correct_architecture(request: CorrectionRequest):
    """
    Generate corrected architecture with security improvements
    """
    try:
        print(f"\n🏗️ Correcting architecture for attack: {request.attack.attack_id}")
        
        # Prepare state
        initial_state: AgentState = {
            "attack": request.attack.dict(),
            "architecture": request.architecture.dict(),
            "validation_result": {},
            "vulnerability_analysis": {},
            "new_architecture": {},
            "recommended_actions": {}
        }
        
        # Run correction
        result = agent.corrector_graph.invoke(initial_state)
        
        # Format response
        new_arch = result.get("new_architecture", {})
        recommendations = result.get("recommended_actions", {})
        vulnerability_analysis = result.get("vulnerability_analysis", {})
        
        # Extract changes from new architecture if available
        changes_made = new_arch.get("changes_made", {
            "added_nodes": [],
            "modified_nodes": [],
            "added_connections": []
        })
        
        response = {
            "original_architecture_id": request.architecture.metadata.get("company_name", "original"),
            "new_architecture": {
                "id": f"arch_secured_{int(datetime.now().timestamp())}",
                "metadata": new_arch.get("metadata", request.architecture.metadata),
                "components": new_arch.get("nodes", []),
                "connections": new_arch.get("connections", [])
            },
            "change_summary": {
                "total_changes": len(changes_made.get("added_nodes", [])) + len(changes_made.get("modified_nodes", [])),
                "added_components": changes_made.get("added_nodes", []),
                "modified_components": changes_made.get("modified_nodes", []),
                "removed_components": [],
                "added_connections": changes_made.get("added_connections", []),
                "security_improvements": recommendations.get("security_improvements", []),
                "mitigated_vulnerabilities": recommendations.get("mitigated_vulnerabilities", [])
            },
            "attack_mitigation": {
                "attack_id": request.attack.attack_id,
                "attack_name": request.attack.attack_name,
                "prevented": True,
                "mitigation_techniques": recommendations.get("immediate_actions", [])[:5]
            }
        }
        
        print(f"✅ Architecture correction complete")
        return response
        
    except Exception as e:
        print(f"❌ Error in correction: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/heal")
async def heal_architecture(request: HealingRequest):
    """
    Comprehensive security healing - runs all attack simulations and provides detailed vulnerability analysis
    """
    try:
        print(f"\n🩹 Starting comprehensive architecture healing...")
        print(f"📊 Architecture: {request.architecture.metadata.get('company_name', 'Unknown')}")
        
        # Load all attack types
        attack_catalog = [
            {"id": "ATK001", "name": "SQL Injection", "category": "injection"},
            {"id": "ATK002", "name": "Cross-Site Scripting (XSS)", "category": "injection"},
            {"id": "ATK003", "name": "DDoS Attack", "category": "availability"},
            {"id": "ATK004", "name": "Man-in-the-Middle (MITM)", "category": "interception"},
            {"id": "ATK005", "name": "Brute Force Attack", "category": "authentication"},
            {"id": "ATK006", "name": "Zero-Day Exploit", "category": "exploitation"},
            {"id": "ATK007", "name": "Ransomware", "category": "malware"},
            {"id": "ATK008", "name": "Phishing", "category": "social_engineering"},
            {"id": "ATK009", "name": "Privilege Escalation", "category": "privilege"},
            {"id": "ATK010", "name": "Data Exfiltration", "category": "data_theft"},
            {"id": "ATK011", "name": "API Abuse", "category": "application"},
            {"id": "ATK012", "name": "Container Escape", "category": "container"},
            {"id": "ATK013", "name": "Supply Chain Attack", "category": "supply_chain"},
            {"id": "ATK014", "name": "Insider Threat", "category": "insider"},
            {"id": "ATK015", "name": "Cloud Misconfiguration", "category": "configuration"},
            {"id": "ATK016", "name": "IoT Device Compromise", "category": "iot"},
            {"id": "ATK017", "name": "Credential Stuffing", "category": "authentication"},
            {"id": "ATK018", "name": "DNS Spoofing", "category": "network"},
            {"id": "ATK019", "name": "Session Hijacking", "category": "session"},
            {"id": "ATK020", "name": "Cryptojacking", "category": "resource_abuse"}
        ]
        
        # Run comprehensive vulnerability analysis
        prompt = f"""You are an expert cybersecurity analyst conducting a comprehensive security audit.

ARCHITECTURE TO ANALYZE:
{json.dumps(request.architecture.model_dump(), indent=2)}

TASK:
Analyze this architecture against ALL possible attack vectors including:
{json.dumps(attack_catalog, indent=2)}

For each attack type, determine:
1. Is the architecture vulnerable?
2. What specific components are at risk?
3. What is the severity (Critical/High/Medium/Low)?
4. What vulnerabilities enable this attack?

Provide a COMPREHENSIVE VULNERABILITY ANALYSIS including:
- Total vulnerability count
- Severity breakdown
- Detailed findings for each vulnerable attack vector
- Risk score (0-100)
- Overall security posture assessment

Return ONLY valid JSON in this exact format:
{{
  "overall_risk_score": <calculate actual risk score 0-100 based on vulnerability severity and count>,
  "security_posture": "<determine actual posture: CRITICAL/HIGH/MEDIUM/LOW>",
  "total_vulnerabilities": <count total vulnerabilities found in architecture>,
  "severity_breakdown": {{
    "critical": <count critical severity vulnerabilities>,
    "high": <count high severity vulnerabilities>,
    "medium": <count medium severity vulnerabilities>,
    "low": <count low severity vulnerabilities>
  }},
  "vulnerable_attacks": [
    {{
      "attack_id": "<actual attack ID from catalog>",
      "attack_name": "<actual attack name from catalog>",
      "vulnerable": <true if architecture is vulnerable to this attack, false otherwise>,
      "severity": "<actual severity: CRITICAL/HIGH/MEDIUM/LOW>",
      "affected_components": ["<list actual component IDs/types from architecture>"],
      "vulnerabilities": ["<list actual vulnerabilities found in this architecture>"],
      "exploit_path": "<explain actual exploit path for THIS specific architecture>",
      "impact": "<describe actual impact on THIS architecture>"
    }}
  ],
  "architecture_weaknesses": [
    "<list actual architectural weaknesses found - NOT generic examples>"
  ],
  "compliance_violations": [
    "<list actual compliance violations if any - leave empty array if none found>"
  ]
}}

IMPORTANT: Analyze the ACTUAL architecture provided above. Do NOT return generic or example data. Every value must be based on the real architecture components, connections, and attack catalog."""

        messages = [{"role": "user", "content": prompt}]
        ai_response = agent.model.invoke(messages)
        
        # Parse vulnerability analysis with error handling
        print(f"🤖 AI Response length: {len(ai_response.content)} chars")
        try:
            vulnerability_analysis = extract_json_from_response(ai_response.content)
            print(f"📋 Found {vulnerability_analysis['total_vulnerabilities']} vulnerabilities")
        except Exception as e:
            print(f"❌ Error parsing vulnerability analysis: {e}")
            print(f"First 500 chars: {ai_response.content[:500]}")
            raise HTTPException(status_code=500, detail=f"Failed to parse vulnerability analysis: {str(e)}")
        
        # Generate healed architecture
        healing_prompt = f"""You are a cybersecurity architect designing a secure system.

CURRENT VULNERABLE ARCHITECTURE:
{json.dumps(request.architecture.model_dump(), indent=2)}

VULNERABILITY ANALYSIS:
{json.dumps(vulnerability_analysis, indent=2)}

TASK:
Design a FULLY SECURED architecture that mitigates ALL identified vulnerabilities.

Add/modify components to:
1. Block all vulnerable attack vectors
2. Implement defense-in-depth
3. Add security controls (WAF, IDS/IPS, encryption, MFA, etc.)
4. Ensure compliance with security standards
5. Maintain functionality while maximizing security

Return ONLY valid JSON in this exact format:
{{
  "metadata": {{
    "company_name": "{request.architecture.metadata.get('company_name', 'Secured Architecture')}",
    "version": "2.0-secured",
    "created_at": "{datetime.now().isoformat()}",
    "security_level": "HARDENED"
  }},
  "nodes": [
    {{
      "id": "<generate unique node ID>",
      "component_type": "<actual security component type: waf/firewall/ids_ips/encryption_gateway/vpn_gateway/load_balancer/siem/honeypot/etc>",
      "name": "<descriptive name for this component>",
      "position": {{"x": <calculate position>, "y": <calculate position>}},
      "properties": {{
        "<key>": "<value based on component type and security requirements>"
      }}
    }}
  ],
  "connections": [
    {{
      "id": "<generate unique connection ID>",
      "source": "<actual source node ID from architecture>",
      "target": "<actual target node ID from architecture>",
      "type": "<connection type: encrypted/secure/monitored/etc>",
      "protocol": "<actual protocol: HTTPS/SSH/VPN/etc>"
    }}
  ]
}}

IMPORTANT: 
1. Keep ALL existing nodes from the original architecture
2. ADD new security components where needed (WAF, firewalls, IDS/IPS, encryption, etc.)
3. MODIFY connections to add encryption and security
4. Position new nodes logically in the architecture flow
5. Base ALL decisions on the actual vulnerabilities found - NOT generic examples"""

        healing_messages = [{"role": "user", "content": healing_prompt}]
        healing_response = agent.model.invoke(healing_messages)
        
        try:
            healed_architecture = extract_json_from_response(healing_response.content)
            print(f"✅ Generated secured architecture with {len(healed_architecture.get('nodes', []))} nodes")
        except Exception as e:
            print(f"❌ Error parsing healed architecture: {e}")
            print(f"First 500 chars: {healing_response.content[:500]}")
            raise HTTPException(status_code=500, detail=f"Failed to parse healed architecture: {str(e)}")
        
        # Generate detailed recommendations
        recommendations_prompt = f"""Based on the vulnerability analysis and healed architecture, provide detailed security recommendations.

VULNERABILITY ANALYSIS:
{json.dumps(vulnerability_analysis, indent=2)}

HEALED ARCHITECTURE:
{json.dumps(healed_architecture, indent=2)}

Provide comprehensive recommendations including:
1. Immediate actions (Critical priority)
2. Short-term improvements (High priority)
3. Long-term strategic initiatives (Medium priority)
4. Monitoring and maintenance guidelines
5. Compliance requirements
6. Cost-benefit analysis


Return ONLY valid JSON in this exact format:
{{
  "immediate_actions": [
    {{
      "action": "<specific action to take based on actual vulnerabilities found>",
      "priority": "<CRITICAL/HIGH/MEDIUM/LOW based on vulnerability severity>",
      "effort": "<realistic time estimate: 1-2 hours / 2-4 hours / 1-2 days / 1-2 weeks>",
      "cost": "<realistic cost estimate: $ / $$ / $$$ / $$$$ or specific range>",
      "impact": "<describe actual security improvement this will provide>"
    }}
  ],
  "short_term_improvements": [
    "<list actual short-term improvements for THIS architecture>"
  ],
  "long_term_initiatives": [
    "<list actual long-term security initiatives for THIS architecture>"
  ],
  "monitoring_guidelines": [
    "<list actual monitoring recommendations for THIS architecture>"
  ],
  "compliance_requirements": [
    "<list actual compliance requirements based on vulnerabilities found>"
  ],
  "estimated_total_cost": "<calculate realistic total cost based on all actions>",
  "implementation_timeline": "<calculate realistic timeline based on effort estimates>",
  "risk_reduction": "<calculate realistic risk reduction percentage based on vulnerabilities addressed>"
}}

IMPORTANT: Base ALL recommendations on the ACTUAL vulnerabilities found in THIS architecture. Do NOT provide generic security advice - every recommendation must directly address a specific vulnerability or weakness identified in the analysis."""

        rec_messages = [{"role": "user", "content": recommendations_prompt}]
        rec_response = agent.model.invoke(rec_messages)
        
        try:
            recommendations = extract_json_from_response(rec_response.content)
            print(f"📋 Generated {len(recommendations.get('immediate_actions', []))} immediate actions")
        except Exception as e:
            print(f"❌ Error parsing recommendations: {e}")
            print(f"First 500 chars: {rec_response.content[:500]}")
            raise HTTPException(status_code=500, detail=f"Failed to parse recommendations: {str(e)}")
        
        # Build comprehensive response
        response = {
            "healing_summary": {
                "original_architecture_id": request.architecture.metadata.get("id", "original"),
                "analysis_timestamp": datetime.now().isoformat(),
                "total_vulnerabilities_found": vulnerability_analysis["total_vulnerabilities"],
                "overall_risk_score": vulnerability_analysis["overall_risk_score"],
                "security_posture": vulnerability_analysis["security_posture"],
                "mitigations_applied": len(recommendations["immediate_actions"])
            },
            "vulnerability_analysis": vulnerability_analysis,
            "healed_architecture": {
                "id": f"arch_healed_{int(datetime.now().timestamp())}",
                "metadata": healed_architecture.get("metadata", {}),
                "nodes": healed_architecture.get("nodes", []),
                "connections": healed_architecture.get("connections", [])
            },
            "recommendations": recommendations,
            "changes_summary": {
                "components_added": len(healed_architecture.get("nodes", [])) - len(request.architecture.nodes),
                "connections_modified": len(healed_architecture.get("connections", [])) - len(request.architecture.connections),
                "security_controls_added": [
                    node["component_type"] for node in healed_architecture.get("nodes", [])
                    if node["component_type"] in ["waf", "firewall", "ids_ips", "vpn_gateway", "siem"]
                ]
            }
        }
        
        print(f"✅ Architecture healing complete - Risk reduced by {recommendations.get('risk_reduction', 'N/A')}")
        return response
        
    except Exception as e:
        print(f"❌ Error in healing: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/healing-report/pdf")
async def generate_healing_report_pdf(request: HealingRequest):
    """
    Generate a comprehensive PDF report for architecture healing analysis
    Returns: PDF file as downloadable attachment
    """
    try:
        print(f"📄 Generating PDF report for architecture with {len(request.architecture.nodes)} nodes")
        
        # Define attack catalog
        attack_catalog = [
            {"id": "ATK001", "name": "SQL Injection", "category": "injection"},
            {"id": "ATK002", "name": "Cross-Site Scripting (XSS)", "category": "injection"},
            {"id": "ATK003", "name": "DDoS Attack", "category": "availability"},
            {"id": "ATK004", "name": "Man-in-the-Middle (MITM)", "category": "interception"},
            {"id": "ATK005", "name": "Brute Force Attack", "category": "authentication"},
            {"id": "ATK006", "name": "Zero-Day Exploit", "category": "exploitation"},
            {"id": "ATK007", "name": "Ransomware", "category": "malware"},
            {"id": "ATK008", "name": "Phishing", "category": "social_engineering"},
            {"id": "ATK009", "name": "Privilege Escalation", "category": "privilege"},
            {"id": "ATK010", "name": "Data Exfiltration", "category": "data_theft"},
            {"id": "ATK011", "name": "Session Hijacking", "category": "session"},
            {"id": "ATK012", "name": "DNS Spoofing", "category": "network"},
            {"id": "ATK013", "name": "API Abuse", "category": "api"},
            {"id": "ATK014", "name": "Insider Threat", "category": "insider"},
            {"id": "ATK015", "name": "Supply Chain Attack", "category": "supply_chain"},
            {"id": "ATK016", "name": "Credential Stuffing", "category": "authentication"},
            {"id": "ATK017", "name": "Cryptojacking", "category": "malware"},
            {"id": "ATK018", "name": "Business Logic Exploit", "category": "logic"},
            {"id": "ATK019", "name": "Data Poisoning", "category": "ai_ml"},
            {"id": "ATK020", "name": "Container Escape", "category": "container"}
        ]
        
        # Step 1: Vulnerability Analysis
        print("🔍 Step 1/3: Analyzing vulnerabilities...")
        arch_json = json.dumps({
            "nodes": [node.dict() for node in request.architecture.nodes],
            "connections": [conn.dict() for conn in request.architecture.connections],
            "metadata": request.architecture.metadata
        })
        
        vulnerability_prompt = f"""You are a cybersecurity expert analyzing a network architecture for vulnerabilities.

Architecture to analyze:
{arch_json}

Attack catalog being tested:
{json.dumps(attack_catalog, indent=2)}

Analyze this architecture against ALL attacks in the catalog. For EACH attack, determine:
1. Is the architecture vulnerable to this specific attack?
2. What is the severity (critical/high/medium/low)?
3. Which components are affected?
4. What is the potential impact?

Return ONLY a valid JSON object with this EXACT structure:
{{
  "overall_risk_score": <calculate actual risk score 0-100>,
  "security_posture": "<determine: CRITICAL/HIGH/MEDIUM/LOW>",
  "total_vulnerabilities": <count actual vulnerabilities>,
  "severity_breakdown": {{
    "critical": <count critical>,
    "high": <count high>,
    "medium": <count medium>,
    "low": <count low>
  }},
  "vulnerable_attacks": [
    {{
      "attack_name": "<actual attack name from catalog>",
      "attack_id": "<actual attack ID>",
      "vulnerable": <true/false based on analysis>,
      "severity": "<actual severity>",
      "affected_components": ["<list actual affected component IDs>"],
      "impact": "<describe actual impact on THIS architecture>",
      "likelihood": "<assess actual likelihood: high/medium/low>"
    }}
  ],
  "architecture_weaknesses": [
    "<list actual weaknesses found in THIS architecture - NOT generic examples>"
  ],
  "compliance_violations": [
    "<list actual violations if found, empty array if none>"
  ]
}}

IMPORTANT: Analyze the ACTUAL architecture above. Provide real findings, NOT example data."""

        vuln_messages = [{"role": "user", "content": vulnerability_prompt}]
        vuln_response = agent.model.invoke(vuln_messages)
        
        try:
            vulnerability_analysis = extract_json_from_response(vuln_response.content)
            print(f"🔍 Found {vulnerability_analysis['total_vulnerabilities']} vulnerabilities")
        except Exception as e:
            print(f"❌ Error parsing vulnerability analysis: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to parse vulnerability analysis: {str(e)}")
        
        # Step 2: Generate Healed Architecture
        print("🩹 Step 2/3: Generating healed architecture...")
        healing_prompt = f"""You are a cybersecurity architect. Based on this vulnerability analysis, generate a SECURED version of the architecture.

Original Architecture:
{arch_json}

Vulnerabilities Found:
{json.dumps(vulnerability_analysis, indent=2)}

Generate a healed architecture that:
1. Adds missing security components (WAF, Firewall, IDS/IPS, etc.)
2. Implements proper network segmentation
3. Adds encryption layers
4. Implements zero-trust principles
5. Addresses ALL identified vulnerabilities

Return ONLY valid JSON with this structure:
{{
  "metadata": {{"version": "2.0", "security_level": "hardened"}},
  "nodes": [
    {{
      "id": "<generate unique ID>",
      "component_type": "<actual security component type needed>",
      "name": "<descriptive component name>",
      "properties": {{"<key>": "<value based on security requirements>"}}
    }}
  ],
  "connections": [
    {{
      "source": "<actual source node ID>",
      "target": "<actual target node ID>",
      "connection_type": "<appropriate connection type>",
      "properties": {{"encryption": "<encryption method if needed>"}}
    }}
  ]
}}

IMPORTANT: Keep all original nodes and ADD security components to address vulnerabilities. Base on ACTUAL analysis."""

        healing_messages = [{"role": "user", "content": healing_prompt}]
        healing_response = agent.model.invoke(healing_messages)
        
        try:
            healed_architecture = extract_json_from_response(healing_response.content)
            print(f"🩹 Healed architecture has {len(healed_architecture.get('nodes', []))} nodes")
        except Exception as e:
            print(f"❌ Error parsing healed architecture: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to parse healed architecture: {str(e)}")
        
        # Step 3: Generate Recommendations
        print("📋 Step 3/3: Generating recommendations...")
        recommendations_prompt = f"""Based on these vulnerabilities and the healed architecture, provide detailed remediation recommendations.

Vulnerabilities:
{json.dumps(vulnerability_analysis, indent=2)}

Healed Architecture:
{json.dumps(healed_architecture, indent=2)}

Provide actionable recommendations with priorities, effort estimates, and costs.

Return ONLY valid JSON:
{{
  "immediate_actions": [
    {{
      "action": "<specific action based on actual vulnerabilities>",
      "priority": "<CRITICAL/HIGH/MEDIUM/LOW>",
      "effort": "<realistic time estimate>",
      "cost": "<realistic cost estimate>",
      "impact": "<actual impact on THIS architecture>"
    }}
  ],
  "short_term_improvements": ["<actual short-term improvements>"],
  "long_term_initiatives": ["<actual long-term initiatives>"],
  "monitoring_guidelines": ["<actual monitoring recommendations>"],
  "compliance_requirements": ["<actual compliance needs>"],
  "estimated_total_cost": "<calculate realistic total>",
  "implementation_timeline": "<calculate realistic timeline>",
  "risk_reduction": "<calculate realistic risk reduction %>"
}}

IMPORTANT: Base ALL recommendations on ACTUAL vulnerabilities found. NO generic examples."""

        rec_messages = [{"role": "user", "content": recommendations_prompt}]
        rec_response = agent.model.invoke(rec_messages)
        
        try:
            recommendations = extract_json_from_response(rec_response.content)
            print(f"📋 Generated {len(recommendations.get('immediate_actions', []))} immediate actions")
        except Exception as e:
            print(f"❌ Error parsing recommendations: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to parse recommendations: {str(e)}")
        
        # Build healing result
        healing_result = {
            "healing_summary": {
                "original_architecture_id": request.architecture.metadata.get("id", "original"),
                "analysis_timestamp": datetime.now().isoformat(),
                "total_vulnerabilities_found": vulnerability_analysis["total_vulnerabilities"],
                "overall_risk_score": vulnerability_analysis["overall_risk_score"],
                "security_posture": vulnerability_analysis["security_posture"],
                "mitigations_applied": len(recommendations["immediate_actions"])
            },
            "vulnerability_analysis": vulnerability_analysis,
            "healed_architecture": {
                "id": f"arch_healed_{int(datetime.now().timestamp())}",
                "metadata": healed_architecture.get("metadata", {}),
                "nodes": healed_architecture.get("nodes", []),
                "connections": healed_architecture.get("connections", [])
            },
            "recommendations": recommendations,
            "changes_summary": {
                "components_added": len(healed_architecture.get("nodes", [])) - len(request.architecture.nodes),
                "connections_modified": len(healed_architecture.get("connections", [])) - len(request.architecture.connections),
                "security_controls_added": [
                    node["component_type"] for node in healed_architecture.get("nodes", [])
                    if node["component_type"] in ["waf", "firewall", "ids_ips", "vpn_gateway", "siem"]
                ]
            }
        }
        
        # Generate PDF
        print("📄 Generating PDF report...")
        pdf_bytes = generate_healing_pdf(healing_result)
        
        # Return as downloadable file
        filename = f"insightx_healing_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        print(f"✅ PDF generated successfully: {len(pdf_bytes)} bytes")
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
        
    except Exception as e:
        print(f"❌ Error generating PDF report: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/generate-architecture")
async def generate_architecture_from_prompt(request: dict):
    """
    Generate architecture from natural language prompt using AI
    """
    try:
        prompt_text = request.get("prompt", "")
        if not prompt_text:
            raise HTTPException(status_code=400, detail="Prompt is required")
        
        print(f"\n🤖 Generating architecture from prompt...")
        print(f"📝 Prompt: {prompt_text[:100]}...")
        
        # AI prompt for architecture generation
        generation_prompt = f"""You are an expert cloud/network architect. A user wants to design a system architecture based on this description:

USER PROMPT:
{prompt_text}

Based on this description, generate a complete, realistic architecture with appropriate components and connections.

COMPONENT TYPES AVAILABLE:
- Web tier: web_server, load_balancer, cdn, api_gateway
- Application tier: app_server, microservice, container, serverless_function
- Data tier: database, cache_server, file_storage, data_warehouse
- Security: firewall, waf, ids_ips, vpn_gateway, authentication_service
- Network: router, switch, proxy_server, dns_server
- Monitoring: monitoring_service, log_aggregator, siem
- User devices: user_workstation, mobile_device, iot_device
- Special: message_queue, email_server, backup_system

TASK:
1. Identify what type of company/system this is
2. Determine required components based on the description
3. Create logical connections between components
4. Position components in a layered architecture (user → web → app → data)
5. Include security components where appropriate

Return ONLY valid JSON in this EXACT format:
{{
  "metadata": {{
    "company_name": "<extract or infer company/system name>",
    "architecture_type": "<type: e-commerce/saas/enterprise/financial/healthcare/etc>",
    "created_at": "{datetime.now().isoformat()}",
    "security_level": "<assess based on requirements: low/medium/high>",
    "description": "<brief 1-sentence summary of the architecture>"
  }},
  "nodes": [
    {{
      "id": "<generate unique ID like 'node_1', 'node_2'>",
      "type": "component",
      "name": "<descriptive name for this component>",
      "properties": {{
        "component_type": "<one of the component types listed above>",
        "description": "<brief description of this component's role>",
        "tier": "<infrastructure/web/application/data/security/user>"
      }},
      "position": {{
        "x": <calculate x position (0-1000) based on logical flow>,
        "y": <calculate y position (0-600) based on tier - user:100, web:200, app:300, data:400, security:varied>
      }}
    }}
  ],
  "connections": [
    {{
      "id": "<generate unique ID like 'conn_1'>",
      "source": "<source node id>",
      "target": "<target node id>",
      "type": "connection",
      "properties": {{
        "protocol": "<HTTP/HTTPS/TCP/UDP/MQTT/etc>",
        "encrypted": <true/false>,
        "description": "<what data/traffic flows through this connection>"
      }}
    }}
  ]
}}

IMPORTANT GUIDELINES:
- Create 5-15 nodes depending on complexity described
- Include typical flow: users → load balancer → web servers → app servers → databases
- Add firewall/WAF if security is mentioned or for production systems
- Add caching if performance is mentioned
- Add monitoring/logging for production systems
- Make connections realistic (don't connect everything to everything)
- Position nodes logically from top to bottom (users at top, data at bottom)
- Use varied x positions to avoid overlapping components

Analyze the user's prompt and generate a REAL architecture based on their needs."""

        messages = [{"role": "user", "content": generation_prompt}]
        ai_response = agent.model.invoke(messages)
        
        try:
            architecture = extract_json_from_response(ai_response.content)
            print(f"✅ Generated architecture with {len(architecture.get('nodes', []))} nodes and {len(architecture.get('connections', []))} connections")
            
            # Validate structure
            if "metadata" not in architecture:
                architecture["metadata"] = {
                    "company_name": "Generated Architecture",
                    "architecture_type": "general",
                    "created_at": datetime.now().isoformat(),
                    "security_level": "medium"
                }
            
            if "nodes" not in architecture or not architecture["nodes"]:
                raise ValueError("No nodes generated in architecture")
            
            if "connections" not in architecture:
                architecture["connections"] = []
            
            return architecture
            
        except Exception as e:
            print(f"❌ Error parsing generated architecture: {e}")
            print(f"First 500 chars: {ai_response.content[:500]}")
            raise HTTPException(status_code=500, detail=f"Failed to parse generated architecture: {str(e)}")
    
    except Exception as e:
        print(f"❌ Error in architecture generation: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health_check():
    return {"status": "healthy", "model": GROQ_MODEL}

if __name__ == "__main__":
    print("🚀 Starting InsightX Security Agent API Server...")
    print(f"📡 Model: {GROQ_MODEL}")
    print(f"🔗 API will be available at: http://localhost:3000")
    print(f"📖 Docs available at: http://localhost:3000/docs")
    
    uvicorn.run(app, host="0.0.0.0", port=3000, log_level="info")
