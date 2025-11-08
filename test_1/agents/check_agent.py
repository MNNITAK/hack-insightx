import json
import os
from typing import Dict, Any, TypedDict
from langchain_groq import ChatGroq
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import PromptTemplate
from langgraph.graph import StateGraph, END

# Define state schema properly for LangGraph
class AnalysisState(TypedDict):
    company_arch: Dict[Any, Any]
    hacker_intervention: Dict[Any, Any]
    vulnerability_analysis: Dict[Any, Any]
    new_architecture: Dict[Any, Any]
    recommended_actions: Dict[Any, Any]

class SecurityAnalysisAgent:
    def __init__(self):
        # Initialize Groq model
        self.model = ChatGroq(
            model="qwen/qwen3-32b",
            temperature=0.2,
            api_key="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",
        )
        self.parser = JsonOutputParser()
        self.graph = self._build_graph()
    
    def _load_json_file(self, filepath: str) -> Dict[Any, Any]:
        """Load JSON file with error handling"""
        try:
            with open(filepath, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Error: File {filepath} not found")
            return {}
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in {filepath}")
            return {}
    
    def _build_graph(self):
        """Build the LangGraph workflow"""
        # Create graph with proper state
        workflow = StateGraph(AnalysisState)
        
        # Add nodes
        workflow.add_node("analyze_vulnerabilities", self._analyze_vulnerabilities)
        workflow.add_node("design_new_architecture", self._design_new_architecture)
        workflow.add_node("generate_recommendations", self._generate_recommendations)
        
        # Add edges
        workflow.add_edge("analyze_vulnerabilities", "design_new_architecture")
        workflow.add_edge("design_new_architecture", "generate_recommendations")
        workflow.add_edge("generate_recommendations", END)
        
        # Set entry point
        workflow.set_entry_point("analyze_vulnerabilities")
        
        return workflow.compile()
    
    def _analyze_vulnerabilities(self, state: AnalysisState) -> AnalysisState:
        """Analyze vulnerabilities from the attack"""
        print("🔍 Analyzing vulnerabilities...")
        
        prompt = PromptTemplate(
            template="""
            You are a cybersecurity expert analyzing a security breach.
            
            Company Architecture:
            {company_arch}
            
            Attack Details:
            {hacker_intervention}
            
            Identify the key vulnerabilities that were exploited. Return ONLY a valid JSON with:
            {{
                "vulnerabilities": [
                    {{
                        "component": "component_name",
                        "vulnerability": "description",
                        "severity": "high",
                        "exploit_method": "how it was exploited"
                    }}
                ],
                "attack_vectors": ["vector1", "vector2"],
                "compromised_systems": ["system1", "system2"]
            }}
            """,
            input_variables=["company_arch", "hacker_intervention"]
        )
        
        formatted_prompt = prompt.format(
            company_arch=json.dumps(state["company_arch"], indent=2),
            hacker_intervention=json.dumps(state["hacker_intervention"], indent=2)
        )
        
        try:
            response = self.model.invoke(formatted_prompt)
            analysis = self.parser.parse(response.content)
            state["vulnerability_analysis"] = analysis
            print("✅ Vulnerability analysis completed")
        except Exception as e:
            print(f"⚠️ Error in vulnerability analysis: {e}")
            state["vulnerability_analysis"] = {
                "vulnerabilities": [],
                "attack_vectors": [],
                "compromised_systems": []
            }
        
        return state
    
    def _design_new_architecture(self, state: AnalysisState) -> AnalysisState:
        """Design improved architecture based on vulnerabilities"""
        print("🏗️ Designing new architecture...")
        
        prompt = PromptTemplate(
            template="""
            Based on the vulnerability analysis and original architecture, design an improved architecture.
            
            Original Architecture:
            {company_arch}
            
            Vulnerability Analysis:
            {vulnerability_analysis}
            
            Create a new architecture JSON that addresses the identified vulnerabilities:
            - Add security controls
            - Implement network segmentation
            - Add monitoring systems
            - Include access controls
            - Add redundancy and backup systems
            
            Return ONLY a valid JSON with the complete new architecture maintaining the original structure but with security improvements.
            """,
            input_variables=["company_arch", "vulnerability_analysis"]
        )
        
        formatted_prompt = prompt.format(
            company_arch=json.dumps(state["company_arch"], indent=2),
            vulnerability_analysis=json.dumps(state.get("vulnerability_analysis", {}), indent=2)
        )
        
        try:
            response = self.model.invoke(formatted_prompt)
            new_arch = self.parser.parse(response.content)
            state["new_architecture"] = new_arch
            print("✅ New architecture designed")
        except Exception as e:
            print(f"⚠️ Error in architecture design: {e}")
            state["new_architecture"] = state["company_arch"]  # Fallback to original
        
        return state
    
    def _generate_recommendations(self, state: AnalysisState) -> AnalysisState:
        """Generate actionable security recommendations"""
        print("📋 Generating recommendations...")
        
        prompt = PromptTemplate(
            template="""
            Generate comprehensive security recommendations based on the analysis.
            
            Vulnerability Analysis:
            {vulnerability_analysis}
            
            New Architecture:
            {new_architecture}
            
            Generate recommendations in this EXACT JSON format:
            {{
                "immediate_actions": [
                    {{
                        "priority": "critical",
                        "action": "specific action to take",
                        "timeline": "immediate",
                        "responsible_team": "Security Team",
                        "estimated_cost": "$10,000",
                        "risk_reduction": "80%"
                    }}
                ],
                "short_term_improvements": [
                    {{
                        "action": "improvement description",
                        "timeline": "1-3 months",
                        "cost": "$5,000"
                    }}
                ],
                "long_term_strategy": [
                    {{
                        "strategy": "long term plan",
                        "timeline": "6-12 months",
                        "cost": "$50,000"
                    }}
                ],
                "compliance_requirements": ["ISO 27001", "SOC 2"],
                "budget_allocation": {{
                    "total_estimated_cost": "$100,000",
                    "breakdown": {{
                        "immediate": "$30,000",
                        "short_term": "$20,000",
                        "long_term": "$50,000"
                    }}
                }},
                "success_metrics": ["Reduced incidents by 90%", "Improved response time"],
                "review_schedule": "monthly"
            }}
            """,
            input_variables=["vulnerability_analysis", "new_architecture"]
        )
        
        formatted_prompt = prompt.format(
            vulnerability_analysis=json.dumps(state.get("vulnerability_analysis", {}), indent=2),
            new_architecture=json.dumps(state.get("new_architecture", {}), indent=2)
        )
        
        try:
            response = self.model.invoke(formatted_prompt)
            recommendations = self.parser.parse(response.content)
            state["recommended_actions"] = recommendations
            print("✅ Recommendations generated")
        except Exception as e:
            print(f"⚠️ Error in recommendation generation: {e}")
            state["recommended_actions"] = {
                "immediate_actions": [],
                "short_term_improvements": [],
                "long_term_strategy": [],
                "compliance_requirements": [],
                "budget_allocation": {"total_estimated_cost": "0"},
                "success_metrics": [],
                "review_schedule": "monthly"
            }
        
        return state
    
    def analyze(self, company_arch_path: str, hacker_intervention_path: str) -> Dict[Any, Any]:
        """Main analysis function"""
        print("🚀 Starting security analysis...")
        
        # Load input files
        company_arch = self._load_json_file(company_arch_path)
        hacker_intervention = self._load_json_file(hacker_intervention_path)
        
        if not company_arch or not hacker_intervention:
            raise ValueError("Failed to load input files")
        
        # Run analysis with proper state initialization
        initial_state: AnalysisState = {
            "company_arch": company_arch,
            "hacker_intervention": hacker_intervention,
            "vulnerability_analysis": {},
            "new_architecture": {},
            "recommended_actions": {}
        }
        
        result = self.graph.invoke(initial_state)
        
        return {
            "new_architecture": result.get("new_architecture", {}),
            "recommended_actions": result.get("recommended_actions", {})
        }
    
    def save_results(self, results: Dict[Any, Any], output_dir: str = "agents"):
        """Save results to JSON files"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Save new architecture
        with open(f"{output_dir}/new_company_architecture.json", "w") as f:
            json.dump(results["new_architecture"], f, indent=2)
        
        # Save recommendations
        with open(f"{output_dir}/recommended_actions.json", "w") as f:
            json.dump(results["recommended_actions"], f, indent=2)
        
        print(f"✅ Results saved to {output_dir}/")

# ---------- Main Execution ----------
if __name__ == "__main__":
    try:
        # Initialize agent
        print("🤖 Initializing Security Analysis Agent...")
        agent = SecurityAnalysisAgent()
        
        # Check if input files exist
        arch_file = "../architecture.json"
        attack_file = "../attack.json"
        
        if not os.path.exists(arch_file):
            print(f"❌ Architecture file not found at {arch_file}")
            print("Please ensure architecture.json exists in the agents folder")
            exit(1)
            
        if not os.path.exists(attack_file):
            print(f"❌ Attack file not found at {attack_file}")
            print("Please ensure attack.json exists in the agents folder")
            exit(1)
        
        # Run analysis
        results = agent.analyze(arch_file, attack_file)
        
        # Save results
        agent.save_results(results)
        
        print("\n🎉 Security analysis completed successfully!")
        print("📁 Check the agents/ folder for output files:")
        print("  - new_company_architecture.json")
        print("  - recommended_actions.json")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        print("\nMake sure you have:")
        print("1. architecture.json and attack.json files in the agents/ folder")
        print("2. Installed required packages: langchain langgraph langchain-groq")
        print("3. Valid Groq API key")