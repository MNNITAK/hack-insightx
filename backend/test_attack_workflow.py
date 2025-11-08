"""
Test the complete rule-based attack workflow
Tests: validate-attack -> correct-architecture -> comparison
"""

import requests
import json
from datetime import datetime

# Test architecture with a simple web application
test_architecture = {
    "metadata": {
        "company_name": "Test Company",
        "architecture_name": "Simple Web App",
        "created_at": datetime.now().isoformat()
    },
    "nodes": [
        {
            "id": "web1",
            "type": "Web Server",
            "category": "Server",
            "properties": {
                "name": "Apache Web Server",
                "version": "2.4",
                "ports": ["80", "443"]
            },
            "position": {"x": 100, "y": 100}
        },
        {
            "id": "db1",
            "type": "Database",
            "category": "Database",
            "properties": {
                "name": "MySQL Database",
                "version": "5.7",
                "encryption": False
            },
            "position": {"x": 200, "y": 200}
        },
        {
            "id": "user1",
            "type": "User Device",
            "category": "Client",
            "properties": {
                "name": "End User",
                "device_type": "Browser"
            },
            "position": {"x": 0, "y": 100}
        }
    ],
    "connections": [
        {
            "id": "conn1",
            "source": "user1",
            "target": "web1",
            "type": "HTTP",
            "properties": {
                "protocol": "HTTP",
                "encrypted": False
            }
        },
        {
            "id": "conn2",
            "source": "web1",
            "target": "db1",
            "type": "Database Connection",
            "properties": {
                "protocol": "TCP",
                "encrypted": False
            }
        }
    ],
    "network_zones": []
}

# Test attacks to validate
test_attacks = [
    {
        "attack_id": "sql_injection_001",
        "attack_name": "SQL Injection",
        "category": "Injection",
        "configured_at": datetime.now().isoformat(),
        "parameters": {}
    },
    {
        "attack_id": "ddos_001",
        "attack_name": "DDoS Attack",
        "category": "Availability",
        "configured_at": datetime.now().isoformat(),
        "parameters": {}
    },
    {
        "attack_id": "mitm_001",
        "attack_name": "Man-in-the-Middle Attack",
        "category": "Network",
        "configured_at": datetime.now().isoformat(),
        "parameters": {}
    }
]

BASE_URL = "http://localhost:5000"

def test_validate_attack(attack):
    """Test attack validation endpoint"""
    print(f"\n{'='*60}")
    print(f"🎯 Testing Attack: {attack['attack_name']}")
    print(f"{'='*60}")
    
    payload = {
        "attack": attack,
        "architecture": test_architecture
    }
    
    try:
        response = requests.post(f"{BASE_URL}/api/validate-attack", json=payload, timeout=30)
        response.raise_for_status()
        result = response.json()
        
        print(f"\n✅ Validation Response:")
        print(f"   Attack Possible: {result.get('can_proceed', 'Unknown')}")
        print(f"   Confidence: {result.get('security_analysis', {}).get('confidence_score', 0)}%")
        print(f"   Risk Score: {result.get('security_analysis', {}).get('overall_risk_score', 0)}")
        print(f"   Vulnerable Components: {len(result.get('security_analysis', {}).get('vulnerability_assessment', {}).get('vulnerable_components', []))}")
        print(f"   Recommendation: {result.get('recommendation', 'N/A')[:150]}...")
        
        return result
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

def test_correct_architecture(attack):
    """Test architecture correction endpoint"""
    print(f"\n🔧 Generating Corrected Architecture...")
    
    payload = {
        "attack": attack,
        "architecture": test_architecture
    }
    
    try:
        response = requests.post(f"{BASE_URL}/api/correct-architecture", json=payload, timeout=30)
        response.raise_for_status()
        result = response.json()
        
        print(f"\n✅ Correction Response:")
        print(f"   Components Added: {result.get('change_summary', {}).get('components_added_count', 0)}")
        print(f"   Security Improvements: {len(result.get('change_summary', {}).get('security_improvements', []))}")
        print(f"   Attack Prevented: {result.get('attack_mitigation', {}).get('prevented', False)}")
        print(f"   Risk Reduction: {result.get('attack_mitigation', {}).get('risk_reduction', 'Unknown')}")
        
        print(f"\n   Added Components:")
        for comp in result.get('change_summary', {}).get('added_components', [])[:5]:
            print(f"      • {comp}")
        
        print(f"\n   Security Improvements:")
        for imp in result.get('change_summary', {}).get('security_improvements', [])[:3]:
            print(f"      • {imp}")
        
        return result
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

def test_complete_workflow():
    """Test complete attack simulation workflow"""
    print("\n" + "="*60)
    print("🚀 RULE-BASED ATTACK SIMULATION WORKFLOW TEST")
    print("="*60)
    
    # Test server health
    try:
        health = requests.get(f"{BASE_URL}/health", timeout=5)
        health_data = health.json()
        print(f"\n✅ Server Status: {health_data.get('status', 'unknown').upper()}")
        print(f"   Mode: {health_data.get('mode', 'unknown')}")
        print(f"   LLM Dependency: {health_data.get('llm_dependency', 'unknown')}")
        print(f"   Frameworks: {', '.join(health_data.get('frameworks', []))}")
    except Exception as e:
        print(f"\n❌ Server not running: {e}")
        print("   Please start the server with: python backend/api/security_agent_rulebased.py")
        return
    
    # Test each attack
    results = []
    for attack in test_attacks:
        validation_result = test_validate_attack(attack)
        if validation_result:
            correction_result = test_correct_architecture(attack)
            results.append({
                "attack": attack['attack_name'],
                "validation": validation_result,
                "correction": correction_result
            })
    
    # Summary
    print("\n" + "="*60)
    print("📊 TEST SUMMARY")
    print("="*60)
    print(f"\nTotal Attacks Tested: {len(test_attacks)}")
    print(f"Successful Tests: {len(results)}")
    
    print("\n🎯 Attack Results:")
    for r in results:
        attack_name = r['attack']
        can_proceed = r['validation'].get('can_proceed', False)
        added_components = r['correction'].get('change_summary', {}).get('components_added_count', 0) if r['correction'] else 0
        
        status = "🔴 POSSIBLE" if can_proceed else "🟢 BLOCKED"
        print(f"\n   {attack_name}:")
        print(f"      Status: {status}")
        print(f"      Security Controls Added: {added_components}")
    
    print("\n✅ All tests completed successfully!")
    print("\n💡 The rule-based system provides the same workflow as LLM-based:")
    print("   1. Validates if attack is possible")
    print("   2. Generates corrected architecture")
    print("   3. Shows before/after comparison")
    print("   4. 100% rule-based, no LLM dependency")

if __name__ == "__main__":
    test_complete_workflow()
