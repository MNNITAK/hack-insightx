"""
Test VM Attack API endpoints to verify they're working
"""

import requests
import json

# Test the VM attack scenarios endpoint
def test_vm_attack_scenarios():
    url = "http://localhost:5000/api/vm-attack-scenarios"
    
    # Simple test architecture
    test_architecture = {
        "architecture": {
            "metadata": {
                "company_name": "Test Company",
                "architecture_type": "web_application"
            },
            "nodes": [
                {"id": "web1", "type": "web_server", "name": "Web Server"},
                {"id": "db1", "type": "database", "name": "Database"}
            ],
            "connections": [
                {"id": "conn1", "source": "web1", "target": "db1"}
            ],
            "network_zones": []
        }
    }
    
    try:
        print("🧪 Testing VM Attack Scenarios endpoint...")
        response = requests.post(url, json=test_architecture, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            scenarios = data.get('scenarios', [])
            print(f"✅ SUCCESS: Got {len(scenarios)} attack scenarios")
            
            # Print first scenario for verification
            if scenarios:
                print(f"📝 First scenario: {scenarios[0]['name']}")
                print(f"   Severity: {scenarios[0]['severity']}")
                print(f"   Success Rate: {scenarios[0]['success_probability']*100:.0f}%")
            
            return True
        else:
            print(f"❌ FAILED: HTTP {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ FAILED: Cannot connect to API server")
        print("Make sure the server is running on http://localhost:5000")
        return False
    except Exception as e:
        print(f"❌ FAILED: {e}")
        return False

if __name__ == "__main__":
    print("🎯 VM Attack API Test")
    print("=" * 30)
    
    success = test_vm_attack_scenarios()
    
    if success:
        print("\n🎉 VM Attack API is working!")
        print("Your frontend should now show attack scenarios.")
    else:
        print("\n🚨 VM Attack API test failed!")
        print("Check if the backend server is running.")