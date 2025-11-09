"""
TEST ATTACK SIMULATION
======================

Test script to demonstrate the attack simulation engine using existing files
"""

import json
from attack_simulation import AttackSimulationEngine

def test_attack_simulation():
    """Test the attack simulation with sample architecture and attack"""
    
    # Create sample architecture if test_1/architecture.json exists
    architecture_file = "test_1/architecture.json" 
    attack_file = "test_1/attack.json"
    
    # Initialize simulation engine
    engine = AttackSimulationEngine()
    
    print("🎯 Testing Attack Simulation Engine...")
    print("=" * 60)
    
    try:
        # Run simulation
        result = engine.analyze_attack_on_architecture(architecture_file, attack_file)
        
        if "error" in result:
            print(f"❌ Simulation failed: {result['error']}")
            return
        
        print("✅ Simulation completed successfully!")
        print(f"Simulation ID: {result['simulation_id']}")
        print(f"Architecture: {result['architecture_name']}")
        print(f"Attack: {result['attack_name']}")
        
        # Quick summary
        total_impact = result['total_impact']
        print("\n📊 QUICK SUMMARY:")
        print(f"  Components Compromised: {len(total_impact['compromised_components'])}")
        print(f"  Data Assets Breached: {len(total_impact['breached_data'])}")
        print(f"  Credentials Exposed: {len(total_impact['exposed_credentials'])}")
        print(f"  Lateral Movement: {'Yes' if total_impact['lateral_movement_paths'] else 'No'}")
        
        # Show phases
        print("\n🎭 ATTACK PHASES:")
        for phase in result['attack_phases']:
            success_count = len(phase['successful_compromises'])
            fail_count = len(phase['failed_attempts'])
            print(f"  Phase {phase['phase_number']}: {phase['phase_name']}")
            print(f"    Success: {success_count}, Failed: {fail_count}")
        
        # Generate full report
        print("\n📝 Generating detailed report...")
        report = engine.generate_detailed_report(result)
        
        # Save report
        output_file = f"test_attack_report_{result['simulation_id']}.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"✅ Full report saved to: {output_file}")
        
        # Show sample of compromised data
        if total_impact['breached_data']:
            print("\n🗃️ SAMPLE BREACHED DATA:")
            for i, data in enumerate(total_impact['breached_data'][:3]):  # Show first 3
                print(f"  {i+1}. {data['asset_name']} ({data['data_type']}) - {data['sensitivity_level']}")
        
        return result
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

def create_sample_files_if_needed():
    """Create sample files if they don't exist"""
    
    import os
    
    # Create sample architecture
    architecture_path = "test_1/architecture.json"
    attack_path = "test_1/attack.json"
    
    if not os.path.exists(architecture_path):
        print("📁 Creating sample architecture file...")
        
        sample_architecture = {
            "name": "Sample E-commerce Architecture",
            "nodes": [
                {
                    "id": "web1",
                    "label": "Web Server",
                    "type": "web_server",
                    "description": "Main application server"
                },
                {
                    "id": "db1", 
                    "label": "Database Server",
                    "type": "database_server",
                    "description": "Customer database"
                },
                {
                    "id": "fw1",
                    "label": "Firewall", 
                    "type": "firewall",
                    "description": "Network security appliance"
                },
                {
                    "id": "user1",
                    "label": "User Workstation",
                    "type": "user_workstation", 
                    "description": "Employee desktop"
                }
            ],
            "connections": [
                {"source": "fw1", "target": "web1"},
                {"source": "web1", "target": "db1"},
                {"source": "user1", "target": "fw1"}
            ]
        }
        
        os.makedirs("test_1", exist_ok=True)
        with open(architecture_path, 'w') as f:
            json.dump(sample_architecture, f, indent=2)
        
        print(f"✅ Created {architecture_path}")
    
    if not os.path.exists(attack_path):
        print("📁 Creating sample attack file...")
        
        sample_attack = {
            "name": "SQL Injection with Lateral Movement",
            "description": "Multi-stage attack targeting web application and database",
            "target": ["web_server", "database_server"],
            "attack_path": [
                {
                    "name": "Initial Web Compromise",
                    "type": "sql_injection",
                    "description": "Exploit SQL injection vulnerability in web application",
                    "technique": "Union-based SQL injection",
                    "estimated_time": "30 minutes"
                },
                {
                    "name": "Database Access", 
                    "type": "credential_theft",
                    "description": "Extract database credentials from compromised web server",
                    "technique": "Configuration file analysis",
                    "estimated_time": "15 minutes"
                },
                {
                    "name": "Data Exfiltration",
                    "type": "data_exfiltration", 
                    "description": "Extract customer data from database",
                    "technique": "Direct database access",
                    "estimated_time": "45 minutes"
                }
            ]
        }
        
        with open(attack_path, 'w') as f:
            json.dump(sample_attack, f, indent=2)
        
        print(f"✅ Created {attack_path}")

if __name__ == "__main__":
    # Ensure sample files exist
    create_sample_files_if_needed()
    
    # Run the test
    result = test_attack_simulation()
    
    if result:
        print("\n✅ Test completed successfully!")
        print("🎯 Attack simulation engine is ready for use!")
    else:
        print("\n❌ Test failed!")