"""
SIMPLE TEST FOR ENHANCED VM ENGINE
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__)))

try:
    from enhanced_vm_attack_engine import EnhancedVMAttackEngine
    
    # Test with sample architecture
    sample_architecture = {
        "metadata": {"company_name": "Test Corp"},
        "nodes": [
            {"id": "web1", "type": "web_server", "name": "Web Server"},
            {"id": "db1", "type": "database", "name": "Database"},
            {"id": "user1", "type": "user_workstation", "name": "User PC"}
        ],
        "connections": [
            {"source": "web1", "target": "db1"},
            {"source": "user1", "target": "web1"}
        ]
    }
    
    print("🎯 Testing Enhanced VM Attack Engine...")
    engine = EnhancedVMAttackEngine()
    
    print("📊 Getting attack options...")
    attack_options = engine.get_attack_options(sample_architecture)
    
    print(f"✅ Generated {len(attack_options)} attack scenarios:")
    for i, attack in enumerate(attack_options[:10], 1):
        print(f"  {i}. {attack['name']}")
        print(f"     Category: {attack['category']}")
        print(f"     Severity: {attack['severity']}")
        print(f"     Duration: {attack['estimated_duration']}")
        print(f"     Success Rate: {attack['success_probability']*100:.1f}%")
        print()
    
    print("✅ Enhanced VM Attack Engine working successfully!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()