#!/usr/bin/env python3
"""
Test Case Study Analysis Feature
Tests the new case study analysis functionality in both backend and frontend
"""

import requests
import json

def test_case_study_api():
    """Test the case study analysis API endpoint"""
    url = "http://localhost:8082/api/analyze-case-studies"
    
    # Sample architecture with web server and database
    test_data = {
        "architecture": {
            "metadata": {
                "company_name": "Test E-commerce Platform",
                "architecture_type": "web_application",
                "security_level": "medium",
                "description": "Test architecture for case study analysis"
            },
            "nodes": [
                {
                    "id": "web1",
                    "type": "web_server",
                    "category": "compute",
                    "name": "Apache Web Server",
                    "properties": {
                        "component_type": "web_server",
                        "version": "2.4.41",
                        "port": 80
                    }
                },
                {
                    "id": "db1", 
                    "type": "database_server",
                    "category": "database",
                    "name": "MySQL Database",
                    "properties": {
                        "component_type": "database_server",
                        "version": "8.0",
                        "port": 3306
                    }
                }
            ],
            "connections": [
                {
                    "id": "conn1",
                    "source": "web1",
                    "target": "db1",
                    "type": "database_connection",
                    "properties": {
                        "protocol": "TCP",
                        "encrypted": False
                    }
                }
            ]
        },
        "attack": None  # General analysis without specific attack
    }
    
    try:
        print("🔍 Testing Case Study Analysis API...")
        print(f"📡 Sending request to: {url}")
        print(f"📊 Test architecture: {test_data['architecture']['metadata']['company_name']}")
        print(f"🏗️  Components: {len(test_data['architecture']['nodes'])} nodes, {len(test_data['architecture']['connections'])} connections")
        
        response = requests.post(url, json=test_data)
        
        if response.status_code == 200:
            result = response.json()
            print("✅ API call successful!")
            print(f"🆔 Analysis ID: {result.get('analysis_id')}")
            print(f"⏰ Timestamp: {result.get('analysis_timestamp')}")
            
            case_study_results = result.get('case_study_results', {})
            similar_cases = case_study_results.get('similar_cases', [])
            analysis = case_study_results.get('analysis', {})
            meta = case_study_results.get('meta', {})
            
            print(f"\n📊 Case Study Analysis Results:")
            print(f"🔍 Found {len(similar_cases)} similar historical incidents")
            print(f"🗄️  Total cases analyzed: {meta.get('total_cases_analyzed', 0)}")
            print(f"🤖 VCDB available: {meta.get('vcdb_available', False)}")
            print(f"🎯 Confidence score: {analysis.get('confidence_score', 0) * 100:.1f}%")
            
            if similar_cases:
                print(f"\n⚠️  Top Similar Incidents:")
                for i, case in enumerate(similar_cases[:3], 1):
                    print(f"  {i}. {case.get('incident_id')} - {case.get('summary', 'N/A')[:80]}...")
                    print(f"     Risk Level: {case.get('impact_overall_rating')} | Similarity: {(1-case.get('distance', 1))*100:.1f}%")
            
            if analysis.get('risk_patterns'):
                print(f"\n⚠️  Risk Patterns Identified:")
                for pattern in analysis['risk_patterns']:
                    print(f"  • {pattern}")
                    
            if analysis.get('recommendations'):
                print(f"\n🛡️  Security Recommendations:")
                for rec in analysis['recommendations']:
                    print(f"  • {rec}")
            
            return True
            
        else:
            print(f"❌ API call failed with status {response.status_code}")
            print(f"📄 Response: {response.text}")
            return False
            
    except requests.exceptions.ConnectionError:
        print("❌ Connection failed - Backend server may not be running")
        print("🔧 Make sure the backend is running on http://localhost:8082")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_enhanced_validation():
    """Test enhanced validation with case study analysis"""
    url = "http://localhost:8082/api/enhanced-validation"
    
    test_data = {
        "attack": {
            "attack_name": "SQL Injection on E-commerce Platform",
            "category": "injection",
            "techniques": ["T1190"],
            "target_components": ["web_server", "database_server"],
            "attack_steps": [
                "Identify SQL injection vulnerability",
                "Extract database schema",
                "Access customer data"
            ]
        },
        "architecture": {
            "metadata": {
                "company_name": "E-commerce Test Platform"
            },
            "nodes": [
                {
                    "id": "web1",
                    "type": "web_server",
                    "properties": {"component_type": "web_server"}
                },
                {
                    "id": "db1",
                    "type": "database_server", 
                    "properties": {"component_type": "database_server"}
                }
            ],
            "connections": []
        }
    }
    
    try:
        print(f"\n🔧 Testing Enhanced Validation with Case Studies...")
        response = requests.post(url, json=test_data)
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Enhanced validation successful!")
            
            validation_result = result.get('validation_result', {})
            case_study_insights = result.get('case_study_insights', {})
            
            print(f"🎯 Attack feasibility: {validation_result.get('feasibility_score', 0)*100:.1f}%")
            print(f"📊 Historical context: {len(case_study_insights.get('similar_cases', []))} similar cases found")
            
            return True
        else:
            print(f"❌ Enhanced validation failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Enhanced validation error: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Testing Case Study Analysis Feature")
    print("=" * 50)
    
    # Test basic case study analysis
    success1 = test_case_study_api()
    
    # Test enhanced validation
    success2 = test_enhanced_validation()
    
    print(f"\n📋 Test Summary:")
    print(f"✅ Case Study Analysis API: {'PASSED' if success1 else 'FAILED'}")
    print(f"✅ Enhanced Validation API: {'PASSED' if success2 else 'FAILED'}")
    
    if success1 and success2:
        print(f"\n🎉 All tests passed! Case Study Analysis feature is working correctly.")
        print(f"💡 You can now use the 📊 Case Studies button in the frontend to analyze your architectures!")
    else:
        print(f"\n⚠️  Some tests failed. Check the backend server and try again.")