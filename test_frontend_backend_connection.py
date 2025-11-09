#!/usr/bin/env python3
"""
Quick test to verify frontend-backend API connectivity
Tests that the virtual sandbox API endpoints are accessible on port 8082
"""

import requests
import json
import time

def test_connection():
    """Test basic API connectivity"""
    base_url = "http://localhost:8082"
    
    print("🧪 Testing Frontend-Backend API Connectivity")
    print("=" * 50)
    
    # Test 1: Health Check
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            print("✅ Health check passed")
            print(f"   Response: {response.json()}")
        else:
            print("❌ Health check failed")
            print(f"   Status: {response.status_code}")
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        print("   Is the backend server running on port 8082?")
        return False
    
    # Test 2: Check Virtual Sandbox API endpoints
    sandbox_endpoints = [
        "/api/sandbox/deploy",  # POST
        "/docs"  # GET - API documentation
    ]
    
    for endpoint in sandbox_endpoints:
        try:
            if endpoint == "/docs":
                response = requests.get(f"{base_url}{endpoint}", timeout=5)
                if response.status_code == 200:
                    print(f"✅ {endpoint} accessible")
                else:
                    print(f"⚠️  {endpoint} returned status {response.status_code}")
            else:
                print(f"📋 {endpoint} (POST endpoint - not testing without payload)")
        except Exception as e:
            print(f"❌ {endpoint} failed: {e}")
    
    # Test 3: Mock sandbox deployment (similar to what frontend would do)
    try:
        print("\n🎯 Testing Virtual Sandbox Deploy Endpoint...")
        deploy_data = {
            "network_template": "basic_enterprise",
            "components": ["web_server", "database_server"],
            "scenario": "web_application_testing"
        }
        
        # Note: This might fail if sandbox isn't fully set up, but should at least connect
        response = requests.post(
            f"{base_url}/api/sandbox/deploy",
            json=deploy_data,
            timeout=10
        )
        
        if response.status_code in [200, 201]:
            print("✅ Sandbox deploy endpoint accessible and responding")
            result = response.json()
            print(f"   Response: {result}")
        elif response.status_code == 500:
            print("⚠️  Sandbox deploy endpoint accessible but returned server error")
            print("   This is expected if Docker isn't set up properly")
            print(f"   Response: {response.text[:200]}...")
        else:
            print(f"❌ Unexpected response: {response.status_code}")
            print(f"   Response: {response.text[:200]}...")
            
    except Exception as e:
        print(f"❌ Sandbox deploy test failed: {e}")
    
    print("\n" + "=" * 50)
    print("🏁 Frontend-Backend Connectivity Test Complete")
    
    return True

if __name__ == "__main__":
    test_connection()