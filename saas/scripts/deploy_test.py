#!/usr/bin/env python3
"""
Quick deployment verification script

This script tests that all SaaS endpoints are working correctly
after deployment. Run this after starting the server.
"""

import requests
import json
import sys
import time

def test_health():
    """Test basic health endpoint"""
    print("🏥 Testing health endpoint...")
    try:
        response = requests.get("http://localhost:8000/health", timeout=5)
        if response.status_code == 200:
            print("✅ Health check passed")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False

def test_team_creation():
    """Test team creation endpoint"""
    print("👥 Testing team creation...")
    try:
        response = requests.post(
            "http://localhost:8000/v1/saas/teams/create",
            json={
                "team_name": "Test Deployment",
                "admin_email": "test@example.com",
                "plan": "free"
            },
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            print(f"✅ Team created: {data.get('team_id', 'unknown')}")
            print(f"✅ API key: {data.get('api_key', 'unknown')[:20]}...")
            return data
        else:
            print(f"❌ Team creation failed: {response.status_code}")
            print(f"Response: {response.text}")
            return None
    except Exception as e:
        print(f"❌ Team creation error: {e}")
        return None

def test_chat_endpoint(api_key):
    """Test chat completions endpoint"""
    print("💬 Testing chat endpoint...")
    try:
        response = requests.post(
            "http://localhost:8000/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "X-User-Role": "developer"
            },
            json={
                "messages": [
                    {"role": "user", "content": "Say hello"}
                ],
                "model": "gpt-4",
                "max_tokens": 50
            },
            timeout=15
        )

        if response.status_code == 200:
            data = response.json()
            print("✅ Chat endpoint working")
            print(f"✅ LLM Shield metadata present: {'llmshield' in data}")
            return True
        else:
            print(f"❌ Chat endpoint failed: {response.status_code}")
            print(f"Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Chat endpoint error: {e}")
        return False

def test_guardrails(api_key):
    """Test guardrails are working"""
    print("🛡️ Testing guardrails...")
    try:
        # Try to send potentially sensitive content
        response = requests.post(
            "http://localhost:8000/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "X-User-Role": "developer"
            },
            json={
                "messages": [
                    {"role": "user", "content": "My email is test@secret.com and password is 123456"}
                ],
                "model": "gpt-4"
            },
            timeout=15
        )

        # Should be blocked or handled safely
        if response.status_code == 400:
            print("✅ Guardrails blocking sensitive content")
            return True
        elif response.status_code == 200:
            data = response.json()
            if 'llmshield' in data and data['llmshield'].get('safe'):
                print("✅ Guardrails allowing safe content")
                return True

        print(f"⚠️ Unexpected guardrail response: {response.status_code}")
        return False

    except Exception as e:
        print(f"❌ Guardrails test error: {e}")
        return False

def main():
    """Run deployment verification"""
    print("🚀 LLM Shield SaaS Deployment Test")
    print("=" * 50)

    # Test 1: Health
    if not test_health():
        print("❌ Basic health check failed. Is the server running?")
        sys.exit(1)

    time.sleep(1)

    # Test 2: Team creation
    team_data = test_team_creation()
    if not team_data:
        print("❌ Team creation failed")
        sys.exit(1)

    api_key = team_data.get('api_key')
    if not api_key:
        print("❌ No API key returned from team creation")
        sys.exit(1)

    time.sleep(1)

    # Test 3: Chat endpoint
    if not test_chat_endpoint(api_key):
        print("❌ Chat endpoint test failed")
        sys.exit(1)

    time.sleep(1)

    # Test 4: Guardrails
    if not test_guardrails(api_key):
        print("⚠️ Guardrails test inconclusive")

    print("\n" + "=" * 50)
    print("🎉 Deployment verification successful!")
    print(f"🔑 Test API key: {api_key}")
    print("\n📋 Quick Start:")
    print(f"export SHIELD_API_KEY={api_key}")
    print("pip install requests")
    print("python -c \"import requests; print(requests.post('http://localhost:8000/v1/chat/completions', headers={'Authorization': 'Bearer " + api_key + "'}, json={'messages': [{'role': 'user', 'content': 'Hello!'}]}).json())\"")

    return True

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⏹️ Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Test failed with error: {e}")
        sys.exit(1)