#!/usr/bin/env python3
"""
Test script for SBOM Security Agent deployment.

This script helps test your deployed SBOM Security Agent by sending
a sample request and displaying the response.
"""

import os
import sys
import json
import requests
from utils import reauthenticate_user


def get_jwt_token(client_id):
    """Get a fresh JWT token from Cognito."""
    try:
        print("🔑 Getting fresh JWT token from Cognito...")
        token = reauthenticate_user(client_id)
        print("✅ JWT token obtained successfully")
        return token
    except Exception as e:
        print(f"❌ Failed to get JWT token: {str(e)}")
        return None


def test_agent(endpoint_url, jwt_token, repository_url):
    """Test the agent with a sample repository."""
    print(f"🧪 Testing agent with repository: {repository_url}")
    
    payload = {
        "prompt": f"Analyze the repository {repository_url} for security vulnerabilities and generate an SBOM report"
    }
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {jwt_token}"
    }
    
    try:
        print("📡 Sending request to agent...")
        response = requests.post(endpoint_url, json=payload, headers=headers, timeout=300)
        
        print(f"📊 Response Status: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ Agent responded successfully!")
            print("\n" + "="*60)
            print("AGENT RESPONSE:")
            print("="*60)
            
            # Try to parse as JSON for pretty printing
            try:
                response_json = response.json()
                print(json.dumps(response_json, indent=2))
            except json.JSONDecodeError:
                # If not JSON, print as text
                print(response.text)
                
        elif response.status_code == 401:
            print("❌ Authentication failed (401 Unauthorized)")
            print("   - Check that your JWT token is valid and not expired")
            print("   - Try generating a new token")
            
        elif response.status_code == 403:
            print("❌ Access forbidden (403 Forbidden)")
            print("   - Check that your JWT token has the correct permissions")
            print("   - Verify the Cognito User Pool configuration")
            
        elif response.status_code == 404:
            print("❌ Agent endpoint not found (404 Not Found)")
            print("   - Check that the endpoint URL is correct")
            print("   - Verify the agent was deployed successfully")
            
        else:
            print(f"❌ Unexpected response status: {response.status_code}")
            print(f"Response: {response.text}")
            
        return response.status_code == 200
        
    except requests.exceptions.Timeout:
        print("❌ Request timed out (agent may be processing)")
        print("   - The agent might still be working on your request")
        print("   - Try with a smaller repository or increase timeout")
        return False
        
    except requests.exceptions.ConnectionError:
        print("❌ Connection error")
        print("   - Check that the endpoint URL is correct")
        print("   - Verify your internet connection")
        return False
        
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        return False


def main():
    """Main test function."""
    print("🚀 SBOM Security Agent Deployment Test")
    print("="*50)
    
    # Get configuration from environment or user input
    endpoint_url = os.getenv("AGENT_ENDPOINT")
    client_id = os.getenv("COGNITO_CLIENT_ID")
    repository_url = os.getenv("TEST_REPOSITORY", "https://github.com/microsoft/vscode")
    
    if not endpoint_url:
        endpoint_url = input("Enter your agent endpoint URL: ").strip()
        if not endpoint_url:
            print("❌ Agent endpoint URL is required")
            sys.exit(1)
    
    if not client_id:
        client_id = input("Enter your Cognito Client ID: ").strip()
        if not client_id:
            print("❌ Cognito Client ID is required")
            sys.exit(1)
    
    print(f"🎯 Agent Endpoint: {endpoint_url}")
    print(f"🔑 Cognito Client ID: {client_id}")
    print(f"📁 Test Repository: {repository_url}")
    print()
    
    # Get JWT token
    jwt_token = get_jwt_token(client_id)
    if not jwt_token:
        print("❌ Cannot proceed without JWT token")
        sys.exit(1)
    
    print()
    
    # Test the agent
    success = test_agent(endpoint_url, jwt_token, repository_url)
    
    print("\n" + "="*50)
    if success:
        print("🎉 Deployment test completed successfully!")
        print("\nYour SBOM Security Agent is working correctly.")
        print("You can now use it to analyze repositories for security vulnerabilities.")
    else:
        print("❌ Deployment test failed!")
        print("\nPlease check the error messages above and:")
        print("1. Verify your agent endpoint URL")
        print("2. Check your Cognito configuration")
        print("3. Ensure the agent was deployed successfully")
        print("4. Review the troubleshooting section in DEPLOYMENT.md")
    
    print("="*50)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()