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
from urllib.parse import urlparse
from utils import reauthenticate_user


def validate_endpoint_url(url):
    """Validate and fix the endpoint URL format."""
    if not url:
        return None, "URL cannot be empty"
    
    # Remove whitespace
    url = url.strip()
    
    # Add https:// if no protocol is specified
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Parse the URL to validate it
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return None, "Invalid URL format"
        
        # Ensure it ends with /invocations if it doesn't already
        if not parsed.path.endswith('/invocations'):
            if parsed.path and not parsed.path.endswith('/'):
                url += '/invocations'
            else:
                url += 'invocations'
        
        return url, None
        
    except Exception as e:
        return None, f"Invalid URL: {str(e)}"


def show_endpoint_help():
    """Show detailed help for finding the agent endpoint URL."""
    print("\n" + "="*60)
    print("🔍 HOW TO FIND YOUR AGENT ENDPOINT URL")
    print("="*60)
    print()
    print("1. FROM DEPLOYMENT OUTPUT:")
    print("   When you ran 'python deployment_config.py', look for:")
    print("   • 'Deployment result: {...}'")
    print("   • Look for 'endpoint' or 'invokeUrl' in the output")
    print()
    print("2. FROM AWS CONSOLE:")
    print("   • Go to AWS Console > Bedrock > AgentCore")
    print("   • Find your agent: 'sbom-security-agent'")
    print("   • Copy the endpoint URL from the agent details")
    print()
    print("3. COMMON URL FORMATS:")
    print("   • https://[agent-id].bedrock-agentcore.[region].amazonaws.com/invocations")
    print("   • https://abcd1234.bedrock-agentcore.us-east-1.amazonaws.com/invocations")
    print()
    print("4. WHAT TO ENTER:")
    print("   You can enter any of these formats (I'll fix them automatically):")
    print("   • Full URL: https://abcd1234.bedrock-agentcore.us-east-1.amazonaws.com/invocations")
    print("   • Without protocol: abcd1234.bedrock-agentcore.us-east-1.amazonaws.com")
    print("   • Without /invocations: https://abcd1234.bedrock-agentcore.us-east-1.amazonaws.com")
    print("="*60)


def get_endpoint_url_from_user():
    """Get and validate endpoint URL from user with helpful guidance."""
    print("\n📍 I need your AgentCore agent endpoint URL to test the deployment.")
    
    # Ask if they need help finding it
    need_help = input("Do you need help finding your agent endpoint URL? (y/n): ").strip().lower()
    if need_help in ['y', 'yes', '1', 'true']:
        show_endpoint_help()
    
    print()
    
    while True:
        endpoint_url = input("Enter your agent endpoint URL: ").strip()
        
        if not endpoint_url:
            print("❌ Agent endpoint URL is required")
            
            # Offer help again
            retry_help = input("Would you like help finding the URL? (y/n): ").strip().lower()
            if retry_help in ['y', 'yes', '1', 'true']:
                show_endpoint_help()
            continue
        
        # Validate and fix the URL
        validated_url, error = validate_endpoint_url(endpoint_url)
        
        if error:
            print(f"❌ {error}")
            print("Please try again with a valid URL format.")
            print("Example: https://abcd1234.bedrock-agentcore.us-east-1.amazonaws.com/invocations")
            continue
        
        print(f"✅ Using endpoint: {validated_url}")
        return validated_url


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
        
    except requests.exceptions.ConnectionError as e:
        print("❌ Connection error")
        print(f"   Error details: {str(e)}")
        print("   - Check that the endpoint URL is correct")
        print("   - Verify your internet connection")
        print("   - Ensure the agent is deployed and running")
        return False
        
    except requests.exceptions.InvalidURL as e:
        print("❌ Invalid URL format")
        print(f"   Error details: {str(e)}")
        print("   - Check that the endpoint URL includes https://")
        print("   - Ensure the URL format is correct")
        return False
        
    except Exception as e:
        error_str = str(e)
        print(f"❌ Unexpected error: {error_str}")
        
        # Provide specific help for common errors
        if "no connection adapters" in error_str.lower():
            print("   This usually means the URL format is incorrect.")
            print("   Make sure your URL starts with https:// or http://")
        elif "name or service not known" in error_str.lower():
            print("   This usually means the hostname cannot be resolved.")
            print("   Check that the agent endpoint URL is correct.")
        
        return False


def try_get_endpoint_from_deployment():
    """Try to get the endpoint URL from recent deployment output."""
    try:
        # Check if there's a .bedrock_agentcore.yaml file (created by starter toolkit)
        if os.path.exists('.bedrock_agentcore.yaml'):
            print("📄 Found .bedrock_agentcore.yaml file from deployment")
            with open('.bedrock_agentcore.yaml', 'r') as f:
                content = f.read()
                print("   You can check this file for configuration details")
        
        # Check for common environment variables
        possible_env_vars = [
            'AGENT_ENDPOINT', 'AGENTCORE_ENDPOINT', 'BEDROCK_AGENT_ENDPOINT',
            'AGENT_URL', 'INVOKE_URL', 'ENDPOINT_URL'
        ]
        
        for var in possible_env_vars:
            value = os.getenv(var)
            if value:
                print(f"📍 Found endpoint in environment variable {var}: {value}")
                return value
        
        return None
        
    except Exception as e:
        print(f"⚠️  Could not auto-detect endpoint: {str(e)}")
        return None


def main():
    """Main test function."""
    print("🚀 SBOM Security Agent Deployment Test")
    print("="*50)
    
    # Get configuration from environment or user input
    endpoint_url = os.getenv("AGENT_ENDPOINT")
    client_id = os.getenv("COGNITO_CLIENT_ID")
    repository_url = os.getenv("TEST_REPOSITORY", "https://github.com/microsoft/vscode")
    
    # Try to auto-detect endpoint if not provided
    if not endpoint_url:
        print("🔍 Trying to auto-detect agent endpoint...")
        endpoint_url = try_get_endpoint_from_deployment()
    
    if not endpoint_url:
        endpoint_url = get_endpoint_url_from_user()
    else:
        # Validate environment variable URL
        validated_url, error = validate_endpoint_url(endpoint_url)
        if error:
            print(f"❌ Invalid endpoint URL: {error}")
            endpoint_url = get_endpoint_url_from_user()
        else:
            endpoint_url = validated_url
            print(f"✅ Using endpoint: {endpoint_url}")
    
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
