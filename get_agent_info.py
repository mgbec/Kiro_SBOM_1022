#!/usr/bin/env python3
"""
Helper script to find your deployed SBOM Security Agent information.

This script queries AWS to find your agent endpoint and other deployment details.
It can automatically detect your agent configuration and save it to .env file
for easy reuse in testing and applications.

Usage:
    python get_agent_info.py              # Interactive mode
    python get_agent_info.py --agent-name my-agent  # Find specific agent
    python get_agent_info.py --save-env   # Auto-detect and save to .env
    python get_agent_info.py --help       # Show help
"""

import boto3
import json
import os
import sys
import argparse
from boto3.session import Session


def find_agent_info(agent_name="sbom-security-agent"):
    """Find information about the deployed agent."""
    print(f"🔍 Looking for agent: {agent_name}")
    
    try:
        # Get AWS session and region
        boto_session = Session()
        region = boto_session.region_name
        
        if not region:
            print("❌ AWS region not configured. Please set AWS_DEFAULT_REGION or configure AWS CLI.")
            return None
        
        print(f"📍 Searching in region: {region}")
        
        # Initialize AgentCore client
        agentcore_client = boto3.client('bedrock-agentcore-control', region_name=region)
        
        print("⚠️  Direct agent listing via AgentCore Control API is not available")
        print("💡 AgentCore agents are managed through the Runtime toolkit")
        print("💡 Trying alternative detection methods...")
        
        # Try to find agent info from deployment artifacts
        agent_id = None
        agent_info = {}
        
        # Check for ECR repository (AgentCore Runtime creates these)
        try:
            ecr_client = boto3.client('ecr', region_name=region)
            repo_name = f"agentcore-runtime-{agent_name.lower().replace('_', '-')}"
            
            try:
                repo_info = ecr_client.describe_repositories(repositoryNames=[repo_name])
                if repo_info.get('repositories'):
                    print(f"✅ Found ECR repository: {repo_name}")
                    # Extract potential agent ID from repository tags or metadata
                    # This is a best-effort approach
                    agent_id = repo_name.replace('agentcore-runtime-', '')
                    agent_info = {
                        'agentName': agent_name,
                        'repository': repo_name
                    }
            except ecr_client.exceptions.RepositoryNotFoundException:
                pass
        except Exception as e:
            print(f"⚠️  Could not check ECR repositories: {str(e)}")
        
        # Check for Lambda function (AgentCore Runtime creates these)
        if not agent_id:
            try:
                lambda_client = boto3.client('lambda', region_name=region)
                function_name = f"agentcore-runtime-{agent_name.lower().replace('_', '-')}"
                
                try:
                    function_info = lambda_client.get_function(FunctionName=function_name)
                    print(f"✅ Found Lambda function: {function_name}")
                    # Extract agent ID from function metadata
                    agent_id = function_name.replace('agentcore-runtime-', '')
                    agent_info = {
                        'agentName': agent_name,
                        'functionName': function_name,
                        'functionArn': function_info.get('Configuration', {}).get('FunctionArn')
                    }
                except lambda_client.exceptions.ResourceNotFoundException:
                    pass
            except Exception as e:
                print(f"⚠️  Could not check Lambda functions: {str(e)}")
        
        if not agent_id:
            print(f"❌ Could not find deployment artifacts for agent '{agent_name}'")
            print("💡 Make sure the agent has been deployed successfully")
            print("💡 Try running the deployment script first")
            return None
        
        # Try to construct the endpoint URL
        endpoint_url = f"https://{agent_id}.bedrock-agentcore.{region}.amazonaws.com/invocations"
        
        print("\n" + "="*60)
        print("🎯 AGENT INFORMATION")
        print("="*60)
        print(f"Agent Name: {agent_info.get('agentName', 'Unknown')}")
        print(f"Agent ID: {agent_id}")
        print(f"Status: {agent_info.get('agentStatus', 'Unknown')}")
        print(f"Region: {region}")
        print(f"Endpoint URL: {endpoint_url}")
        print(f"Created: {agent_info.get('createdAt', 'Unknown')}")
        print(f"Updated: {agent_info.get('updatedAt', 'Unknown')}")
        
        # Show runtime information if available
        if 'agentRuntimeConfig' in agent_info:
            runtime_config = agent_info['agentRuntimeConfig']
            print(f"Runtime Status: {runtime_config.get('status', 'Unknown')}")
            
        print("="*60)
        
        return {
            "agent_id": agent_id,
            "agent_name": agent_info.get('agentName'),
            "endpoint_url": endpoint_url,
            "status": agent_info.get('agentStatus'),
            "region": region
        }
        
    except Exception as e:
        print(f"❌ Error finding agent information: {str(e)}")
        print("\nTroubleshooting:")
        print("1. Ensure AWS credentials are configured")
        print("2. Check that you have AgentCore permissions")
        print("3. Verify the agent was deployed successfully")
        print("4. Try running: aws bedrock-agentcore list-agents")
        return None


def find_cognito_info():
    """Find Cognito User Pool information."""
    print("\n🔍 Looking for Cognito User Pool information...")
    
    try:
        boto_session = Session()
        region = boto_session.region_name
        cognito_client = boto3.client('cognito-idp', region_name=region)
        
        # List user pools
        response = cognito_client.list_user_pools(MaxResults=50)
        user_pools = response.get('UserPools', [])
        
        # Look for our user pool
        mcp_pool = None
        for pool in user_pools:
            if 'MCPServerPool' in pool.get('Name', ''):
                mcp_pool = pool
                break
        
        if mcp_pool:
            pool_id = mcp_pool['Id']
            print(f"✅ Found Cognito User Pool: {mcp_pool['Name']}")
            print(f"   Pool ID: {pool_id}")
            
            # Get app clients
            clients_response = cognito_client.list_user_pool_clients(
                UserPoolId=pool_id,
                MaxResults=50
            )
            
            clients = clients_response.get('UserPoolClients', [])
            if clients:
                client = clients[0]  # Take the first client
                client_id = client['ClientId']
                print(f"   Client ID: {client_id}")
                
                discovery_url = f"https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/openid-configuration"
                print(f"   Discovery URL: {discovery_url}")
                
                return {
                    "pool_id": pool_id,
                    "client_id": client_id,
                    "discovery_url": discovery_url
                }
        
        print("❌ MCPServerPool not found")
        return None
        
    except Exception as e:
        print(f"❌ Error finding Cognito information: {str(e)}")
        return None


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
        from urllib.parse import urlparse
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


def try_get_endpoint_from_deployment():
    """Try to get the endpoint URL from recent deployment output."""
    import os
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


def get_endpoint_url_from_user():
    """Get and validate endpoint URL from user with helpful guidance."""
    print("\n📍 I need your AgentCore agent endpoint URL.")
    
    # Try auto-detection first
    print("🔍 Trying to auto-detect agent endpoint...")
    auto_endpoint = try_get_endpoint_from_deployment()
    
    if not auto_endpoint:
        agent_info = find_agent_info()
        if agent_info and agent_info.get('endpoint_url'):
            auto_endpoint = agent_info['endpoint_url']
    
    if auto_endpoint:
        use_detected = input(f"Found endpoint: {auto_endpoint}. Use this? (y/n): ").strip().lower()
        if use_detected in ['y', 'yes', '1', 'true']:
            validated_url, error = validate_endpoint_url(auto_endpoint)
            if not error:
                return validated_url
    
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


def save_agent_info_to_env(agent_info, cognito_info=None):
    """Save agent information to .env file for easy reuse."""
    try:
        env_content = []
        
        # Read existing .env file if it exists
        if os.path.exists('.env'):
            with open('.env', 'r') as f:
                env_content = f.readlines()
        
        # Remove existing agent-related variables
        env_content = [line for line in env_content if not any(
            line.startswith(var) for var in [
                'AGENT_ENDPOINT=', 'AGENT_ID=', 'AGENT_NAME=', 'AWS_REGION=',
                'COGNITO_CLIENT_ID=', 'COGNITO_POOL_ID=', 'COGNITO_DISCOVERY_URL='
            ]
        )]
        
        # Add new agent information
        env_content.append(f"AGENT_ENDPOINT={agent_info['endpoint_url']}\n")
        env_content.append(f"AGENT_ID={agent_info['agent_id']}\n")
        env_content.append(f"AGENT_NAME={agent_info['agent_name']}\n")
        env_content.append(f"AWS_REGION={agent_info['region']}\n")
        
        if cognito_info:
            env_content.append(f"COGNITO_CLIENT_ID={cognito_info['client_id']}\n")
            env_content.append(f"COGNITO_POOL_ID={cognito_info['pool_id']}\n")
            env_content.append(f"COGNITO_DISCOVERY_URL={cognito_info['discovery_url']}\n")
        
        # Write back to .env file
        with open('.env', 'w') as f:
            f.writelines(env_content)
        
        print("💾 Agent information saved to .env file")
        return True
        
    except Exception as e:
        print(f"⚠️  Could not save to .env file: {str(e)}")
        return False


def interactive_mode():
    """Interactive mode to help users find and configure their agent."""
    print("🎯 SBOM Security Agent Information Helper")
    print("="*50)
    print()
    print("This tool will help you find your deployed agent information")
    print("and save it for easy testing and usage.")
    print()
    
    # Find agent information
    agent_info = find_agent_info()
    
    if not agent_info:
        print("\n❌ Could not automatically find your agent.")
        print("Let me help you enter the information manually.")
        
        endpoint_url = get_endpoint_url_from_user()
        
        # Extract basic info from URL if possible
        try:
            from urllib.parse import urlparse
            parsed = urlparse(endpoint_url)
            hostname_parts = parsed.hostname.split('.')
            if len(hostname_parts) >= 3 and 'bedrock-agentcore' in hostname_parts[1]:
                agent_id = hostname_parts[0]
                region = hostname_parts[2]
                
                agent_info = {
                    "agent_id": agent_id,
                    "agent_name": "sbom-security-agent",
                    "endpoint_url": endpoint_url,
                    "status": "Unknown",
                    "region": region
                }
        except:
            pass
    
    # Find Cognito information
    cognito_info = find_cognito_info()
    
    # Save information to .env file
    if agent_info:
        save_to_env = input("\nWould you like to save this information to .env file for easy reuse? (y/n): ").strip().lower()
        if save_to_env in ['y', 'yes', '1', 'true']:
            save_agent_info_to_env(agent_info, cognito_info)
    
    print("\n" + "="*50)
    print("✅ Setup complete!")
    print()
    print("Next steps:")
    print("1. Run 'python test_deployment.py' to test your agent")
    print("2. Use the endpoint URL in your applications")
    print("3. Check the .env file for saved configuration")
    print("="*50)
    
    return agent_info, cognito_info


def main():
    """Main function with command line argument support."""
    parser = argparse.ArgumentParser(
        description="Find and configure your SBOM Security Agent information",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python get_agent_info.py                    # Interactive mode
  python get_agent_info.py --agent-name my-agent  # Find specific agent
  python get_agent_info.py --save-env         # Auto-detect and save to .env
  python get_agent_info.py --endpoint-only    # Just show endpoint URL
        """
    )
    
    parser.add_argument(
        '--agent-name', 
        default='sbom-security-agent',
        help='Name of the agent to find (default: sbom-security-agent)'
    )
    
    parser.add_argument(
        '--save-env',
        action='store_true',
        help='Automatically save found information to .env file'
    )
    
    parser.add_argument(
        '--endpoint-only',
        action='store_true',
        help='Only output the endpoint URL (useful for scripts)'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Minimal output (useful for scripts)'
    )
    
    args = parser.parse_args()
    
    if args.endpoint_only:
        # Just find and output the endpoint URL
        agent_info = find_agent_info(args.agent_name)
        if agent_info and agent_info.get('endpoint_url'):
            print(agent_info['endpoint_url'])
            sys.exit(0)
        else:
            if not args.quiet:
                print("❌ Could not find agent endpoint", file=sys.stderr)
            sys.exit(1)
    
    elif args.save_env:
        # Auto-detect and save to .env
        if not args.quiet:
            print("🔍 Auto-detecting agent information...")
        
        agent_info = find_agent_info(args.agent_name)
        cognito_info = find_cognito_info()
        
        if agent_info:
            if save_agent_info_to_env(agent_info, cognito_info):
                if not args.quiet:
                    print("✅ Agent information saved to .env file")
                sys.exit(0)
            else:
                if not args.quiet:
                    print("❌ Failed to save to .env file", file=sys.stderr)
                sys.exit(1)
        else:
            if not args.quiet:
                print("❌ Could not find agent information", file=sys.stderr)
            sys.exit(1)
    
    else:
        # Interactive mode
        try:
            interactive_mode()
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            sys.exit(0)
        except Exception as e:
            print(f"\n❌ Unexpected error: {str(e)}")
            print("Please check your AWS credentials and permissions.")
            sys.exit(1)


if __name__ == "__main__":
    main()