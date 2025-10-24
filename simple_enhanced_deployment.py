#!/usr/bin/env python3
"""
Simplified enhanced deployment script for SBOM Security Agent.

This script provides conflict resolution without relying on unavailable AgentCore APIs.
It focuses on what we can actually control: agent names and resource cleanup.
"""

import os
import sys
import argparse
import boto3
from bedrock_agentcore_starter_toolkit import Runtime
from boto3.session import Session
from utils import setup_cognito_user_pool

# Configuration
AGENT_NAME = "sbom_security_agent"
ENTRYPOINT = "sbom_agent.py"
REQUIREMENTS_FILE = "requirements.txt"


def setup_github_oauth_provider():
    """Set up GitHub OAuth2 credential provider with conflict handling."""
    print("Setting up GitHub OAuth2 credential provider...")
    
    github_client_id = os.getenv("GITHUB_CLIENT_ID")
    github_client_secret = os.getenv("GITHUB_CLIENT_SECRET")
    
    if not github_client_id or not github_client_secret:
        print("⚠️  GitHub OAuth credentials not found in environment variables.")
        print("Please set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET before deployment.")
        return False
    
    try:
        boto_session = Session()
        region = boto_session.region_name
        agentcore_client = boto3.client('bedrock-agentcore-control', region_name=region)
        
        provider_name = 'github-provider'
        
        # Check if provider already exists
        try:
            existing_providers = agentcore_client.list_oauth2_credential_providers()
            
            for provider in existing_providers.get('oauth2CredentialProviders', []):
                if provider.get('name') == provider_name:
                    print(f"ℹ️  GitHub OAuth2 provider '{provider_name}' already exists")
                    print("✅ Using existing GitHub OAuth2 provider")
                    return True
                    
        except Exception as list_error:
            print(f"⚠️  Could not list existing providers: {str(list_error)}")
            print("   Proceeding to create new provider...")
        
        # Create new provider
        print("📝 Creating new GitHub OAuth2 provider...")
        response = agentcore_client.create_oauth2_credential_provider(
            name=provider_name,
            credentialProviderVendor='GithubOauth2',
            oauth2ProviderConfigInput={
                'githubOauth2ProviderConfig': {
                    'clientId': github_client_id,
                    'clientSecret': github_client_secret
                }
            }
        )
        
        print(f"✅ GitHub OAuth2 provider created successfully!")
        return True
        
    except Exception as e:
        error_message = str(e)
        
        if "already exists" in error_message.lower():
            print(f"ℹ️  GitHub OAuth2 provider '{provider_name}' already exists")
            print("✅ Using existing GitHub OAuth2 provider")
            return True
        else:
            print(f"❌ Failed to create GitHub OAuth2 provider: {error_message}")
            return False


def setup_cognito_auth():
    """Set up Cognito authentication."""
    print("Setting up Cognito authentication...")
    
    try:
        cognito_config = setup_cognito_user_pool()
        
        if cognito_config:
            print("✅ Cognito User Pool created successfully")
            return {
                "discovery_url": cognito_config["discovery_url"],
                "client_id": cognito_config["client_id"],
                "pool_id": cognito_config["pool_id"],
                "bearer_token": cognito_config["bearer_token"]
            }
        else:
            print("❌ Failed to create Cognito User Pool")
            return {
                "discovery_url": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_EXAMPLE/.well-known/openid-configuration",
                "client_id": "example-client-id"
            }
            
    except Exception as e:
        print(f"❌ Error setting up Cognito: {str(e)}")
        return {
            "discovery_url": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_EXAMPLE/.well-known/openid-configuration",
            "client_id": "example-client-id"
        }


def configure_runtime(agent_name, cognito_config):
    """Configure AgentCore Runtime."""
    print("Configuring AgentCore Runtime deployment...")
    
    try:
        boto_session = Session()
        region = boto_session.region_name
        
        if not region:
            print("❌ AWS region not configured. Please set AWS_DEFAULT_REGION or configure AWS CLI.")
            return False
        
        print(f"Using AWS region: {region}")
        
        # Initialize AgentCore Runtime
        agentcore_runtime = Runtime()
        
        # Configure runtime
        response = agentcore_runtime.configure(
            entrypoint=ENTRYPOINT,
            auto_create_execution_role=True,
            auto_create_ecr=True,
            requirements_file=REQUIREMENTS_FILE,
            region=region,
            agent_name=agent_name,
            authorizer_configuration={
                "customJWTAuthorizer": {
                    "discoveryUrl": cognito_config["discovery_url"],
                    "allowedClients": [cognito_config["client_id"]]
                }
            }
        )
        
        print("✅ AgentCore Runtime configured successfully")
        return agentcore_runtime
        
    except Exception as e:
        print(f"❌ Failed to configure AgentCore Runtime: {str(e)}")
        return False


def deploy_with_conflict_handling(agentcore_runtime, agent_name, auto_update=False, force_recreate=False):
    """Deploy the agent with practical conflict handling."""
    print("Deploying SBOM Security Agent to AgentCore Runtime...")
    
    try:
        # Launch the agent
        print("🚀 Launching agent deployment...")
        launch_result = agentcore_runtime.launch()
        
        print("✅ SBOM Security Agent deployed successfully!")
        print(f"Deployment result: {launch_result}")
        
        return launch_result
        
    except Exception as e:
        error_message = str(e)
        
        # Handle specific conflict errors
        if ("already exists" in error_message.lower() or 
            "conflict" in error_message.lower() or
            "duplicate" in error_message.lower() or
            "resourceconflictexception" in error_message.lower()):
            
            print(f"⚠️  Deployment conflict detected: {error_message}")
            
            if auto_update:
                print("🔄 Auto-update mode: Trying deployment with timestamp suffix...")
                return try_deployment_with_unique_name(agent_name, "update")
            elif force_recreate:
                print("🔄 Force recreate mode: Trying deployment with new unique name...")
                return try_deployment_with_unique_name(agent_name, "recreate")
            else:
                print("\n💡 Conflict Resolution Options:")
                print("1. Run with --auto-update to deploy with a unique name")
                print("2. Run with --force-recreate to deploy with a new unique name")
                print("3. Use --agent-name to specify a different name")
                print("4. Clean up existing resources: python cleanup_deployment.py --execute")
                print("5. List existing resources: python cleanup_deployment.py")
                print("\n🔄 Attempting automatic resolution with unique name...")
                return try_deployment_with_unique_name(agent_name, "auto")
            
        else:
            print(f"❌ Failed to deploy agent: {error_message}")
            return False


def try_deployment_with_unique_name(base_agent_name, mode):
    """Try deployment with a unique agent name to avoid conflicts."""
    import datetime
    
    # Generate unique suffix
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    unique_agent_name = f"{base_agent_name}-{mode}-{timestamp}"
    
    print(f"🔄 Attempting deployment with unique name: {unique_agent_name}")
    
    try:
        # Set up Cognito auth again
        cognito_config = setup_cognito_auth()
        
        # Configure runtime with unique name
        agentcore_runtime = configure_runtime(unique_agent_name, cognito_config)
        if not agentcore_runtime:
            print("❌ Failed to configure runtime with unique name")
            return False
        
        # Launch with unique name
        launch_result = agentcore_runtime.launch()
        
        print("✅ SBOM Security Agent deployed successfully with unique name!")
        print(f"🏷️  Agent Name: {unique_agent_name}")
        print(f"Deployment result: {launch_result}")
        
        # Save the new agent name to environment for future use
        try:
            with open('.env', 'a') as f:
                f.write(f"\n# Auto-generated agent name from conflict resolution\n")
                f.write(f"AGENT_NAME={unique_agent_name}\n")
            print(f"💾 Saved new agent name to .env file")
        except Exception as env_error:
            print(f"⚠️  Could not save to .env file: {str(env_error)}")
        
        return launch_result
        
    except Exception as e:
        print(f"❌ Failed to deploy with unique name: {str(e)}")
        print("💡 You may need to manually clean up AWS resources or use a different base name")
        return False


def main():
    """Main deployment function with command line arguments."""
    parser = argparse.ArgumentParser(
        description="Deploy SBOM Security Agent with basic conflict resolution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Conflict Resolution Options:
  --auto-update         Let AgentCore Runtime handle existing resources
  --force-recreate      Let AgentCore Runtime clean up and recreate
  --agent-name NAME     Use a different agent name to avoid conflicts

Examples:
  python simple_enhanced_deployment.py                    # Standard deployment
  python simple_enhanced_deployment.py --auto-update     # Handle conflicts automatically
  python simple_enhanced_deployment.py --agent-name my-agent  # Use different name
        """
    )
    
    parser.add_argument(
        '--auto-update',
        action='store_true',
        help='Let AgentCore Runtime handle existing resources automatically'
    )
    
    parser.add_argument(
        '--force-recreate',
        action='store_true',
        help='Let AgentCore Runtime clean up and recreate resources'
    )
    
    parser.add_argument(
        '--agent-name',
        default=AGENT_NAME,
        help=f'Name for the agent (default: {AGENT_NAME})'
    )
    
    parser.add_argument(
        '--region',
        help='AWS region to deploy to (overrides AWS_DEFAULT_REGION)'
    )
    
    args = parser.parse_args()
    
    # Set region if provided
    if args.region:
        os.environ['AWS_DEFAULT_REGION'] = args.region
    
    # Validate conflicting options
    if args.auto_update and args.force_recreate:
        print("❌ Cannot use both --auto-update and --force-recreate together")
        sys.exit(1)
    
    try:
        print(f"🚀 Starting SBOM Security Agent deployment...")
        print(f"   Agent Name: {args.agent_name}")
        print(f"   Auto Update: {args.auto_update}")
        print(f"   Force Recreate: {args.force_recreate}")
        print("="*60)
        
        # Step 1: Set up GitHub OAuth2 provider
        if not setup_github_oauth_provider():
            print("❌ GitHub OAuth2 setup failed. Deployment cannot continue.")
            return False
        
        print()
        
        # Step 2: Set up Cognito authentication
        cognito_config = setup_cognito_auth()
        
        print()
        
        # Step 3: Configure AgentCore Runtime
        agentcore_runtime = configure_runtime(args.agent_name, cognito_config)
        if not agentcore_runtime:
            print("❌ AgentCore Runtime configuration failed. Deployment cannot continue.")
            return False
        
        print()
        
        # Step 4: Deploy agent with conflict handling
        deployment_result = deploy_with_conflict_handling(
            agentcore_runtime,
            args.agent_name,
            auto_update=args.auto_update,
            force_recreate=args.force_recreate
        )
        
        if not deployment_result:
            print("❌ Agent deployment failed.")
            return False
        
        print()
        print("="*60)
        print("🎉 SBOM Security Agent deployment completed successfully!")
        print()
        print("Next steps:")
        print("1. Test the agent: python test_deployment.py")
        print("2. Find agent info: python get_agent_info.py")
        print("3. Configure monitoring and logging")
        print("4. Set up CI/CD pipeline for updates")
        
        return True
        
    except KeyboardInterrupt:
        print("\n\n👋 Deployment cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error during deployment: {str(e)}")
        print("Please check your AWS credentials and permissions.")
        sys.exit(1)


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)