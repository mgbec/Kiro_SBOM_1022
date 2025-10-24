"""
Deployment configuration script for SBOM Security Agent.

This script configures the AgentCore Runtime deployment following the 
established patterns from the reference implementation.
"""

import os
import boto3
from bedrock_agentcore_starter_toolkit import Runtime
from boto3.session import Session
from utils import setup_cognito_user_pool, reauthenticate_user

# Configuration
AGENT_NAME = "sbom_security_agent"
ENTRYPOINT = "sbom_agent.py"
REQUIREMENTS_FILE = "requirements.txt"

def setup_github_oauth_provider():
    """Set up GitHub OAuth2 credential provider."""
    print("Setting up GitHub OAuth2 credential provider...")
    
    # Get GitHub credentials from environment
    github_client_id = os.getenv("GITHUB_CLIENT_ID")
    github_client_secret = os.getenv("GITHUB_CLIENT_SECRET")
    
    if not github_client_id or not github_client_secret:
        print("⚠️  GitHub OAuth credentials not found in environment variables.")
        print("Please set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET before deployment.")
        print("\nTo set up GitHub OAuth:")
        print("1. Go to GitHub Settings > Developer settings > OAuth Apps")
        print("2. Create a new OAuth App with:")
        print("   - Homepage URL: https://bedrock-agentcore.us-east-1.amazonaws.com/identities/oauth2/callback")
        print("   - Authorization callback URL: https://bedrock-agentcore.us-east-1.amazonaws.com/identities/oauth2/callback")
        print("3. Set environment variables:")
        print("   export GITHUB_CLIENT_ID='your-client-id'")
        print("   export GITHUB_CLIENT_SECRET='your-client-secret'")
        return False
    
    try:
        # Initialize AWS clients
        boto_session = Session()
        region = boto_session.region_name
        agentcore_client = boto3.client('bedrock-agentcore-control', region_name=region)
        
        # First, check if the provider already exists
        provider_name = 'github-provider'
        
        try:
            # Try to get the existing provider
            existing_providers = agentcore_client.list_oauth2_credential_providers()
            
            for provider in existing_providers.get('oauth2CredentialProviders', []):
                if provider.get('name') == provider_name:
                    print(f"ℹ️  GitHub OAuth2 provider '{provider_name}' already exists")
                    print(f"   Provider ARN: {provider.get('credentialProviderArn', 'N/A')}")
                    print(f"   Vendor: {provider.get('credentialProviderVendor', 'N/A')}")
                    print(f"   Created: {provider.get('createdAt', 'N/A')}")
                    print("✅ Using existing GitHub OAuth2 provider")
                    return True
                    
        except Exception as list_error:
            print(f"⚠️  Could not list existing providers: {str(list_error)}")
            print("   Proceeding to create new provider...")
        
        # If we get here, the provider doesn't exist, so create it
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
        print(f"   Provider ARN: {response['credentialProviderArn']}")
        print(f"   Name: {provider_name}")
        return True
        
    except Exception as e:
        error_message = str(e)
        
        # Check if the error is about the provider already existing
        if "already exists" in error_message.lower() or "duplicate" in error_message.lower():
            print(f"ℹ️  GitHub OAuth2 provider '{provider_name}' already exists")
            print("✅ Using existing GitHub OAuth2 provider")
            return True
        else:
            print(f"❌ Failed to create GitHub OAuth2 provider: {error_message}")
            return False

def setup_cognito_auth():
    """Set up Cognito authentication using the utils.py implementation."""
    print("Setting up Cognito authentication...")
    
    try:
        # Use the actual Cognito setup from utils.py
        cognito_config = setup_cognito_user_pool()
        
        if cognito_config:
            print("✅ Cognito User Pool created successfully")
            print(f"Pool ID: {cognito_config['pool_id']}")
            print(f"Client ID: {cognito_config['client_id']}")
            print(f"Discovery URL: {cognito_config['discovery_url']}")
            
            return {
                "discovery_url": cognito_config["discovery_url"],
                "client_id": cognito_config["client_id"],
                "pool_id": cognito_config["pool_id"],
                "bearer_token": cognito_config["bearer_token"]
            }
        else:
            print("❌ Failed to create Cognito User Pool")
            # Fallback to placeholder values for development
            print("⚠️  Using placeholder values for development")
            return {
                "discovery_url": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_EXAMPLE/.well-known/openid-configuration",
                "client_id": "example-client-id"
            }
            
    except Exception as e:
        print(f"❌ Error setting up Cognito: {str(e)}")
        print("⚠️  Using placeholder values for development")
        return {
            "discovery_url": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_EXAMPLE/.well-known/openid-configuration",
            "client_id": "example-client-id"
        }

def configure_agentcore_runtime():
    """Configure AgentCore Runtime deployment."""
    print("Configuring AgentCore Runtime deployment...")
    
    try:
        # Get AWS session and region
        boto_session = Session()
        region = boto_session.region_name
        
        if not region:
            print("❌ AWS region not configured. Please set AWS_DEFAULT_REGION or configure AWS CLI.")
            return False
        
        print(f"Using AWS region: {region}")
        
        # Set up Cognito (placeholder)
        cognito_config = setup_cognito_auth()
        
        # Initialize AgentCore Runtime
        agentcore_runtime = Runtime()
        
        # Configure runtime
        response = agentcore_runtime.configure(
            entrypoint=ENTRYPOINT,
            auto_create_execution_role=True,
            auto_create_ecr=True,
            requirements_file=REQUIREMENTS_FILE,
            region=region,
            agent_name=AGENT_NAME,
            authorizer_configuration={
                "customJWTAuthorizer": {
                    "discoveryUrl": cognito_config["discovery_url"],
                    "allowedClients": [cognito_config["client_id"]]
                }
            }
        )
        
        print("✅ AgentCore Runtime configured successfully")
        print(f"Configuration: {response}")
        
        return agentcore_runtime
        
    except Exception as e:
        print(f"❌ Failed to configure AgentCore Runtime: {str(e)}")
        return False

def deploy_agent(agentcore_runtime, auto_update_on_conflict=False):
    """Deploy the agent to AgentCore Runtime."""
    print("Deploying SBOM Security Agent to AgentCore Runtime...")
    
    try:
        # Launch the agent
        launch_result = agentcore_runtime.launch()
        
        print("✅ SBOM Security Agent deployed successfully!")
        print(f"Deployment result: {launch_result}")
        
        return launch_result
        
    except Exception as e:
        error_message = str(e)
        
        # Handle deployment conflicts
        if ("already exists" in error_message.lower() or 
            "conflict" in error_message.lower() or
            "duplicate" in error_message.lower()):
            
            print(f"⚠️  Deployment conflict detected: {error_message}")
            
            if auto_update_on_conflict:
                print("🔄 Auto-update mode: Attempting to resolve conflict...")
                print("💡 For more advanced conflict resolution, use: python enhanced_deployment.py")
                
                # Try launching again (AgentCore Runtime may handle updates automatically)
                try:
                    launch_result = agentcore_runtime.launch()
                    print("✅ SBOM Security Agent updated successfully!")
                    return launch_result
                except Exception as retry_error:
                    print(f"❌ Auto-update failed: {str(retry_error)}")
                    print("💡 Try using: python enhanced_deployment.py --auto-update")
                    return False
            else:
                print("\n💡 Conflict Resolution Options:")
                print("1. Use --auto-update-on-conflict flag to automatically handle conflicts")
                print("2. Use enhanced_deployment.py for more control:")
                print("   python enhanced_deployment.py --auto-update")
                print("   python enhanced_deployment.py --force-recreate")
                print("   python enhanced_deployment.py --agent-name different-name")
                return False
        else:
            print(f"❌ Failed to deploy agent: {error_message}")
            return False

def main():
    """Main deployment function."""
    import sys
    
    # Check for command line arguments
    auto_update_on_conflict = "--auto-update-on-conflict" in sys.argv
    
    if auto_update_on_conflict:
        print("🔄 Auto-update on conflict mode enabled")
    
    print("🚀 Starting SBOM Security Agent deployment...")
    print("="*60)
    
    # Step 1: Set up GitHub OAuth2 provider
    if not setup_github_oauth_provider():
        print("❌ GitHub OAuth2 setup failed. Deployment cannot continue.")
        return False
    
    print()
    
    # Step 2: Configure AgentCore Runtime
    agentcore_runtime = configure_agentcore_runtime()
    if not agentcore_runtime:
        print("❌ AgentCore Runtime configuration failed. Deployment cannot continue.")
        return False
    
    print()
    
    # Step 3: Deploy agent
    deployment_result = deploy_agent(agentcore_runtime, auto_update_on_conflict)
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
    print("5. Note: Cognito User Pool credentials are displayed above for authentication")
    
    return True

if __name__ == "__main__":
    import sys
    
    # Show help if requested
    if "--help" in sys.argv or "-h" in sys.argv:
        print("SBOM Security Agent Deployment Script")
        print("="*40)
        print()
        print("Usage:")
        print("  python deployment_config.py                    # Standard deployment")
        print("  python deployment_config.py --auto-update-on-conflict  # Handle conflicts automatically")
        print()
        print("For advanced conflict resolution, use:")
        print("  python enhanced_deployment.py --help")
        print()
        print("Options:")
        print("  --auto-update-on-conflict    Automatically handle deployment conflicts")
        print("  --help, -h                   Show this help message")
        sys.exit(0)
    
    success = main()
    exit(0 if success else 1)