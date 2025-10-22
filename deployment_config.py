"""
Deployment configuration script for SBOM Security Agent.

This script configures the AgentCore Runtime deployment following the 
established patterns from the reference implementation.
"""

import os
import boto3
from bedrock_agentcore_starter_toolkit import Runtime
from boto3.session import Session

# Configuration
AGENT_NAME = "sbom-security-agent"
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
        # Create credential provider
        boto_session = Session()
        region = boto_session.region_name
        agentcore_client = boto3.client('bedrock-agentcore-control', region_name=region)
        
        response = agentcore_client.create_oauth2_credential_provider(
            name='github-provider',
            credentialProviderVendor='GithubOauth2',
            oauth2ProviderConfigInput={
                'githubOauth2ProviderConfig': {
                    'clientId': github_client_id,
                    'clientSecret': github_client_secret
                }
            }
        )
        
        print(f"✅ GitHub OAuth2 provider created: {response['credentialProviderArn']}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to create GitHub OAuth2 provider: {str(e)}")
        return False

def setup_cognito_auth():
    """Set up Cognito authentication (placeholder for actual implementation)."""
    print("Setting up Cognito authentication...")
    print("ℹ️  For production deployment, configure Cognito User Pool with:")
    print("   - User Pool with App Client")
    print("   - JWT token configuration")
    print("   - Appropriate scopes and permissions")
    print("✅ Cognito configuration placeholder completed")
    return {
        "discovery_url": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_EXAMPLE/.well-known/openid_configuration",
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

def deploy_agent(agentcore_runtime):
    """Deploy the agent to AgentCore Runtime."""
    print("Deploying SBOM Security Agent to AgentCore Runtime...")
    
    try:
        # Launch the agent
        launch_result = agentcore_runtime.launch()
        
        print("✅ SBOM Security Agent deployed successfully!")
        print(f"Deployment result: {launch_result}")
        
        return launch_result
        
    except Exception as e:
        print(f"❌ Failed to deploy agent: {str(e)}")
        return False

def main():
    """Main deployment function."""
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
    deployment_result = deploy_agent(agentcore_runtime)
    if not deployment_result:
        print("❌ Agent deployment failed.")
        return False
    
    print()
    print("="*60)
    print("🎉 SBOM Security Agent deployment completed successfully!")
    print()
    print("Next steps:")
    print("1. Test the agent with a sample repository")
    print("2. Configure monitoring and logging")
    print("3. Set up CI/CD pipeline for updates")
    print("4. Review security and compliance settings")
    
    return True

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)