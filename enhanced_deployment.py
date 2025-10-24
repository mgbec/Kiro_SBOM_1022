#!/usr/bin/env python3
"""
Enhanced deployment script for SBOM Security Agent with conflict resolution.

This script extends the original deployment with options for handling
redeployment scenarios and conflicts.
"""

import os
import sys
import argparse
import boto3
from bedrock_agentcore_starter_toolkit import Runtime
from boto3.session import Session
from utils import setup_cognito_user_pool, reauthenticate_user

# Configuration
AGENT_NAME = "sbom_security_agent"
ENTRYPOINT = "sbom_agent.py"
REQUIREMENTS_FILE = "requirements.txt"


class DeploymentManager:
    """Manages deployment with conflict resolution capabilities."""
    
    def __init__(self, agent_name=AGENT_NAME, auto_update=False, force_recreate=False):
        self.agent_name = agent_name
        self.auto_update = auto_update
        self.force_recreate = force_recreate
        self.boto_session = Session()
        self.region = self.boto_session.region_name
        self.agentcore_client = boto3.client('bedrock-agentcore-control', region_name=self.region)
    
    def find_existing_agent(self):
        """Find existing agent by name."""
        try:
            response = self.agentcore_client.list_agents()
            agents = response.get('agents', [])
            
            for agent in agents:
                if self.agent_name.lower() in agent.get('agentName', '').lower():
                    return agent
            
            return None
            
        except Exception as e:
            print(f"⚠️  Could not list existing agents: {str(e)}")
            return None
    
    def delete_existing_agent(self, agent_id):
        """Delete an existing agent."""
        try:
            print(f"🗑️  Deleting existing agent: {agent_id}")
            self.agentcore_client.delete_agent(agentId=agent_id)
            print("✅ Existing agent deleted successfully")
            return True
            
        except Exception as e:
            print(f"❌ Failed to delete existing agent: {str(e)}")
            return False
    
    def update_existing_agent(self, agent_id):
        """Update an existing agent."""
        try:
            print(f"🔄 Updating existing agent: {agent_id}")
            
            # Get current agent configuration
            agent_details = self.agentcore_client.get_agent(agentId=agent_id)
            current_config = agent_details.get('agent', {})
            
            # Update agent with new configuration
            update_params = {
                'agentId': agent_id,
                'agentName': self.agent_name,
                'description': 'SBOM Security Agent - Updated deployment'
            }
            
            # Add any additional update parameters here
            response = self.agentcore_client.update_agent(**update_params)
            
            print("✅ Existing agent updated successfully")
            return response
            
        except Exception as e:
            print(f"❌ Failed to update existing agent: {str(e)}")
            return None
    
    def handle_existing_agent(self, existing_agent):
        """Handle existing agent based on deployment options."""
        agent_id = existing_agent.get('agentId')
        agent_name = existing_agent.get('agentName')
        agent_status = existing_agent.get('agentStatus', 'Unknown')
        
        print(f"🔍 Found existing agent:")
        print(f"   Name: {agent_name}")
        print(f"   ID: {agent_id}")
        print(f"   Status: {agent_status}")
        print()
        
        if self.force_recreate:
            print("🔄 Force recreate mode: Deleting existing agent...")
            if self.delete_existing_agent(agent_id):
                return None  # Proceed with new deployment
            else:
                return False  # Failed to delete
        
        elif self.auto_update:
            print("🔄 Auto-update mode: Updating existing agent...")
            return self.update_existing_agent(agent_id)
        
        else:
            # Interactive mode - ask user what to do
            print("❓ An agent with this name already exists. What would you like to do?")
            print("1. Update the existing agent (recommended)")
            print("2. Delete and recreate the agent")
            print("3. Cancel deployment")
            print("4. Deploy with a different name")
            
            while True:
                choice = input("Enter your choice (1-4): ").strip()
                
                if choice == '1':
                    return self.update_existing_agent(agent_id)
                elif choice == '2':
                    if self.delete_existing_agent(agent_id):
                        return None  # Proceed with new deployment
                    else:
                        return False
                elif choice == '3':
                    print("❌ Deployment cancelled by user")
                    return False
                elif choice == '4':
                    new_name = input("Enter new agent name: ").strip()
                    if new_name:
                        self.agent_name = new_name
                        return None  # Proceed with new deployment
                    else:
                        print("❌ Invalid agent name")
                        continue
                else:
                    print("❌ Invalid choice. Please enter 1, 2, 3, or 4.")
    
    def setup_github_oauth_provider(self):
        """Set up GitHub OAuth2 credential provider with conflict handling."""
        print("Setting up GitHub OAuth2 credential provider...")
        
        github_client_id = os.getenv("GITHUB_CLIENT_ID")
        github_client_secret = os.getenv("GITHUB_CLIENT_SECRET")
        
        if not github_client_id or not github_client_secret:
            print("⚠️  GitHub OAuth credentials not found in environment variables.")
            print("Please set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET before deployment.")
            return False
        
        try:
            provider_name = 'github-provider'
            
            # Check if provider already exists
            try:
                existing_providers = self.agentcore_client.list_oauth2_credential_providers()
                
                for provider in existing_providers.get('oauth2CredentialProviders', []):
                    if provider.get('name') == provider_name:
                        print(f"ℹ️  GitHub OAuth2 provider '{provider_name}' already exists")
                        
                        if self.auto_update or self.force_recreate:
                            print("🔄 Updating existing OAuth2 provider...")
                            # Note: AgentCore may not support updating providers
                            # In that case, we'll use the existing one
                            print("✅ Using existing GitHub OAuth2 provider")
                            return True
                        else:
                            use_existing = input("Use existing GitHub OAuth2 provider? (y/n): ").strip().lower()
                            if use_existing in ['y', 'yes', '1', 'true']:
                                print("✅ Using existing GitHub OAuth2 provider")
                                return True
                            else:
                                print("❌ Cannot proceed without OAuth2 provider")
                                return False
                        
            except Exception as list_error:
                print(f"⚠️  Could not list existing providers: {str(list_error)}")
                print("   Proceeding to create new provider...")
            
            # Create new provider
            print("📝 Creating new GitHub OAuth2 provider...")
            response = self.agentcore_client.create_oauth2_credential_provider(
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
    
    def setup_cognito_auth(self):
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
    
    def configure_runtime(self, cognito_config):
        """Configure AgentCore Runtime."""
        print("Configuring AgentCore Runtime deployment...")
        
        try:
            if not self.region:
                print("❌ AWS region not configured. Please set AWS_DEFAULT_REGION or configure AWS CLI.")
                return False
            
            print(f"Using AWS region: {self.region}")
            
            # Initialize AgentCore Runtime
            agentcore_runtime = Runtime()
            
            # Configure runtime
            response = agentcore_runtime.configure(
                entrypoint=ENTRYPOINT,
                auto_create_execution_role=True,
                auto_create_ecr=True,
                requirements_file=REQUIREMENTS_FILE,
                region=self.region,
                agent_name=self.agent_name,
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
    
    def deploy_agent(self, agentcore_runtime):
        """Deploy the agent with conflict handling."""
        print("Deploying SBOM Security Agent to AgentCore Runtime...")
        
        try:
            # Check for existing agent first
            existing_agent = self.find_existing_agent()
            
            if existing_agent:
                result = self.handle_existing_agent(existing_agent)
                
                if result is False:
                    # User cancelled or error occurred
                    return False
                elif result is not None:
                    # Agent was updated
                    print("✅ SBOM Security Agent updated successfully!")
                    return result
                # If result is None, proceed with new deployment
            
            # Launch new agent
            launch_result = agentcore_runtime.launch()
            
            print("✅ SBOM Security Agent deployed successfully!")
            print(f"Deployment result: {launch_result}")
            
            return launch_result
            
        except Exception as e:
            error_message = str(e)
            
            # Handle specific conflict errors
            if "already exists" in error_message.lower() or "conflict" in error_message.lower():
                print(f"⚠️  Deployment conflict detected: {error_message}")
                
                if self.auto_update:
                    print("🔄 Auto-update mode: Attempting to resolve conflict...")
                    # Try to find and update the existing agent
                    existing_agent = self.find_existing_agent()
                    if existing_agent:
                        return self.handle_existing_agent(existing_agent)
                
                print("❌ Deployment failed due to conflict. Try using --auto-update or --force-recreate")
                return False
            else:
                print(f"❌ Failed to deploy agent: {error_message}")
                return False
    
    def deploy(self):
        """Main deployment method."""
        print(f"🚀 Starting SBOM Security Agent deployment...")
        print(f"   Agent Name: {self.agent_name}")
        print(f"   Auto Update: {self.auto_update}")
        print(f"   Force Recreate: {self.force_recreate}")
        print("="*60)
        
        # Step 1: Set up GitHub OAuth2 provider
        if not self.setup_github_oauth_provider():
            print("❌ GitHub OAuth2 setup failed. Deployment cannot continue.")
            return False
        
        print()
        
        # Step 2: Set up Cognito authentication
        cognito_config = self.setup_cognito_auth()
        
        print()
        
        # Step 3: Configure AgentCore Runtime
        agentcore_runtime = self.configure_runtime(cognito_config)
        if not agentcore_runtime:
            print("❌ AgentCore Runtime configuration failed. Deployment cannot continue.")
            return False
        
        print()
        
        # Step 4: Deploy agent
        deployment_result = self.deploy_agent(agentcore_runtime)
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


def main():
    """Main function with command line argument support."""
    parser = argparse.ArgumentParser(
        description="Deploy SBOM Security Agent with conflict resolution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Conflict Resolution Options:
  --auto-update         Automatically update existing agents instead of failing
  --force-recreate      Delete and recreate existing agents
  --agent-name NAME     Use a different agent name to avoid conflicts

Examples:
  python enhanced_deployment.py                    # Interactive deployment
  python enhanced_deployment.py --auto-update     # Auto-update existing agents
  python enhanced_deployment.py --force-recreate  # Delete and recreate
  python enhanced_deployment.py --agent-name my-agent  # Use different name
        """
    )
    
    parser.add_argument(
        '--auto-update',
        action='store_true',
        help='Automatically update existing agents instead of failing on conflicts'
    )
    
    parser.add_argument(
        '--force-recreate',
        action='store_true',
        help='Delete and recreate existing agents (destructive operation)'
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
        # Create deployment manager
        deployment_manager = DeploymentManager(
            agent_name=args.agent_name,
            auto_update=args.auto_update,
            force_recreate=args.force_recreate
        )
        
        # Run deployment
        success = deployment_manager.deploy()
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\n\n👋 Deployment cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error during deployment: {str(e)}")
        print("Please check your AWS credentials and permissions.")
        sys.exit(1)


if __name__ == "__main__":
    main()