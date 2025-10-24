#!/usr/bin/env python3
"""
Working deployment script for SBOM Security Agent with practical conflict resolution.

This script provides simple, reliable conflict resolution that actually works.
"""

import os
import sys
import argparse
import datetime
from deployment_config import (
    setup_github_oauth_provider,
    setup_cognito_auth,
    configure_agentcore_runtime
)


def generate_unique_agent_name(base_name, mode="auto"):
    """Generate a unique agent name with timestamp (using only valid characters)."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{base_name}_{mode}_{timestamp}"


def deploy_with_conflict_resolution(base_agent_name, auto_update=False, force_recreate=False):
    """Deploy agent with working conflict resolution."""
    
    # Determine the agent name to use
    if auto_update:
        agent_name = generate_unique_agent_name(base_agent_name, "update")
        print(f"🔄 Auto-update mode: Using unique name: {agent_name}")
    elif force_recreate:
        agent_name = generate_unique_agent_name(base_agent_name, "recreate")
        print(f"🔄 Force recreate mode: Using unique name: {agent_name}")
    else:
        agent_name = base_agent_name
        print(f"📝 Using standard agent name: {agent_name}")
    
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
    
    # Override the agent name in the runtime configuration
    print(f"🔧 Configuring runtime with agent name: {agent_name}")
    
    # We need to reconfigure with the new agent name
    try:
        from bedrock_agentcore_starter_toolkit import Runtime
        from boto3.session import Session
        from utils import setup_cognito_user_pool
        
        # Get region
        boto_session = Session()
        region = boto_session.region_name
        
        # Set up Cognito
        cognito_config = setup_cognito_user_pool()
        if not cognito_config:
            print("❌ Cognito setup failed")
            return False
        
        # Create new runtime with unique name
        agentcore_runtime = Runtime()
        response = agentcore_runtime.configure(
            entrypoint="sbom_agent.py",
            auto_create_execution_role=True,
            auto_create_ecr=True,
            requirements_file="requirements.txt",
            region=region,
            agent_name=agent_name,  # Use the unique name
            authorizer_configuration={
                "customJWTAuthorizer": {
                    "discoveryUrl": cognito_config["discovery_url"],
                    "allowedClients": [cognito_config["client_id"]]
                }
            }
        )
        
        print("✅ AgentCore Runtime reconfigured with unique name")
        
    except Exception as e:
        print(f"❌ Failed to reconfigure runtime: {str(e)}")
        return False
    
    print()
    
    # Step 3: Deploy agent
    try:
        print("🚀 Launching agent deployment...")
        deployment_result = agentcore_runtime.launch()
        
        print("✅ SBOM Security Agent deployed successfully!")
        print(f"🏷️  Agent Name: {agent_name}")
        print(f"Deployment result: {deployment_result}")
        
        # Save the agent name for future reference
        if agent_name != base_agent_name:
            try:
                with open('.env', 'a') as f:
                    f.write(f"\n# Auto-generated agent name from conflict resolution ({datetime.datetime.now()})\n")
                    f.write(f"DEPLOYED_AGENT_NAME={agent_name}\n")
                print(f"💾 Saved deployed agent name to .env file")
                print(f"💡 Use this name for future operations: {agent_name}")
            except Exception as env_error:
                print(f"⚠️  Could not save to .env file: {str(env_error)}")
        
        return deployment_result
        
    except Exception as e:
        error_message = str(e)
        print(f"❌ Deployment failed: {error_message}")
        
        # If we still get conflicts even with unique names, suggest manual cleanup
        if ("already exists" in error_message.lower() or 
            "conflict" in error_message.lower() or
            "duplicate" in error_message.lower()):
            
            print("\n💡 Even with unique names, conflicts detected. Try:")
            print("1. Clean up existing resources: python cleanup_deployment.py --execute")
            print("2. Use a completely different base name: --agent-name my-custom-agent")
            print("3. Check AWS console for conflicting resources")
        
        return False


def main():
    """Main deployment function."""
    parser = argparse.ArgumentParser(
        description="Deploy SBOM Security Agent with working conflict resolution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Working Conflict Resolution:
  --auto-update         Deploy with unique timestamped name (update mode)
  --force-recreate      Deploy with unique timestamped name (recreate mode)
  --agent-name NAME     Use specific agent name

Examples:
  python working_deployment.py                           # Standard deployment
  python working_deployment.py --auto-update             # Deploy with unique name
  python working_deployment.py --agent-name my-agent     # Use custom name
        """
    )
    
    parser.add_argument(
        '--auto-update',
        action='store_true',
        help='Deploy with unique timestamped name (update mode)'
    )
    
    parser.add_argument(
        '--force-recreate',
        action='store_true',
        help='Deploy with unique timestamped name (recreate mode)'
    )
    
    parser.add_argument(
        '--agent-name',
        default='sbom_security_agent',
        help='Base name for the agent (default: sbom_security_agent)'
    )
    
    args = parser.parse_args()
    
    # Validate conflicting options
    if args.auto_update and args.force_recreate:
        print("❌ Cannot use both --auto-update and --force-recreate together")
        sys.exit(1)
    
    try:
        success = deploy_with_conflict_resolution(
            args.agent_name,
            auto_update=args.auto_update,
            force_recreate=args.force_recreate
        )
        
        if success:
            print("\n" + "="*60)
            print("🎉 SBOM Security Agent deployment completed successfully!")
            print()
            print("Next steps:")
            print("1. Test the agent: python test_deployment.py")
            print("2. Find agent info: python get_agent_info.py")
            print("3. Configure monitoring and logging")
            print("="*60)
        else:
            print("\n❌ Deployment failed. Check the error messages above.")
            sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n\n👋 Deployment cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error during deployment: {str(e)}")
        print("Please check your AWS credentials and permissions.")
        sys.exit(1)


if __name__ == "__main__":
    main()