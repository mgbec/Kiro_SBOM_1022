#!/usr/bin/env python3
"""
Cleanup utility for SBOM Security Agent deployment resources.

This script helps identify and clean up AWS resources created by AgentCore Runtime
deployments to resolve conflicts.
"""

import os
import sys
import argparse
import boto3
from boto3.session import Session


def list_agentcore_resources(agent_name_pattern="sbom"):
    """List AgentCore-related resources that might cause conflicts."""
    print(f"🔍 Searching for AgentCore resources matching pattern: '{agent_name_pattern}'")
    
    boto_session = Session()
    region = boto_session.region_name
    
    if not region:
        print("❌ AWS region not configured. Please set AWS_DEFAULT_REGION or configure AWS CLI.")
        return []
    
    print(f"📍 Searching in region: {region}")
    
    resources = []
    
    # Check ECR repositories
    try:
        ecr_client = boto3.client('ecr', region_name=region)
        response = ecr_client.describe_repositories()
        
        for repo in response.get('repositories', []):
            repo_name = repo.get('repositoryName', '')
            if 'agentcore-runtime' in repo_name and agent_name_pattern in repo_name:
                resources.append({
                    'type': 'ECR Repository',
                    'name': repo_name,
                    'arn': repo.get('repositoryArn'),
                    'created': repo.get('createdAt'),
                    'client': ecr_client,
                    'delete_method': 'delete_repository',
                    'delete_params': {'repositoryName': repo_name, 'force': True}
                })
                
    except Exception as e:
        print(f"⚠️  Could not list ECR repositories: {str(e)}")
    
    # Check Lambda functions
    try:
        lambda_client = boto3.client('lambda', region_name=region)
        response = lambda_client.list_functions()
        
        for func in response.get('Functions', []):
            func_name = func.get('FunctionName', '')
            if 'agentcore-runtime' in func_name and agent_name_pattern in func_name:
                resources.append({
                    'type': 'Lambda Function',
                    'name': func_name,
                    'arn': func.get('FunctionArn'),
                    'created': func.get('LastModified'),
                    'client': lambda_client,
                    'delete_method': 'delete_function',
                    'delete_params': {'FunctionName': func_name}
                })
                
    except Exception as e:
        print(f"⚠️  Could not list Lambda functions: {str(e)}")
    
    # Check IAM roles
    try:
        iam_client = boto3.client('iam', region_name=region)
        response = iam_client.list_roles()
        
        for role in response.get('Roles', []):
            role_name = role.get('RoleName', '')
            if 'AgentCoreRuntimeRole' in role_name and agent_name_pattern in role_name:
                resources.append({
                    'type': 'IAM Role',
                    'name': role_name,
                    'arn': role.get('Arn'),
                    'created': role.get('CreateDate'),
                    'client': iam_client,
                    'delete_method': 'delete_role',
                    'delete_params': {'RoleName': role_name},
                    'requires_policy_cleanup': True
                })
                
    except Exception as e:
        print(f"⚠️  Could not list IAM roles: {str(e)}")
    
    # Check CloudWatch Log Groups
    try:
        logs_client = boto3.client('logs', region_name=region)
        response = logs_client.describe_log_groups()
        
        for log_group in response.get('logGroups', []):
            log_group_name = log_group.get('logGroupName', '')
            if 'bedrock-agentcore' in log_group_name and agent_name_pattern in log_group_name:
                resources.append({
                    'type': 'CloudWatch Log Group',
                    'name': log_group_name,
                    'arn': log_group.get('arn'),
                    'created': log_group.get('creationTime'),
                    'client': logs_client,
                    'delete_method': 'delete_log_group',
                    'delete_params': {'logGroupName': log_group_name}
                })
                
    except Exception as e:
        print(f"⚠️  Could not list CloudWatch Log Groups: {str(e)}")
    
    return resources


def display_resources(resources):
    """Display found resources in a formatted way."""
    if not resources:
        print("✅ No AgentCore resources found matching the pattern")
        return
    
    print(f"\n📋 Found {len(resources)} AgentCore resources:")
    print("="*80)
    
    for i, resource in enumerate(resources, 1):
        print(f"{i}. {resource['type']}: {resource['name']}")
        if resource.get('arn'):
            print(f"   ARN: {resource['arn']}")
        if resource.get('created'):
            print(f"   Created: {resource['created']}")
        print()


def cleanup_resources(resources, dry_run=True):
    """Clean up the specified resources."""
    if not resources:
        print("✅ No resources to clean up")
        return True
    
    if dry_run:
        print("🔍 DRY RUN MODE - No resources will be deleted")
        print("Run with --execute to actually delete resources")
        print()
    
    success_count = 0
    error_count = 0
    
    for resource in resources:
        resource_type = resource['type']
        resource_name = resource['name']
        
        try:
            if dry_run:
                print(f"[DRY RUN] Would delete {resource_type}: {resource_name}")
            else:
                print(f"🗑️  Deleting {resource_type}: {resource_name}")
                
                # Handle IAM roles specially (need to detach policies first)
                if resource.get('requires_policy_cleanup'):
                    cleanup_iam_role_policies(resource['client'], resource_name)
                
                # Delete the resource
                delete_method = getattr(resource['client'], resource['delete_method'])
                delete_method(**resource['delete_params'])
                
                print(f"✅ Deleted {resource_type}: {resource_name}")
            
            success_count += 1
            
        except Exception as e:
            error_message = str(e)
            if dry_run:
                print(f"[DRY RUN] Would fail to delete {resource_type}: {resource_name} - {error_message}")
            else:
                print(f"❌ Failed to delete {resource_type}: {resource_name} - {error_message}")
            error_count += 1
    
    print()
    if dry_run:
        print(f"📊 DRY RUN SUMMARY: {success_count} resources would be deleted, {error_count} would fail")
    else:
        print(f"📊 CLEANUP SUMMARY: {success_count} resources deleted, {error_count} failed")
    
    return error_count == 0


def cleanup_iam_role_policies(iam_client, role_name):
    """Clean up IAM role policies before deleting the role."""
    try:
        # Detach managed policies
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
        for policy in attached_policies.get('AttachedPolicies', []):
            iam_client.detach_role_policy(
                RoleName=role_name,
                PolicyArn=policy['PolicyArn']
            )
        
        # Delete inline policies
        inline_policies = iam_client.list_role_policies(RoleName=role_name)
        for policy_name in inline_policies.get('PolicyNames', []):
            iam_client.delete_role_policy(
                RoleName=role_name,
                PolicyName=policy_name
            )
            
    except Exception as e:
        print(f"⚠️  Warning: Could not clean up policies for role {role_name}: {str(e)}")


def main():
    """Main cleanup function."""
    parser = argparse.ArgumentParser(
        description="Clean up AgentCore deployment resources",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cleanup_deployment.py                           # List resources (dry run)
  python cleanup_deployment.py --execute                 # Actually delete resources
  python cleanup_deployment.py --pattern my-agent        # Search for specific pattern
  python cleanup_deployment.py --pattern sbom --execute  # Delete resources matching 'sbom'
        """
    )
    
    parser.add_argument(
        '--pattern',
        default='sbom',
        help='Pattern to match in resource names (default: sbom)'
    )
    
    parser.add_argument(
        '--execute',
        action='store_true',
        help='Actually delete resources (default is dry run)'
    )
    
    parser.add_argument(
        '--region',
        help='AWS region to search in (overrides AWS_DEFAULT_REGION)'
    )
    
    args = parser.parse_args()
    
    # Set region if provided
    if args.region:
        os.environ['AWS_DEFAULT_REGION'] = args.region
    
    try:
        print("🧹 AgentCore Resource Cleanup Utility")
        print("="*50)
        
        if not args.execute:
            print("⚠️  DRY RUN MODE - No resources will be deleted")
            print("   Use --execute to actually delete resources")
            print()
        
        # Find resources
        resources = list_agentcore_resources(args.pattern)
        
        # Display what was found
        display_resources(resources)
        
        if resources:
            if args.execute:
                # Confirm before deletion
                print("⚠️  WARNING: This will permanently delete the resources listed above!")
                confirm = input("Are you sure you want to proceed? (type 'yes' to confirm): ").strip().lower()
                
                if confirm != 'yes':
                    print("❌ Cleanup cancelled by user")
                    sys.exit(0)
            
            # Clean up resources
            success = cleanup_resources(resources, dry_run=not args.execute)
            
            if success and args.execute:
                print("\n🎉 Cleanup completed successfully!")
                print("You can now try deploying your agent again.")
            elif not args.execute:
                print("\n💡 To actually delete these resources, run:")
                print(f"   python cleanup_deployment.py --pattern {args.pattern} --execute")
        
        sys.exit(0)
        
    except KeyboardInterrupt:
        print("\n\n👋 Cleanup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error during cleanup: {str(e)}")
        print("Please check your AWS credentials and permissions.")
        sys.exit(1)


if __name__ == "__main__":
    main()