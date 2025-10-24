# Deployment Options and Conflict Resolution

This guide explains the different deployment options available for the SBOM Security Agent and how to handle redeployment scenarios.

## Deployment Scripts

### 1. `deployment_config.py` - Standard Deployment
Basic deployment script with simple conflict handling.

```bash
# Standard deployment
python deployment_config.py

# Handle conflicts automatically
python deployment_config.py --auto-update-on-conflict

# Show help
python deployment_config.py --help
```

### 2. `enhanced_deployment.py` - Advanced Deployment
Full-featured deployment with comprehensive conflict resolution.

```bash
# Interactive deployment (recommended)
python enhanced_deployment.py

# Auto-update existing agents
python enhanced_deployment.py --auto-update

# Delete and recreate agents
python enhanced_deployment.py --force-recreate

# Use different agent name
python enhanced_deployment.py --agent-name my-custom-agent

# Deploy to specific region
python enhanced_deployment.py --region us-west-2

# Show help
python enhanced_deployment.py --help
```

### 3. `production_deployment.py` - Production Deployment
Production-specific deployment with OAuth callback handling.

```bash
# Production deployment (requires environment variables)
python production_deployment.py
```

## Conflict Resolution Strategies

### What Causes Deployment Conflicts?

1. **Agent Name Conflicts**: An agent with the same name already exists
2. **Resource Conflicts**: ECR repositories, IAM roles, or other AWS resources exist
3. **OAuth Provider Conflicts**: GitHub OAuth provider already configured
4. **Cognito Conflicts**: User pool or client already exists

### Resolution Options

#### 1. Auto-Update (Recommended)
Updates existing resources instead of creating new ones.

```bash
# Simple auto-update
python deployment_config.py --auto-update-on-conflict

# Advanced auto-update
python enhanced_deployment.py --auto-update
```

**Pros:**
- Preserves existing configuration
- Minimal disruption
- Safe for production

**Cons:**
- May not update all components
- Limited to compatible changes

#### 2. Force Recreate
Deletes existing resources and creates new ones.

```bash
python enhanced_deployment.py --force-recreate
```

**Pros:**
- Clean deployment
- Ensures all components are updated
- Resolves configuration drift

**Cons:**
- Destructive operation
- Temporary downtime
- Loses existing data/configuration

#### 3. Different Name
Deploy with a different agent name to avoid conflicts.

```bash
python enhanced_deployment.py --agent-name sbom-agent-v2
```

**Pros:**
- No conflicts
- Allows side-by-side deployment
- Safe testing

**Cons:**
- Multiple agents to manage
- Resource duplication
- Manual cleanup needed

#### 4. Interactive Resolution
Let the script guide you through conflict resolution.

```bash
python enhanced_deployment.py
# Follow the interactive prompts when conflicts are detected
```

## Environment-Specific Deployment

### Development
```bash
# Quick deployment with auto-update
python deployment_config.py --auto-update-on-conflict
```

### Staging
```bash
# Controlled deployment with specific name
python enhanced_deployment.py --agent-name sbom-agent-staging --auto-update
```

### Production
```bash
# Production deployment with all required environment variables
export GITHUB_CLIENT_ID="your-prod-client-id"
export GITHUB_CLIENT_SECRET="your-prod-client-secret"
export OAUTH_CALLBACK_URL="https://your-app.com/oauth/callback"
export COGNITO_DISCOVERY_URL="https://cognito-idp.us-east-1.amazonaws.com/..."
export COGNITO_CLIENT_ID="your-cognito-client-id"

python production_deployment.py
```

## CI/CD Integration

### GitHub Actions Example
```yaml
name: Deploy SBOM Agent

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      
      - name: Deploy Agent
        env:
          GITHUB_CLIENT_ID: ${{ secrets.GITHUB_CLIENT_ID }}
          GITHUB_CLIENT_SECRET: ${{ secrets.GITHUB_CLIENT_SECRET }}
        run: |
          python enhanced_deployment.py --auto-update --agent-name sbom-agent-prod
```

### AWS CodePipeline Example
```bash
# In your buildspec.yml
version: 0.2
phases:
  build:
    commands:
      - python enhanced_deployment.py --auto-update --agent-name $AGENT_NAME
```

## Troubleshooting Deployment Issues

### Common Errors and Solutions

#### "Agent already exists"
```bash
# Solution 1: Auto-update
python enhanced_deployment.py --auto-update

# Solution 2: Use different name
python enhanced_deployment.py --agent-name sbom-agent-$(date +%Y%m%d)

# Solution 3: Force recreate (destructive)
python enhanced_deployment.py --force-recreate
```

#### "OAuth provider already exists"
```bash
# The scripts handle this automatically
# If issues persist, check AWS console for existing providers
```

#### "ECR repository already exists"
```bash
# AgentCore Runtime handles this automatically
# If issues persist, check ECR console
```

#### "IAM role already exists"
```bash
# AgentCore Runtime handles this automatically
# If issues persist, check IAM console for conflicting roles
```

### Debugging Tips

1. **Check AWS Credentials**
   ```bash
   aws sts get-caller-identity
   ```

2. **Verify Region Configuration**
   ```bash
   echo $AWS_DEFAULT_REGION
   aws configure get region
   ```

3. **List Existing Agents**
   ```bash
   aws bedrock-agentcore list-agents
   ```

4. **Check AgentCore Permissions**
   ```bash
   aws bedrock-agentcore list-agents --dry-run
   ```

## Best Practices

### Development Workflow
1. Use `--auto-update` for iterative development
2. Test with different agent names for experiments
3. Use `enhanced_deployment.py` for full control

### Production Workflow
1. Use `production_deployment.py` for production deployments
2. Always test in staging first
3. Use `--auto-update` for safe updates
4. Keep deployment logs for troubleshooting

### Cleanup
```bash
# List all agents
python get_agent_info.py

# Delete specific agent (manual process via AWS console)
# Or use AWS CLI:
aws bedrock-agentcore delete-agent --agent-id YOUR_AGENT_ID
```

## Next Steps

After successful deployment:

1. **Test the deployment**: `python test_deployment.py`
2. **Find agent information**: `python get_agent_info.py`
3. **Set up monitoring**: Configure CloudWatch logs and metrics
4. **Configure CI/CD**: Automate deployments with your preferred platform
5. **Document your setup**: Keep track of agent names and configurations

For more information, see:
- `ENDPOINT_DISCOVERY.md` - Finding your agent endpoint
- `USER_GUIDE.md` - Using the deployed agent
- `README.md` - General project information