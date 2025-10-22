# SBOM Security Agent Deployment Guide

This guide walks you through deploying the SBOM Security Agent to Amazon Bedrock AgentCore Runtime.

## Prerequisites

### Required Software
- Python 3.10+
- AWS CLI configured with appropriate permissions
- Docker (for containerization)
- Git

### Required AWS Permissions
Your AWS credentials need the following permissions:
- Amazon Bedrock AgentCore access
- Amazon ECR repository creation and management
- IAM role creation for agent execution
- Amazon Cognito User Pool management (for authentication)

### Required External Services
- GitHub OAuth Application (for repository access)
- Optional: NVD API key (for enhanced vulnerability data)

## Step 1: GitHub OAuth Setup

1. Go to GitHub Settings > Developer settings > OAuth Apps
2. Click "New OAuth App"
3. Fill in the application details:
   - **Application Name**: SBOM Security Agent
   - **Homepage URL**: `https://bedrock-agentcore.us-east-1.amazonaws.com/identities/oauth2/callback`
   - **Authorization callback URL**: `https://bedrock-agentcore.us-east-1.amazonaws.com/identities/oauth2/callback`
4. Click "Register application"
5. Note down the **Client ID** and generate a **Client Secret**

## Step 2: Environment Configuration

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and set your GitHub OAuth credentials:
   ```bash
   GITHUB_CLIENT_ID=your-github-client-id
   GITHUB_CLIENT_SECRET=your-github-client-secret
   ```

3. Set environment variables:
   ```bash
   export $(cat .env | xargs)
   ```

## Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

## Step 4: Deploy to AgentCore Runtime

### Automated Deployment

Run the deployment script:
```bash
python deployment_config.py
```

This script will:
1. Create the GitHub OAuth2 credential provider
2. Configure AgentCore Runtime with proper settings
3. Deploy the agent container

### Manual Deployment

If you prefer manual deployment:

1. **Configure AgentCore Runtime:**
   ```python
   from bedrock_agentcore_starter_toolkit import Runtime
   
   agentcore_runtime = Runtime()
   response = agentcore_runtime.configure(
       entrypoint="sbom_agent.py",
       auto_create_execution_role=True,
       auto_create_ecr=True,
       requirements_file="requirements.txt",
       region="us-east-1",  # Your AWS region
       agent_name="sbom-security-agent"
   )
   ```

2. **Launch the agent:**
   ```python
   launch_result = agentcore_runtime.launch()
   ```

## Step 5: Verify Deployment

1. Check the AgentCore console for your deployed agent
2. Test with a sample repository:
   ```json
   {
     "prompt": "Analyze the repository https://github.com/example/repo for security vulnerabilities"
   }
   ```

## Configuration Options

### Authentication
The agent supports GitHub OAuth2 authentication with the following scopes:
- `repo` - Access to repositories
- `read:user` - Read user profile information
- `read:org` - Read organization information

### Supported Package Managers
- **npm** (Node.js): package.json, package-lock.json, yarn.lock
- **pip** (Python): requirements.txt, Pipfile, pyproject.toml
- **Maven** (Java): pom.xml
- **Gradle** (Java/Kotlin): build.gradle, build.gradle.kts
- **Cargo** (Rust): Cargo.toml, Cargo.lock
- **Go Modules**: go.mod, go.sum
- **Composer** (PHP): composer.json, composer.lock
- **NuGet** (.NET): *.csproj, packages.config

### SBOM Formats
- **SPDX 2.3** - Industry standard format
- **CycloneDX 1.4** - Modern security-focused format

### Vulnerability Databases
- **OSV Database** - Open Source Vulnerabilities
- **GitHub Security Advisories** - GitHub-specific security data
- **NVD** - National Vulnerability Database (with API key)

## Monitoring and Logging

### CloudWatch Logs
Agent logs are automatically sent to CloudWatch Logs. Monitor:
- `/aws/lambda/sbom-security-agent` - Agent execution logs
- Authentication events
- API rate limiting events
- Error conditions

### Metrics
Key metrics to monitor:
- Request count and latency
- Authentication success/failure rates
- Vulnerability scan completion rates
- SBOM generation success rates

## Security Considerations

### Secrets Management
- GitHub OAuth credentials are stored securely in AgentCore
- Never commit secrets to version control
- Use environment variables for configuration

### Network Security
- Agent runs in AWS managed environment
- All external API calls use HTTPS
- Rate limiting prevents abuse

### Data Privacy
- Repository data is processed in memory only
- No persistent storage of repository contents
- Vulnerability data is cached temporarily

## Troubleshooting

### Common Issues

**Authentication Failures:**
- Verify GitHub OAuth credentials are correct
- Check that callback URL matches exactly
- Ensure required scopes are granted

**Rate Limiting:**
- GitHub API: 5000 requests/hour (authenticated)
- OSV API: Implement backoff strategies
- Consider caching for frequently analyzed repositories

**Memory Issues:**
- Large repositories may require increased memory allocation
- Consider implementing streaming for very large dependency lists

**Network Timeouts:**
- Increase timeout values for large repositories
- Implement retry logic with exponential backoff

### Support

For deployment issues:
1. Check CloudWatch logs for detailed error messages
2. Verify AWS permissions and region configuration
3. Test GitHub OAuth flow independently
4. Contact AWS support for AgentCore-specific issues

## Updates and Maintenance

### Updating the Agent
1. Update the source code
2. Run the deployment script again
3. AgentCore will handle container updates automatically

### Dependency Updates
- Regularly update Python dependencies
- Monitor for security updates in base images
- Test thoroughly before deploying updates

### Monitoring
- Set up CloudWatch alarms for error rates
- Monitor API usage and costs
- Review security scan results regularly