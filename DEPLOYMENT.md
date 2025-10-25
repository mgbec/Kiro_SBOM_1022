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

1. clone repo and switch to created folder

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
2. Get your agent endpoint URL from the deployment output
3. Test with a sample repository using one of these methods:

### Option A: Using curl (Command Line)
```bash
curl -X POST "https://your-agent-endpoint.amazonaws.com/invocations" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "prompt": "Analyze the repository https://github.com/microsoft/vscode for security vulnerabilities"
  }'
```

### Option B: Using Python script
Create a test file `test_agent.py`:
```python
import requests
import json

# Replace with your actual agent endpoint and JWT token
AGENT_ENDPOINT = "https://your-agent-endpoint.amazonaws.com/invocations"
JWT_TOKEN = "your-jwt-token-here"

payload = {
    "prompt": "Analyze the repository https://github.com/microsoft/vscode for security vulnerabilities"
}

headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {JWT_TOKEN}"
}

response = requests.post(AGENT_ENDPOINT, json=payload, headers=headers)
print("Status Code:", response.status_code)
print("Response:", response.text)
```

Then run:
```bash
python test_agent.py
```

### Option C: Using the Test Script (Recommended)
Use the provided test script for easy testing:
```bash
python test_deployment.py
```

The script will:
- Prompt you for your agent endpoint and Cognito client ID
- Automatically get a fresh JWT token
- Send a test request to your agent
- Display the results in a readable format

### Option D: Using the Web Interface (if deployed)
If you've deployed the web application from `web_app_example.py`:
1. Open your web application URL in a browser
2. Enter the repository URL: `https://github.com/microsoft/vscode`
3. Click "Analyze Repository"
4. Follow the authentication flow if prompted

### Expected Response
The agent should respond with a streaming analysis that includes:
- Authentication flow (if not already authenticated)
- Repository dependency analysis
- SBOM generation
- Vulnerability scanning
- Security report generation

### Getting Your Agent Endpoint and JWT Token
After successful deployment, you'll need:
1. **Agent Endpoint**: Found in the deployment output or AgentCore console
2. **JWT Token**: Use the bearer token from the Cognito setup output, or generate a new one:

```bash
# If you need to get a new JWT token
python -c "
from utils import reauthenticate_user
token = reauthenticate_user('YOUR_COGNITO_CLIENT_ID')
print('JWT Token:', token)
"
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

**Testing Issues:**
- **"Prompt::command not found"**: This means you're trying to run the JSON payload as a shell command. Use one of the testing methods in Step 5 instead.
- **"Agent endpoint not found"**: Check the deployment output for the correct endpoint URL
- **"401 Unauthorized"**: Your JWT token may be expired. Generate a new one using the utils.py script
- **"403 Forbidden"**: Check that your JWT token has the correct permissions

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
