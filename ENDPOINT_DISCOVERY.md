# Agent Endpoint Discovery Guide

This guide explains how to find your deployed SBOM Security Agent endpoint URL using the provided utilities.

## Quick Start

### Option 1: Interactive Helper (Recommended)
```bash
python get_agent_info.py
```
This will guide you through finding your agent information and optionally save it to `.env` file.

### Option 2: Quick Endpoint Lookup
```bash
python find_endpoint.py
```
This outputs just the endpoint URL for scripts or quick reference.

### Option 3: Command Line Options
```bash
# Auto-detect and save to .env file
python get_agent_info.py --save-env

# Just show the endpoint URL
python get_agent_info.py --endpoint-only

# Find a specific agent by name
python get_agent_info.py --agent-name my-custom-agent
```

## What These Tools Do

### `get_agent_info.py` - Comprehensive Agent Discovery
- **Auto-detects** your agent using AWS APIs
- **Finds Cognito** User Pool information
- **Validates** endpoint URLs
- **Saves configuration** to `.env` file
- **Interactive guidance** for manual entry
- **Command line options** for automation

### `find_endpoint.py` - Quick Endpoint Lookup
- **Fast endpoint discovery** for scripts
- **Checks environment variables** first
- **Falls back to AWS API** if needed
- **Minimal output** for automation

## How Agent Discovery Works

The tools search for your agent in this order:

1. **Environment Variables**
   - `AGENT_ENDPOINT`
   - `AGENTCORE_ENDPOINT`
   - `BEDROCK_AGENT_ENDPOINT`
   - `AGENT_URL`
   - `INVOKE_URL`
   - `ENDPOINT_URL`

2. **Deployment Files**
   - `.bedrock_agentcore.yaml`
   - Other configuration files

3. **AWS API Query**
   - Lists all agents in your account
   - Finds agents matching "sbom-security-agent"
   - Constructs endpoint URL from agent ID

## Expected Endpoint URL Format

Your agent endpoint should look like:
```
https://[agent-id].bedrock-agentcore.[region].amazonaws.com/invocations
```

Examples:
- `https://abcd1234.bedrock-agentcore.us-east-1.amazonaws.com/invocations`
- `https://xyz789.bedrock-agentcore.eu-west-1.amazonaws.com/invocations`

## Finding Your Endpoint Manually

### From Deployment Output
When you ran `python deployment_config.py`, look for:
```
Deployment result: {
  "endpoint": "https://abcd1234.bedrock-agentcore.us-east-1.amazonaws.com/invocations",
  ...
}
```

### From AWS Console
1. Go to **AWS Console** > **Bedrock** > **AgentCore**
2. Find your agent: **sbom-security-agent**
3. Copy the endpoint URL from agent details

### From AWS CLI
```bash
aws bedrock-agentcore list-agents
aws bedrock-agentcore get-agent --agent-id YOUR_AGENT_ID
```

## Saving Configuration

The tools can save your agent information to `.env` file:

```bash
# Auto-save after discovery
python get_agent_info.py --save-env
```

This creates/updates `.env` with:
```env
AGENT_ENDPOINT=https://abcd1234.bedrock-agentcore.us-east-1.amazonaws.com/invocations
AGENT_ID=abcd1234
AGENT_NAME=sbom-security-agent
AWS_REGION=us-east-1
COGNITO_CLIENT_ID=your-client-id
COGNITO_POOL_ID=your-pool-id
COGNITO_DISCOVERY_URL=https://cognito-idp.us-east-1.amazonaws.com/your-pool-id/.well-known/openid-configuration
```

## Using in Scripts

### Get Endpoint URL Only
```bash
# Get just the URL
ENDPOINT=$(python find_endpoint.py)
echo "Agent endpoint: $ENDPOINT"

# Or with error handling
if ENDPOINT=$(python get_agent_info.py --endpoint-only --quiet); then
    echo "Found endpoint: $ENDPOINT"
else
    echo "Could not find endpoint"
    exit 1
fi
```

### Load from Environment
```bash
# Source the .env file
source .env
echo "Using endpoint: $AGENT_ENDPOINT"
```

## Troubleshooting

### "No agents found"
- Check that your agent was deployed successfully
- Verify you're using the correct AWS region
- Ensure your AWS credentials have AgentCore permissions

### "Authentication failed"
- Check your AWS credentials: `aws sts get-caller-identity`
- Verify you have the required permissions
- Try: `aws bedrock-agentcore list-agents`

### "Invalid URL format"
- The tools will try to fix common URL format issues
- Ensure your URL includes the protocol (https://)
- Check that it ends with `/invocations`

### "Connection error"
- Verify the endpoint URL is correct
- Check your internet connection
- Ensure the agent is deployed and running

## Integration with Testing

After finding your endpoint, you can test it:

```bash
# Save configuration first
python get_agent_info.py --save-env

# Then test the deployment
python test_deployment.py
```

The test script will automatically use the saved configuration.

## Command Reference

### get_agent_info.py
```bash
python get_agent_info.py [OPTIONS]

Options:
  --agent-name NAME     Name of agent to find (default: sbom-security-agent)
  --save-env           Save found information to .env file
  --endpoint-only      Only output the endpoint URL
  --quiet, -q          Minimal output for scripts
  --help               Show help message
```

### find_endpoint.py
```bash
python find_endpoint.py

# No options - just outputs the endpoint URL or exits with error
```

## Next Steps

Once you have your endpoint URL:

1. **Test your deployment**: `python test_deployment.py`
2. **Use in applications**: Load from `.env` or use directly
3. **Integrate with CI/CD**: Use `--endpoint-only` for automation
4. **Monitor your agent**: Check AWS CloudWatch logs

For more information, see:
- `DEPLOYMENT.md` - Deployment guide
- `USER_GUIDE.md` - Usage instructions
- `test_deployment.py` - Testing your agent