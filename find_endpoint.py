#!/usr/bin/env python3
"""
Quick script to find your SBOM Security Agent endpoint URL.

This is a simplified version that just outputs the endpoint URL
for use in scripts or quick lookups.
"""

import sys
import os

# Add the current directory to Python path to import get_agent_info
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from get_agent_info import find_agent_info, try_get_endpoint_from_deployment
except ImportError:
    print("❌ Could not import get_agent_info module", file=sys.stderr)
    sys.exit(1)


def main():
    """Find and display the agent endpoint URL."""
    
    # Try environment variables first
    endpoint = os.getenv('AGENT_ENDPOINT')
    if endpoint:
        print(f"Found in environment: {endpoint}")
        return
    
    # Try deployment files
    endpoint = try_get_endpoint_from_deployment()
    if endpoint:
        print(f"Found in deployment files: {endpoint}")
        return
    
    # Try AWS API
    print("Searching AWS for your agent...", file=sys.stderr)
    agent_info = find_agent_info("sbom-security-agent")
    
    if agent_info and agent_info.get('endpoint_url'):
        print(agent_info['endpoint_url'])
    else:
        print("❌ Could not find agent endpoint URL", file=sys.stderr)
        print("Try running: python get_agent_info.py", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()