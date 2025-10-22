# SBOM Security Agent

A comprehensive security analysis agent that generates Software Bill of Materials (SBOM) reports and performs vulnerability scanning for GitHub repositories.

## Features

- **GitHub Integration**: Secure OAuth2 authentication to access public and private repositories
- **Multi-Language Support**: Analyzes dependencies across multiple package managers (npm, pip, Maven, Gradle, Cargo, Go, Composer, NuGet)
- **SBOM Generation**: Creates industry-standard SBOM reports in SPDX and CycloneDX formats
- **Vulnerability Scanning**: Identifies security vulnerabilities using multiple databases (OSV, GitHub Security Advisories, NVD)
- **Comprehensive Reporting**: Generates executive summaries and detailed security reports
- **AgentCore Integration**: Built on Amazon Bedrock AgentCore with Strands agents and Claude models

## Architecture

The agent is built using the AgentCore framework and follows established patterns for:
- Authentication via AgentCore Identity
- Runtime management via AgentCore Runtime
- Streaming responses for real-time progress updates
- Tool-based architecture for modular functionality

## Prerequisites

- Python 3.10+
- AWS credentials configured
- Amazon Bedrock AgentCore SDK
- Docker (for deployment)
- GitHub OAuth application (for repository access)

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

1. Set up GitHub OAuth2 application
2. Configure environment variables:
   ```bash
   export GITHUB_CLIENT_ID="your-client-id"
   export GITHUB_CLIENT_SECRET="your-client-secret"
   export NVD_API_KEY="your-nvd-api-key"  # Optional
   ```

## Usage

The agent provides conversational interface for:
- Repository analysis requests
- SBOM report generation
- Security vulnerability scanning
- Compliance reporting

## Supported Package Managers

- **npm** (Node.js): package.json, package-lock.json, yarn.lock
- **pip** (Python): requirements.txt, Pipfile, pyproject.toml
- **Maven** (Java): pom.xml
- **Gradle** (Java/Kotlin): build.gradle, build.gradle.kts
- **Cargo** (Rust): Cargo.toml, Cargo.lock
- **Go Modules**: go.mod, go.sum
- **Composer** (PHP): composer.json, composer.lock
- **NuGet** (.NET): *.csproj, packages.config

## SBOM Formats

- **SPDX 2.3**: Industry standard format for software bill of materials
- **CycloneDX 1.4**: Modern format optimized for security use cases

## Security Features

- Vulnerability detection from multiple sources
- Severity assessment and risk scoring
- Remediation recommendations
- Compliance mapping for security standards
- Executive reporting for risk management

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Code formatting
black src/
isort src/

# Type checking
mypy src/
```

## License

MIT License - see LICENSE file for details.