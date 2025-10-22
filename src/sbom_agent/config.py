"""Configuration settings for the SBOM Security Agent."""

import os
from typing import Dict, List


class Config:
    """Configuration settings for the SBOM Security Agent."""
    
    # GitHub OAuth2 Configuration
    GITHUB_PROVIDER_NAME = "github-provider"
    GITHUB_SCOPES = ["repo", "read:user", "read:org"]
    GITHUB_API_BASE_URL = "https://api.github.com"
    
    # Claude Model Configuration
    CLAUDE_MODEL = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
    
    # Vulnerability Database URLs
    OSV_API_URL = "https://api.osv.dev"
    GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json"
    
    # Supported Package Managers and their dependency files
    PACKAGE_MANAGER_FILES: Dict[str, List[str]] = {
        "npm": ["package.json", "package-lock.json", "yarn.lock"],
        "pip": ["requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml"],
        "maven": ["pom.xml"],
        "gradle": ["build.gradle", "build.gradle.kts"],
        "cargo": ["Cargo.toml", "Cargo.lock"],
        "go": ["go.mod", "go.sum"],
        "composer": ["composer.json", "composer.lock"],
        "nuget": ["*.csproj", "packages.config", "*.nuspec"]
    }
    
    # SBOM Configuration
    SBOM_FORMATS = ["SPDX", "CycloneDX"]
    SPDX_VERSION = "SPDX-2.3"
    CYCLONE_DX_VERSION = "1.4"
    
    # Rate Limiting
    GITHUB_API_RATE_LIMIT = 5000  # requests per hour
    VULNERABILITY_API_RATE_LIMIT = 1000  # requests per hour
    
    # Caching
    CACHE_TTL_SECONDS = 3600  # 1 hour
    MAX_CACHE_SIZE = 1000  # Maximum cached items
    
    # Analysis Configuration
    MAX_DEPENDENCY_DEPTH = 5  # Maximum depth for nested dependencies
    ANALYSIS_TIMEOUT_SECONDS = 300  # 5 minutes
    
    # Report Configuration
    MAX_REPORT_SIZE_MB = 50
    SUPPORTED_EXPORT_FORMATS = ["json", "pdf", "csv", "html"]
    
    # Environment Variables
    @classmethod
    def get_github_client_id(cls) -> str:
        """Get GitHub OAuth client ID from environment."""
        return os.getenv("GITHUB_CLIENT_ID", "")
    
    @classmethod
    def get_github_client_secret(cls) -> str:
        """Get GitHub OAuth client secret from environment."""
        return os.getenv("GITHUB_CLIENT_SECRET", "")
    
    @classmethod
    def get_nvd_api_key(cls) -> str:
        """Get NVD API key from environment."""
        return os.getenv("NVD_API_KEY", "")
    
    @classmethod
    def get_log_level(cls) -> str:
        """Get logging level from environment."""
        return os.getenv("LOG_LEVEL", "INFO")
    
    @classmethod
    def is_debug_mode(cls) -> bool:
        """Check if debug mode is enabled."""
        return os.getenv("DEBUG", "false").lower() == "true"


# System prompts for the agent
SYSTEM_PROMPTS = {
    "main": """You are a SBOM Security Analysis specialist. You help users analyze GitHub repositories 
    to generate Software Bill of Materials (SBOM) reports and perform security vulnerability analysis.

    Your capabilities include:
    - Authenticating with GitHub to access repositories
    - Analyzing repository dependencies across multiple package managers
    - Generating SBOM reports in SPDX and CycloneDX formats
    - Performing security vulnerability scanning
    - Creating comprehensive security reports with remediation recommendations

    Always provide clear, actionable information and guide users through the authentication process 
    when needed. Use the available tools to perform thorough analysis and present results in a 
    structured, easy-to-understand format.""",
    
    "authentication": """GitHub authentication is required to access repositories. I'll guide you 
    through the OAuth2 authentication process to securely access your repositories.""",
    
    "analysis": """Analyzing repository for dependencies and security vulnerabilities. This may 
    take a few moments depending on the repository size and number of dependencies.""",
    
    "error": """An error occurred during analysis. I'll provide details about what went wrong 
    and suggest next steps to resolve the issue."""
}