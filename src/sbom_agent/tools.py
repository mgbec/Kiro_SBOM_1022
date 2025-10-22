"""Agent tools for SBOM security analysis."""

import json
from typing import Dict, Any, Optional

from strands import tool

from .auth import auth_manager, authenticate_github, needs_authentication
from .dependency_analyzer import DependencyAnalyzer
from .sbom_generator import SBOMGenerator
from .vulnerability import VulnerabilityScanner
from .reporting import ExecutiveSummaryGenerator, SecurityReportGenerator, ExportManager
from .models import SBOMFormat
from .streaming import StreamingQueue
from .validation import InputValidator, ErrorHandler
from .exceptions import (
    SBOMAgentError, AuthenticationError, RepositoryAccessError, 
    SBOMGenerationError, VulnerabilityDatabaseError
)


# Global instances
dependency_analyzer = DependencyAnalyzer()
sbom_generator = SBOMGenerator()
vulnerability_scanner = VulnerabilityScanner()
executive_summary_generator = ExecutiveSummaryGenerator()
security_report_generator = SecurityReportGenerator()
export_manager = ExportManager()


@tool
def analyze_repository(repository_url: str, branch: str = "main") -> str:
    """
    Analyze a GitHub repository for dependencies and generate SBOM with security analysis.
    
    Args:
        repository_url: GitHub repository URL to analyze
        branch: Git branch to analyze (default: main)
        
    Returns:
        str: Analysis results with dependencies, SBOM, and security findings
    """
    try:
        # Validate repository URL
        url_validation = InputValidator.validate_github_url(repository_url)
        if not url_validation["valid"]:
            return json.dumps({
                "error": True,
                "message": ErrorHandler.format_validation_errors(url_validation),
                "repository_url": repository_url
            })
        
        # Validate branch name
        branch_validation = InputValidator.validate_branch_name(branch)
        if not branch_validation["valid"]:
            return json.dumps({
                "error": True,
                "message": ErrorHandler.format_validation_errors(branch_validation),
                "branch": branch
            })
        
        # Use normalized URL
        normalized_url = url_validation["normalized_url"]
        
        # Check authentication
        if not auth_manager.is_authenticated():
            return json.dumps({
                "auth_required": True,
                "message": "GitHub authentication is required to access repositories. Please wait while we set up the authorization.",
                "repository_url": normalized_url,
                "branch": branch
            })
        
        # This will be handled by the async agent task
        return json.dumps({
            "status": "starting_analysis",
            "message": f"Starting comprehensive analysis of {normalized_url} (branch: {branch})",
            "repository_url": normalized_url,
            "branch": branch,
            "steps": [
                "Analyzing repository dependencies",
                "Generating SBOM reports",
                "Scanning for security vulnerabilities",
                "Creating security analysis report"
            ]
        })
        
    except Exception as e:
        return json.dumps({
            "error": True,
            "message": ErrorHandler.get_generic_error_message(e, "repository analysis setup"),
            "repository_url": repository_url
        })


@tool
def generate_sbom_report(repository_url: str, format: str = "both", branch: str = "main") -> str:
    """
    Generate SBOM (Software Bill of Materials) report for a repository.
    
    Args:
        repository_url: GitHub repository URL
        format: SBOM format - "spdx", "cyclonedx", or "both" (default: both)
        branch: Git branch to analyze (default: main)
        
    Returns:
        str: SBOM generation results
    """
    try:
        # Validate repository URL
        url_validation = InputValidator.validate_github_url(repository_url)
        if not url_validation["valid"]:
            return json.dumps({
                "error": True,
                "message": ErrorHandler.format_validation_errors(url_validation),
                "repository_url": repository_url
            })
        
        # Validate branch name
        branch_validation = InputValidator.validate_branch_name(branch)
        if not branch_validation["valid"]:
            return json.dumps({
                "error": True,
                "message": ErrorHandler.format_validation_errors(branch_validation),
                "branch": branch
            })
        
        # Validate SBOM format
        format_validation = InputValidator.validate_sbom_format(format)
        if not format_validation["valid"]:
            return json.dumps({
                "error": True,
                "message": ErrorHandler.format_validation_errors(format_validation),
                "format": format
            })
        
        normalized_url = url_validation["normalized_url"]
        normalized_format = format_validation["normalized_format"]
        
        # Check authentication
        if not auth_manager.is_authenticated():
            return json.dumps({
                "auth_required": True,
                "message": "GitHub authentication is required to access repositories for SBOM generation.",
                "repository_url": normalized_url,
                "format": normalized_format,
                "branch": branch
            })
        
        return json.dumps({
            "status": "starting_sbom_generation",
            "message": f"Generating {normalized_format.upper()} SBOM for {normalized_url}",
            "repository_url": normalized_url,
            "format": normalized_format,
            "branch": branch
        })
        
    except Exception as e:
        return json.dumps({
            "error": True,
            "message": ErrorHandler.get_generic_error_message(e, "SBOM generation setup"),
            "repository_url": repository_url
        })


@tool
def scan_vulnerabilities(repository_url: str, branch: str = "main") -> str:
    """
    Scan repository dependencies for security vulnerabilities.
    
    Args:
        repository_url: GitHub repository URL to scan
        branch: Git branch to scan (default: main)
        
    Returns:
        str: Vulnerability scan results
    """
    try:
        # Check authentication
        if not auth_manager.is_authenticated():
            return json.dumps({
                "auth_required": True,
                "message": "GitHub authentication is required to access repositories for vulnerability scanning.",
                "repository_url": repository_url,
                "branch": branch
            })
        
        return json.dumps({
            "status": "starting_vulnerability_scan",
            "message": f"Scanning {repository_url} for security vulnerabilities",
            "repository_url": repository_url,
            "branch": branch,
            "scan_sources": ["OSV Database", "GitHub Security Advisories"]
        })
        
    except Exception as e:
        return json.dumps({
            "error": True,
            "message": f"Failed to start vulnerability scan: {str(e)}",
            "repository_url": repository_url
        })


@tool
def generate_security_report(repository_url: str, report_type: str = "detailed", branch: str = "main") -> str:
    """
    Generate comprehensive security analysis report.
    
    Args:
        repository_url: GitHub repository URL
        report_type: Type of report - "executive", "detailed", or "both" (default: detailed)
        branch: Git branch to analyze (default: main)
        
    Returns:
        str: Security report generation results
    """
    try:
        # Check authentication
        if not auth_manager.is_authenticated():
            return json.dumps({
                "auth_required": True,
                "message": "GitHub authentication is required to generate security reports.",
                "repository_url": repository_url,
                "report_type": report_type,
                "branch": branch
            })
        
        # Validate report type
        valid_types = ["executive", "detailed", "both"]
        if report_type.lower() not in valid_types:
            return json.dumps({
                "error": True,
                "message": f"Invalid report type '{report_type}'. Supported types: {', '.join(valid_types)}",
                "repository_url": repository_url
            })
        
        return json.dumps({
            "status": "starting_security_report",
            "message": f"Generating {report_type} security report for {repository_url}",
            "repository_url": repository_url,
            "report_type": report_type,
            "branch": branch
        })
        
    except Exception as e:
        return json.dumps({
            "error": True,
            "message": f"Failed to start security report generation: {str(e)}",
            "repository_url": repository_url
        })


@tool
def export_report(report_data: str, format: str = "json", report_type: str = "security_analysis") -> str:
    """
    Export analysis results in various formats.
    
    Args:
        report_data: JSON string containing report data to export
        format: Export format - "json", "csv", "html", "pdf" (default: json)
        report_type: Type of report being exported (default: security_analysis)
        
    Returns:
        str: Export results with download information
    """
    try:
        # Validate export format
        format_validation = InputValidator.validate_export_format(format)
        if not format_validation["valid"]:
            return json.dumps({
                "error": True,
                "message": ErrorHandler.format_validation_errors(format_validation)
            })
        
        normalized_format = format_validation["normalized_format"]
        
        # Validate report data
        if not report_data or not isinstance(report_data, str):
            return json.dumps({
                "error": True,
                "message": "Report data is required and must be a JSON string"
            })
        
        # Parse report data
        try:
            data = json.loads(report_data)
        except json.JSONDecodeError as e:
            return json.dumps({
                "error": True,
                "message": f"Invalid JSON format in report data: {str(e)}"
            })
        
        # Validate report type
        valid_report_types = ["security_analysis", "executive_summary", "sbom", "vulnerability_report"]
        if report_type not in valid_report_types:
            return json.dumps({
                "warning": True,
                "message": f"Unknown report type '{report_type}'. Proceeding with export anyway.",
                "valid_types": valid_report_types
            })
        
        return json.dumps({
            "status": "starting_export",
            "message": f"Exporting {report_type} report as {normalized_format.upper()}",
            "format": normalized_format,
            "report_type": report_type,
            "data_size": len(report_data)
        })
        
    except Exception as e:
        return json.dumps({
            "error": True,
            "message": ErrorHandler.get_generic_error_message(e, "report export setup")
        })


@tool
def get_supported_package_managers() -> str:
    """
    Get list of supported package managers for dependency analysis.
    
    Returns:
        str: JSON list of supported package managers and their file types
    """
    try:
        supported_managers = dependency_analyzer.get_supported_package_managers()
        
        manager_info = {
            "npm": {"files": ["package.json", "package-lock.json", "yarn.lock"], "language": "JavaScript/Node.js"},
            "pip": {"files": ["requirements.txt", "Pipfile", "pyproject.toml"], "language": "Python"},
            "maven": {"files": ["pom.xml"], "language": "Java"},
            "gradle": {"files": ["build.gradle", "build.gradle.kts"], "language": "Java/Kotlin"},
            "cargo": {"files": ["Cargo.toml", "Cargo.lock"], "language": "Rust"},
            "go": {"files": ["go.mod", "go.sum"], "language": "Go"},
            "composer": {"files": ["composer.json", "composer.lock"], "language": "PHP"},
            "nuget": {"files": ["*.csproj", "packages.config"], "language": ".NET"}
        }
        
        result = {
            "supported_package_managers": supported_managers,
            "details": {manager: manager_info.get(manager, {}) for manager in supported_managers},
            "total_supported": len(supported_managers)
        }
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        return json.dumps({
            "error": True,
            "message": f"Failed to get supported package managers: {str(e)}"
        })


@tool
def get_agent_capabilities() -> str:
    """
    Get information about the SBOM Security Agent capabilities and features.
    
    Returns:
        str: JSON description of agent capabilities
    """
    capabilities = {
        "agent_name": "SBOM Security Agent",
        "version": "0.1.0",
        "description": "Comprehensive security analysis agent for GitHub repositories",
        "capabilities": {
            "repository_analysis": {
                "description": "Analyze GitHub repositories for dependencies across multiple package managers",
                "supported_package_managers": dependency_analyzer.get_supported_package_managers(),
                "authentication": "GitHub OAuth2 with repository access"
            },
            "sbom_generation": {
                "description": "Generate Software Bill of Materials in industry-standard formats",
                "supported_formats": sbom_generator.get_supported_formats(),
                "standards_compliance": ["SPDX 2.3", "CycloneDX 1.4"]
            },
            "vulnerability_scanning": {
                "description": "Scan dependencies for known security vulnerabilities",
                "data_sources": ["OSV Database", "GitHub Security Advisories", "NVD (planned)"],
                "severity_levels": ["Critical", "High", "Medium", "Low"]
            },
            "reporting": {
                "description": "Generate comprehensive security reports and executive summaries",
                "report_types": ["Executive Summary", "Detailed Security Analysis", "Compliance Assessment"],
                "export_formats": export_manager.get_supported_formats()
            }
        },
        "use_cases": [
            "Software supply chain security assessment",
            "Compliance reporting for security standards",
            "Vulnerability management and remediation planning",
            "Open source license compliance",
            "DevSecOps integration and automation"
        ],
        "integration": {
            "framework": "Amazon Bedrock AgentCore",
            "model": "Claude 3.7 Sonnet",
            "authentication": "GitHub OAuth2",
            "deployment": "AgentCore Runtime"
        }
    }
    
    return json.dumps(capabilities, indent=2)