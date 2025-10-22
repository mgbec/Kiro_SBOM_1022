"""Input validation and error handling utilities."""

import re
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse

from .exceptions import RepositoryAccessError, SBOMAgentError


class InputValidator:
    """Validates user inputs and parameters."""
    
    @staticmethod
    def validate_github_url(url: str) -> Dict[str, Any]:
        """
        Validate GitHub repository URL format.
        
        Args:
            url: Repository URL to validate
            
        Returns:
            Dict[str, Any]: Validation result with parsed components
        """
        result = {
            "valid": False,
            "url": url,
            "owner": None,
            "repo": None,
            "errors": []
        }
        
        if not url or not isinstance(url, str):
            result["errors"].append("Repository URL is required and must be a string")
            return result
        
        url = url.strip()
        
        # Check for GitHub domain
        if "github.com" not in url.lower():
            result["errors"].append("URL must be a GitHub repository (github.com)")
            return result
        
        # Parse URL patterns
        patterns = [
            r'https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$',
            r'git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$',
            r'github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                owner, repo = match.groups()
                
                # Clean up repo name
                repo = repo.replace('.git', '')
                
                # Validate owner and repo names
                if not InputValidator._is_valid_github_name(owner):
                    result["errors"].append(f"Invalid GitHub username/organization: {owner}")
                    return result
                
                if not InputValidator._is_valid_github_name(repo):
                    result["errors"].append(f"Invalid GitHub repository name: {repo}")
                    return result
                
                result.update({
                    "valid": True,
                    "owner": owner,
                    "repo": repo,
                    "normalized_url": f"https://github.com/{owner}/{repo}"
                })
                return result
        
        result["errors"].append("Invalid GitHub repository URL format")
        return result
    
    @staticmethod
    def _is_valid_github_name(name: str) -> bool:
        """Check if name is valid for GitHub username/repository."""
        if not name or len(name) > 39:
            return False
        
        # GitHub names can contain alphanumeric characters and hyphens
        # Cannot start or end with hyphen
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$'
        return bool(re.match(pattern, name))
    
    @staticmethod
    def validate_branch_name(branch: str) -> Dict[str, Any]:
        """
        Validate Git branch name.
        
        Args:
            branch: Branch name to validate
            
        Returns:
            Dict[str, Any]: Validation result
        """
        result = {
            "valid": False,
            "branch": branch,
            "errors": []
        }
        
        if not branch or not isinstance(branch, str):
            result["errors"].append("Branch name is required and must be a string")
            return result
        
        branch = branch.strip()
        
        if not branch:
            result["errors"].append("Branch name cannot be empty")
            return result
        
        # Git branch name restrictions
        invalid_patterns = [
            r'\.\.', r'@{', r'^\.', r'\.$', r'/$', r'^/', 
            r'\s', r'~', r'\^', r':', r'\?', r'\*', r'\[',
            r'\\', r'\x00-\x1f', r'\x7f'
        ]
        
        for pattern in invalid_patterns:
            if re.search(pattern, branch):
                result["errors"].append(f"Branch name contains invalid characters: {branch}")
                return result
        
        if len(branch) > 250:
            result["errors"].append("Branch name is too long (max 250 characters)")
            return result
        
        result["valid"] = True
        return result
    
    @staticmethod
    def validate_sbom_format(format_str: str) -> Dict[str, Any]:
        """
        Validate SBOM format parameter.
        
        Args:
            format_str: SBOM format string
            
        Returns:
            Dict[str, Any]: Validation result
        """
        result = {
            "valid": False,
            "format": format_str,
            "normalized_format": None,
            "errors": []
        }
        
        if not format_str or not isinstance(format_str, str):
            result["errors"].append("SBOM format is required and must be a string")
            return result
        
        format_str = format_str.strip().lower()
        valid_formats = ["spdx", "cyclonedx", "both"]
        
        if format_str not in valid_formats:
            result["errors"].append(f"Invalid SBOM format '{format_str}'. Supported: {', '.join(valid_formats)}")
            return result
        
        result.update({
            "valid": True,
            "normalized_format": format_str
        })
        return result
    
    @staticmethod
    def validate_export_format(format_str: str) -> Dict[str, Any]:
        """
        Validate export format parameter.
        
        Args:
            format_str: Export format string
            
        Returns:
            Dict[str, Any]: Validation result
        """
        result = {
            "valid": False,
            "format": format_str,
            "normalized_format": None,
            "errors": []
        }
        
        if not format_str or not isinstance(format_str, str):
            result["errors"].append("Export format is required and must be a string")
            return result
        
        format_str = format_str.strip().lower()
        valid_formats = ["json", "csv", "html", "pdf"]
        
        if format_str not in valid_formats:
            result["errors"].append(f"Invalid export format '{format_str}'. Supported: {', '.join(valid_formats)}")
            return result
        
        result.update({
            "valid": True,
            "normalized_format": format_str
        })
        return result
    
    @staticmethod
    def validate_report_type(report_type: str) -> Dict[str, Any]:
        """
        Validate report type parameter.
        
        Args:
            report_type: Report type string
            
        Returns:
            Dict[str, Any]: Validation result
        """
        result = {
            "valid": False,
            "report_type": report_type,
            "normalized_type": None,
            "errors": []
        }
        
        if not report_type or not isinstance(report_type, str):
            result["errors"].append("Report type is required and must be a string")
            return result
        
        report_type = report_type.strip().lower()
        valid_types = ["executive", "detailed", "both"]
        
        if report_type not in valid_types:
            result["errors"].append(f"Invalid report type '{report_type}'. Supported: {', '.join(valid_types)}")
            return result
        
        result.update({
            "valid": True,
            "normalized_type": report_type
        })
        return result


class ErrorHandler:
    """Centralized error handling and user-friendly error messages."""
    
    @staticmethod
    def handle_authentication_error(error: Exception, context: str = "") -> str:
        """
        Handle authentication-related errors.
        
        Args:
            error: The exception that occurred
            context: Additional context about where the error occurred
            
        Returns:
            str: User-friendly error message
        """
        base_msg = "GitHub authentication is required to access repositories."
        
        if "rate limit" in str(error).lower():
            return f"{base_msg} Additionally, GitHub API rate limit has been exceeded. Please try again later."
        elif "forbidden" in str(error).lower():
            return f"{base_msg} The current authentication doesn't have sufficient permissions. Please ensure your GitHub token has 'repo' access."
        elif "unauthorized" in str(error).lower():
            return f"{base_msg} The authentication token appears to be invalid or expired. Please re-authenticate."
        else:
            return f"{base_msg} {context} Error: {str(error)}"
    
    @staticmethod
    def handle_repository_access_error(error: Exception, repo_url: str) -> str:
        """
        Handle repository access errors.
        
        Args:
            error: The exception that occurred
            repo_url: Repository URL that failed
            
        Returns:
            str: User-friendly error message
        """
        if "not found" in str(error).lower() or "404" in str(error):
            return f"Repository not found: {repo_url}. Please check that the repository exists and you have access to it."
        elif "private" in str(error).lower() or "403" in str(error):
            return f"Access denied to repository: {repo_url}. This may be a private repository that requires authentication."
        elif "rate limit" in str(error).lower():
            return f"GitHub API rate limit exceeded while accessing {repo_url}. Please try again later."
        elif "timeout" in str(error).lower():
            return f"Timeout while accessing repository: {repo_url}. The repository may be large or GitHub may be experiencing issues."
        else:
            return f"Failed to access repository {repo_url}: {str(error)}"
    
    @staticmethod
    def handle_dependency_parsing_error(error: Exception, file_path: str) -> str:
        """
        Handle dependency file parsing errors.
        
        Args:
            error: The exception that occurred
            file_path: Path to the file that failed to parse
            
        Returns:
            str: User-friendly error message
        """
        if "json" in str(error).lower():
            return f"Invalid JSON format in {file_path}. Please check the file syntax."
        elif "yaml" in str(error).lower():
            return f"Invalid YAML format in {file_path}. Please check the file syntax."
        elif "xml" in str(error).lower():
            return f"Invalid XML format in {file_path}. Please check the file syntax."
        elif "toml" in str(error).lower():
            return f"Invalid TOML format in {file_path}. Please check the file syntax."
        else:
            return f"Failed to parse dependency file {file_path}: {str(error)}"
    
    @staticmethod
    def handle_vulnerability_database_error(error: Exception, database: str) -> str:
        """
        Handle vulnerability database query errors.
        
        Args:
            error: The exception that occurred
            database: Name of the vulnerability database
            
        Returns:
            str: User-friendly error message
        """
        if "rate limit" in str(error).lower():
            return f"{database} API rate limit exceeded. Vulnerability data may be incomplete. Please try again later."
        elif "timeout" in str(error).lower():
            return f"Timeout while querying {database}. Some vulnerability data may be missing."
        elif "network" in str(error).lower() or "connection" in str(error).lower():
            return f"Network error while accessing {database}. Please check your internet connection."
        else:
            return f"Error querying {database} vulnerability database: {str(error)}"
    
    @staticmethod
    def handle_sbom_generation_error(error: Exception, format_type: str) -> str:
        """
        Handle SBOM generation errors.
        
        Args:
            error: The exception that occurred
            format_type: SBOM format that failed
            
        Returns:
            str: User-friendly error message
        """
        if "memory" in str(error).lower():
            return f"Insufficient memory to generate {format_type} SBOM. The repository may have too many dependencies."
        elif "disk" in str(error).lower() or "space" in str(error).lower():
            return f"Insufficient disk space to generate {format_type} SBOM."
        else:
            return f"Failed to generate {format_type} SBOM: {str(error)}"
    
    @staticmethod
    def get_generic_error_message(error: Exception, operation: str) -> str:
        """
        Get a generic user-friendly error message.
        
        Args:
            error: The exception that occurred
            operation: Description of the operation that failed
            
        Returns:
            str: User-friendly error message
        """
        return f"An error occurred during {operation}: {str(error)}. Please try again or contact support if the issue persists."
    
    @staticmethod
    def format_validation_errors(validation_result: Dict[str, Any]) -> str:
        """
        Format validation errors into user-friendly message.
        
        Args:
            validation_result: Result from validation function
            
        Returns:
            str: Formatted error message
        """
        if validation_result.get("valid", False):
            return ""
        
        errors = validation_result.get("errors", ["Unknown validation error"])
        
        if len(errors) == 1:
            return f"Validation error: {errors[0]}"
        else:
            error_list = "\n".join(f"• {error}" for error in errors)
            return f"Validation errors:\n{error_list}"