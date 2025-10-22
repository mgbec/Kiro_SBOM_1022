"""GitHub API client for repository access and analysis."""

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from .auth import get_auth_headers, auth_manager
from .config import Config
from .exceptions import RepositoryAccessError, AuthenticationError, NetworkError, RateLimitError


class GitHubClient:
    """Client for interacting with GitHub API."""
    
    def __init__(self):
        self.base_url = Config.GITHUB_API_BASE_URL
        self.timeout = 30.0
    
    def _parse_repository_url(self, repo_url: str) -> Tuple[str, str]:
        """
        Parse GitHub repository URL to extract owner and repo name.
        
        Args:
            repo_url: GitHub repository URL
            
        Returns:
            Tuple of (owner, repo_name)
            
        Raises:
            RepositoryAccessError: If URL format is invalid
        """
        # Handle various GitHub URL formats
        patterns = [
            r'github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?/?$',
            r'github\.com/([^/]+)/([^/]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, repo_url)
            if match:
                owner, repo = match.groups()
                # Remove .git suffix if present
                repo = repo.replace('.git', '')
                return owner, repo
        
        raise RepositoryAccessError(f"Invalid GitHub repository URL format: {repo_url}")
    
    async def _make_request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """
        Make authenticated HTTP request to GitHub API.
        
        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Additional request parameters
            
        Returns:
            httpx.Response: API response
            
        Raises:
            AuthenticationError: If authentication fails
            RateLimitError: If rate limit is exceeded
            NetworkError: If network request fails
        """
        try:
            headers = get_auth_headers()
            headers.update(kwargs.pop('headers', {}))
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    **kwargs
                )
                
                # Handle rate limiting
                if response.status_code == 403:
                    if 'rate limit' in response.text.lower():
                        raise RateLimitError("GitHub API rate limit exceeded")
                    else:
                        raise AuthenticationError("GitHub API access forbidden")
                
                # Handle authentication errors
                if response.status_code == 401:
                    raise AuthenticationError("GitHub authentication failed or expired")
                
                # Handle not found
                if response.status_code == 404:
                    raise RepositoryAccessError("Repository not found or access denied")
                
                response.raise_for_status()
                return response
                
        except httpx.TimeoutException as e:
            raise NetworkError(f"Request timeout: {str(e)}") from e
        except httpx.RequestError as e:
            raise NetworkError(f"Network error: {str(e)}") from e
    
    async def get_repository_info(self, repo_url: str) -> Dict:
        """
        Get basic repository information.
        
        Args:
            repo_url: GitHub repository URL
            
        Returns:
            Dict: Repository information
        """
        owner, repo = self._parse_repository_url(repo_url)
        url = f"{self.base_url}/repos/{owner}/{repo}"
        
        response = await self._make_request("GET", url)
        return response.json()
    
    async def get_repository_contents(self, repo_url: str, path: str = "", ref: str = "main") -> List[Dict]:
        """
        Get repository contents at specified path.
        
        Args:
            repo_url: GitHub repository URL
            path: Path within repository (empty for root)
            ref: Git reference (branch, tag, or commit)
            
        Returns:
            List[Dict]: List of files and directories
        """
        owner, repo = self._parse_repository_url(repo_url)
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"
        
        params = {"ref": ref} if ref != "main" else {}
        
        try:
            response = await self._make_request("GET", url, params=params)
            return response.json()
        except RepositoryAccessError as e:
            # Try with default branch if main doesn't exist
            if ref == "main":
                try:
                    repo_info = await self.get_repository_info(repo_url)
                    default_branch = repo_info.get("default_branch", "master")
                    return await self.get_repository_contents(repo_url, path, default_branch)
                except Exception:
                    raise e
            raise
    
    async def get_file_content(self, repo_url: str, file_path: str, ref: str = "main") -> str:
        """
        Get content of a specific file.
        
        Args:
            repo_url: GitHub repository URL
            file_path: Path to the file
            ref: Git reference
            
        Returns:
            str: File content
        """
        owner, repo = self._parse_repository_url(repo_url)
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{file_path}"
        
        params = {"ref": ref} if ref != "main" else {}
        
        try:
            response = await self._make_request("GET", url, params=params)
            file_data = response.json()
            
            if file_data.get("type") != "file":
                raise RepositoryAccessError(f"Path {file_path} is not a file")
            
            # Decode base64 content
            import base64
            content = base64.b64decode(file_data["content"]).decode("utf-8")
            return content
            
        except RepositoryAccessError as e:
            # Try with default branch if main doesn't exist
            if ref == "main":
                try:
                    repo_info = await self.get_repository_info(repo_url)
                    default_branch = repo_info.get("default_branch", "master")
                    return await self.get_file_content(repo_url, file_path, default_branch)
                except Exception:
                    raise e
            raise
    
    async def find_dependency_files(self, repo_url: str, ref: str = "main") -> Dict[str, List[str]]:
        """
        Find all dependency files in the repository.
        
        Args:
            repo_url: GitHub repository URL
            ref: Git reference
            
        Returns:
            Dict[str, List[str]]: Package manager to file paths mapping
        """
        dependency_files = {}
        
        async def search_directory(path: str = "") -> None:
            """Recursively search for dependency files."""
            try:
                contents = await self.get_repository_contents(repo_url, path, ref)
                
                for item in contents:
                    if item["type"] == "file":
                        file_name = item["name"]
                        file_path = item["path"]
                        
                        # Check against known dependency files
                        for pkg_manager, patterns in Config.PACKAGE_MANAGER_FILES.items():
                            for pattern in patterns:
                                if self._matches_pattern(file_name, pattern):
                                    if pkg_manager not in dependency_files:
                                        dependency_files[pkg_manager] = []
                                    dependency_files[pkg_manager].append(file_path)
                    
                    elif item["type"] == "dir":
                        # Skip common directories that don't contain dependency files
                        skip_dirs = {".git", "node_modules", "__pycache__", ".pytest_cache", 
                                   "target", "build", "dist", ".venv", "venv"}
                        if item["name"] not in skip_dirs:
                            await search_directory(item["path"])
                            
            except Exception as e:
                print(f"Error searching directory {path}: {e}")
        
        await search_directory()
        return dependency_files
    
    def _matches_pattern(self, filename: str, pattern: str) -> bool:
        """
        Check if filename matches a dependency file pattern.
        
        Args:
            filename: Name of the file
            pattern: Pattern to match against
            
        Returns:
            bool: True if filename matches pattern
        """
        if "*" in pattern:
            # Handle wildcard patterns
            import fnmatch
            return fnmatch.fnmatch(filename, pattern)
        else:
            # Exact match
            return filename == pattern
    
    async def get_user_info(self) -> Dict:
        """
        Get authenticated user information.
        
        Returns:
            Dict: User information
        """
        url = f"{self.base_url}/user"
        response = await self._make_request("GET", url)
        return response.json()
    
    async def validate_repository_access(self, repo_url: str) -> bool:
        """
        Validate that the repository can be accessed.
        
        Args:
            repo_url: GitHub repository URL
            
        Returns:
            bool: True if repository is accessible
        """
        try:
            await self.get_repository_info(repo_url)
            return True
        except (RepositoryAccessError, AuthenticationError):
            return False