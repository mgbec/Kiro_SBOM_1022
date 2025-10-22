"""GitHub OAuth2 authentication integration for the SBOM Security Agent."""

import asyncio
from typing import Optional

from bedrock_agentcore.identity.auth import requires_access_token

from .config import Config
from .exceptions import AuthenticationError


class GitHubAuthManager:
    """Manages GitHub OAuth2 authentication and token storage."""
    
    def __init__(self):
        self._access_token: Optional[str] = None
        self._auth_queue: Optional[asyncio.Queue] = None
    
    @property
    def access_token(self) -> Optional[str]:
        """Get the current GitHub access token."""
        return self._access_token
    
    def set_access_token(self, token: str) -> None:
        """Set the GitHub access token."""
        self._access_token = token
    
    def clear_token(self) -> None:
        """Clear the stored access token."""
        self._access_token = None
    
    def is_authenticated(self) -> bool:
        """Check if user is currently authenticated with GitHub."""
        return self._access_token is not None
    
    async def on_auth_url(self, url: str) -> None:
        """Callback for handling authorization URLs during OAuth flow."""
        print(f"GitHub Authorization URL: {url}")
        if self._auth_queue:
            await self._auth_queue.put(f"Please visit this URL to authorize: {url}")
    
    def set_auth_queue(self, queue: asyncio.Queue) -> None:
        """Set the queue for streaming authentication messages."""
        self._auth_queue = queue


# Global authentication manager instance
auth_manager = GitHubAuthManager()


@requires_access_token(
    provider_name=Config.GITHUB_PROVIDER_NAME,
    scopes=Config.GITHUB_SCOPES,
    auth_flow="USER_FEDERATION",
    on_auth_url=auth_manager.on_auth_url,
    force_authentication=True,
)
async def authenticate_github(*, access_token: str) -> str:
    """
    Authenticate with GitHub using OAuth2 3LO flow.
    
    This function is decorated with @requires_access_token to handle the
    OAuth2 authentication flow with GitHub. It follows the same pattern
    as the reference implementation.
    
    Args:
        access_token: The OAuth2 access token provided by the decorator
        
    Returns:
        str: The access token for use in subsequent API calls
        
    Raises:
        AuthenticationError: If authentication fails
    """
    try:
        if not access_token:
            raise AuthenticationError("No access token received from GitHub OAuth flow")
        
        # Store the token in the auth manager
        auth_manager.set_access_token(access_token)
        
        print(f"GitHub authentication successful. Token: {access_token[:10]}...")
        
        if auth_manager._auth_queue:
            await auth_manager._auth_queue.put("✅ GitHub authentication successful!")
        
        return access_token
        
    except Exception as e:
        error_msg = f"GitHub authentication failed: {str(e)}"
        print(error_msg)
        
        if auth_manager._auth_queue:
            await auth_manager._auth_queue.put(f"❌ {error_msg}")
        
        raise AuthenticationError(error_msg) from e


async def ensure_github_authentication() -> str:
    """
    Ensure GitHub authentication is available.
    
    Returns:
        str: The GitHub access token
        
    Raises:
        AuthenticationError: If authentication is not available or fails
    """
    if not auth_manager.is_authenticated():
        # Trigger authentication flow
        try:
            token = await authenticate_github(access_token="")
            return token
        except Exception as e:
            raise AuthenticationError(f"Failed to authenticate with GitHub: {str(e)}") from e
    
    return auth_manager.access_token


def get_auth_headers() -> dict:
    """
    Get HTTP headers for GitHub API authentication.
    
    Returns:
        dict: Headers with Authorization token
        
    Raises:
        AuthenticationError: If no valid token is available
    """
    if not auth_manager.is_authenticated():
        raise AuthenticationError("GitHub authentication required. Please authenticate first.")
    
    return {
        "Authorization": f"Bearer {auth_manager.access_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }


def needs_authentication(response_text: str) -> bool:
    """
    Check if a response indicates that authentication is required.
    
    Args:
        response_text: The response text to check
        
    Returns:
        bool: True if authentication is needed
    """
    auth_keywords = [
        "authentication", "authorize", "authorization", "auth",
        "sign in", "login", "access", "permission", "credential",
        "need authentication", "requires authentication",
        "github authentication", "oauth"
    ]
    
    return any(keyword.lower() in response_text.lower() for keyword in auth_keywords)