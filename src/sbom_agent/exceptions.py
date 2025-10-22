"""Custom exceptions for the SBOM Security Agent."""


class SBOMAgentError(Exception):
    """Base exception for SBOM Agent errors."""
    pass


class AuthenticationError(SBOMAgentError):
    """Raised when GitHub authentication fails."""
    pass


class RepositoryAccessError(SBOMAgentError):
    """Raised when repository cannot be accessed."""
    pass


class DependencyParsingError(SBOMAgentError):
    """Raised when dependency files cannot be parsed."""
    pass


class VulnerabilityDatabaseError(SBOMAgentError):
    """Raised when vulnerability database queries fail."""
    pass


class SBOMGenerationError(SBOMAgentError):
    """Raised when SBOM generation fails."""
    pass


class UnsupportedPackageManagerError(DependencyParsingError):
    """Raised when encountering unsupported package manager."""
    pass


class RateLimitError(SBOMAgentError):
    """Raised when API rate limits are exceeded."""
    pass


class NetworkError(SBOMAgentError):
    """Raised when network operations fail."""
    pass