"""Base class for dependency parsers."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any

from ..models import Dependency, PackageManager
from ..exceptions import DependencyParsingError


class DependencyParser(ABC):
    """Base class for parsing dependency files."""
    
    def __init__(self, package_manager: PackageManager):
        self.package_manager = package_manager
    
    @abstractmethod
    async def parse(self, content: str, file_path: str) -> List[Dependency]:
        """
        Parse dependency file content.
        
        Args:
            content: File content as string
            file_path: Path to the dependency file
            
        Returns:
            List[Dependency]: Parsed dependencies
            
        Raises:
            DependencyParsingError: If parsing fails
        """
        pass
    
    @abstractmethod
    def can_parse(self, filename: str) -> bool:
        """
        Check if this parser can handle the given filename.
        
        Args:
            filename: Name of the file
            
        Returns:
            bool: True if parser can handle this file
        """
        pass
    
    def _create_dependency(
        self,
        name: str,
        version: str,
        file_path: str,
        license: str = None,
        source_url: str = None,
        description: str = None,
        homepage: str = None
    ) -> Dependency:
        """
        Create a Dependency object with validation.
        
        Args:
            name: Package name
            version: Package version
            file_path: Path where dependency was declared
            license: Package license
            source_url: Source URL
            description: Package description
            homepage: Package homepage
            
        Returns:
            Dependency: Created dependency object
        """
        if not name or not version:
            raise DependencyParsingError(f"Invalid dependency: name='{name}', version='{version}'")
        
        return Dependency(
            name=name.strip(),
            version=version.strip(),
            package_manager=self.package_manager,
            license=license,
            source_url=source_url,
            file_path=file_path,
            description=description,
            homepage=homepage
        )
    
    def _normalize_version(self, version: str) -> str:
        """
        Normalize version string by removing common prefixes and suffixes.
        
        Args:
            version: Raw version string
            
        Returns:
            str: Normalized version
        """
        if not version:
            return "unknown"
        
        # Remove common prefixes
        version = version.strip()
        for prefix in ["^", "~", ">=", "<=", ">", "<", "="]:
            if version.startswith(prefix):
                version = version[len(prefix):].strip()
        
        # Remove quotes
        version = version.strip('"\'')
        
        # Handle version ranges (take the first version)
        if " - " in version:
            version = version.split(" - ")[0].strip()
        
        if " || " in version:
            version = version.split(" || ")[0].strip()
        
        return version or "unknown"
    
    def _safe_parse_json(self, content: str) -> Dict[str, Any]:
        """
        Safely parse JSON content with error handling.
        
        Args:
            content: JSON content as string
            
        Returns:
            Dict: Parsed JSON data
            
        Raises:
            DependencyParsingError: If JSON parsing fails
        """
        import json
        
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise DependencyParsingError(f"Invalid JSON format: {str(e)}") from e
    
    def _safe_parse_toml(self, content: str) -> Dict[str, Any]:
        """
        Safely parse TOML content with error handling.
        
        Args:
            content: TOML content as string
            
        Returns:
            Dict: Parsed TOML data
            
        Raises:
            DependencyParsingError: If TOML parsing fails
        """
        import toml
        
        try:
            return toml.loads(content)
        except Exception as e:
            raise DependencyParsingError(f"Invalid TOML format: {str(e)}") from e
    
    def _safe_parse_yaml(self, content: str) -> Dict[str, Any]:
        """
        Safely parse YAML content with error handling.
        
        Args:
            content: YAML content as string
            
        Returns:
            Dict: Parsed YAML data
            
        Raises:
            DependencyParsingError: If YAML parsing fails
        """
        import yaml
        
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise DependencyParsingError(f"Invalid YAML format: {str(e)}") from e