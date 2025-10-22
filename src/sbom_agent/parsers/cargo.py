"""Rust Cargo.toml parser."""

from typing import List

from .base import DependencyParser
from ..models import Dependency, PackageManager
from ..exceptions import DependencyParsingError


class CargoParser(DependencyParser):
    """Parser for Rust Cargo.toml files."""
    
    def __init__(self):
        super().__init__(PackageManager.CARGO)
    
    def can_parse(self, filename: str) -> bool:
        """Check if this parser can handle the given filename."""
        return filename in ["Cargo.toml", "Cargo.lock"]
    
    async def parse(self, content: str, file_path: str) -> List[Dependency]:
        """Parse Cargo dependency file."""
        if file_path.endswith("Cargo.toml"):
            return await self._parse_cargo_toml(content, file_path)
        elif file_path.endswith("Cargo.lock"):
            return await self._parse_cargo_lock(content, file_path)
        else:
            raise DependencyParsingError(f"Unsupported Cargo file: {file_path}")
    
    async def _parse_cargo_toml(self, content: str, file_path: str) -> List[Dependency]:
        """Parse Cargo.toml file."""
        try:
            data = self._safe_parse_toml(content)
            dependencies = []
            
            # Parse different dependency sections
            for section in ["dependencies", "dev-dependencies", "build-dependencies"]:
                deps = data.get(section, {})
                for name, version_spec in deps.items():
                    dependency = self._parse_cargo_dependency(name, version_spec, file_path)
                    if dependency:
                        dependencies.append(dependency)
            
            return dependencies
            
        except Exception as e:
            raise DependencyParsingError(f"Failed to parse Cargo.toml: {str(e)}") from e
    
    def _parse_cargo_dependency(self, name: str, version_spec, file_path: str) -> Dependency:
        """Parse a single Cargo dependency specification."""
        if isinstance(version_spec, str):
            # Simple version string
            version = version_spec
        elif isinstance(version_spec, dict):
            # Complex dependency specification
            version = version_spec.get("version", "unknown")
            # Could also have git, path, etc.
        else:
            version = "unknown"
        
        return self._create_dependency(
            name=name,
            version=self._normalize_version(version),
            file_path=file_path
        )
    
    async def _parse_cargo_lock(self, content: str, file_path: str) -> List[Dependency]:
        """Parse Cargo.lock file."""
        try:
            data = self._safe_parse_toml(content)
            dependencies = []
            
            # Parse package entries
            packages = data.get("package", [])
            for package in packages:
                name = package.get("name")
                version = package.get("version")
                source = package.get("source")
                
                if name and version:
                    dependency = self._create_dependency(
                        name=name,
                        version=version,
                        file_path=file_path,
                        source_url=source
                    )
                    dependencies.append(dependency)
            
            return dependencies
            
        except Exception as e:
            raise DependencyParsingError(f"Failed to parse Cargo.lock: {str(e)}") from e