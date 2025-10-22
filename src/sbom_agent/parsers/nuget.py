"""NuGet .NET package parser."""

import re
import xml.etree.ElementTree as ET
from typing import List

from .base import DependencyParser
from ..models import Dependency, PackageManager
from ..exceptions import DependencyParsingError


class NuGetParser(DependencyParser):
    """Parser for NuGet .NET package files."""
    
    def __init__(self):
        super().__init__(PackageManager.NUGET)
    
    def can_parse(self, filename: str) -> bool:
        """Check if this parser can handle the given filename."""
        return (filename.endswith(".csproj") or 
                filename == "packages.config" or 
                filename.endswith(".nuspec"))
    
    async def parse(self, content: str, file_path: str) -> List[Dependency]:
        """Parse NuGet dependency file."""
        if file_path.endswith(".csproj"):
            return await self._parse_csproj(content, file_path)
        elif file_path.endswith("packages.config"):
            return await self._parse_packages_config(content, file_path)
        elif file_path.endswith(".nuspec"):
            return await self._parse_nuspec(content, file_path)
        else:
            raise DependencyParsingError(f"Unsupported NuGet file: {file_path}")
    
    async def _parse_csproj(self, content: str, file_path: str) -> List[Dependency]:
        """Parse .csproj file."""
        try:
            root = ET.fromstring(content)
            dependencies = []
            
            # Find PackageReference elements
            for package_ref in root.iter("PackageReference"):
                name = package_ref.get("Include")
                version = package_ref.get("Version")
                
                if name:
                    if not version:
                        # Version might be in a child element
                        version_elem = package_ref.find("Version")
                        if version_elem is not None:
                            version = version_elem.text
                    
                    dependency = self._create_dependency(
                        name=name,
                        version=self._normalize_version(version or "unknown"),
                        file_path=file_path
                    )
                    dependencies.append(dependency)
            
            # Also check for Reference elements with HintPath (older format)
            for ref in root.iter("Reference"):
                include = ref.get("Include")
                if include and "," in include:
                    # Format: "PackageName, Version=1.0.0, Culture=neutral, PublicKeyToken=..."
                    parts = include.split(",")
                    name = parts[0].strip()
                    version = "unknown"
                    
                    for part in parts[1:]:
                        if part.strip().startswith("Version="):
                            version = part.strip()[8:]  # Remove "Version="
                            break
                    
                    dependency = self._create_dependency(
                        name=name,
                        version=self._normalize_version(version),
                        file_path=file_path
                    )
                    dependencies.append(dependency)
            
            return dependencies
            
        except ET.ParseError as e:
            raise DependencyParsingError(f"Invalid XML in .csproj: {str(e)}") from e
        except Exception as e:
            raise DependencyParsingError(f"Failed to parse .csproj: {str(e)}") from e
    
    async def _parse_packages_config(self, content: str, file_path: str) -> List[Dependency]:
        """Parse packages.config file."""
        try:
            root = ET.fromstring(content)
            dependencies = []
            
            # Find package elements
            for package in root.iter("package"):
                name = package.get("id")
                version = package.get("version")
                
                if name and version:
                    dependency = self._create_dependency(
                        name=name,
                        version=version,
                        file_path=file_path
                    )
                    dependencies.append(dependency)
            
            return dependencies
            
        except ET.ParseError as e:
            raise DependencyParsingError(f"Invalid XML in packages.config: {str(e)}") from e
        except Exception as e:
            raise DependencyParsingError(f"Failed to parse packages.config: {str(e)}") from e
    
    async def _parse_nuspec(self, content: str, file_path: str) -> List[Dependency]:
        """Parse .nuspec file."""
        try:
            root = ET.fromstring(content)
            dependencies = []
            
            # Handle namespace
            namespace = ""
            if root.tag.startswith("{"):
                namespace = root.tag.split("}")[0] + "}"
            
            # Find dependencies in metadata
            metadata = root.find(f"{namespace}metadata")
            if metadata is not None:
                deps_element = metadata.find(f"{namespace}dependencies")
                if deps_element is not None:
                    for dep in deps_element.iter(f"{namespace}dependency"):
                        name = dep.get("id")
                        version = dep.get("version")
                        
                        if name:
                            dependency = self._create_dependency(
                                name=name,
                                version=self._normalize_version(version or "unknown"),
                                file_path=file_path
                            )
                            dependencies.append(dependency)
            
            return dependencies
            
        except ET.ParseError as e:
            raise DependencyParsingError(f"Invalid XML in .nuspec: {str(e)}") from e
        except Exception as e:
            raise DependencyParsingError(f"Failed to parse .nuspec: {str(e)}") from e