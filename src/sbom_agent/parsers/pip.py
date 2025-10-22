"""Python pip requirements parser."""

import re
from typing import List

from .base import DependencyParser
from ..models import Dependency, PackageManager
from ..exceptions import DependencyParsingError


class PipParser(DependencyParser):
    """Parser for Python pip requirements files."""
    
    def __init__(self):
        super().__init__(PackageManager.PIP)
    
    def can_parse(self, filename: str) -> bool:
        """Check if this parser can handle the given filename."""
        return filename in ["requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml"]
    
    async def parse(self, content: str, file_path: str) -> List[Dependency]:
        """Parse Python dependency file."""
        if file_path.endswith("requirements.txt"):
            return await self._parse_requirements_txt(content, file_path)
        elif file_path.endswith("Pipfile"):
            return await self._parse_pipfile(content, file_path)
        elif file_path.endswith("Pipfile.lock"):
            return await self._parse_pipfile_lock(content, file_path)
        elif file_path.endswith("pyproject.toml"):
            return await self._parse_pyproject_toml(content, file_path)
        else:
            raise DependencyParsingError(f"Unsupported Python file: {file_path}")
    
    async def _parse_requirements_txt(self, content: str, file_path: str) -> List[Dependency]:
        """Parse requirements.txt file."""
        try:
            dependencies = []
            
            for line in content.split('\n'):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Skip -r, -e, and other pip options
                if line.startswith('-'):
                    continue
                
                # Parse package specification
                dependency = self._parse_requirement_line(line, file_path)
                if dependency:
                    dependencies.append(dependency)
            
            return dependencies
            
        except Exception as e:
            raise DependencyParsingError(f"Failed to parse requirements.txt: {str(e)}") from e
    
    def _parse_requirement_line(self, line: str, file_path: str) -> Dependency:
        """Parse a single requirement line."""
        # Remove inline comments
        if '#' in line:
            line = line.split('#')[0].strip()
        
        # Regular expression to parse package specifications
        # Handles: package==1.0, package>=1.0, package~=1.0, etc.
        pattern = r'^([a-zA-Z0-9_.-]+(?:\[[a-zA-Z0-9_,.-]*\])?)\s*([><=!~]+)?\s*([0-9a-zA-Z.-]+(?:\.[0-9a-zA-Z.-]*)*)?'
        match = re.match(pattern, line)
        
        if not match:
            return None
        
        name = match.group(1)
        operator = match.group(2) or ""
        version = match.group(3) or "unknown"
        
        # Remove extras from package name (e.g., requests[security])
        if '[' in name:
            name = name.split('[')[0]
        
        return self._create_dependency(
            name=name,
            version=self._normalize_version(f"{operator}{version}"),
            file_path=file_path
        )
    
    async def _parse_pipfile(self, content: str, file_path: str) -> List[Dependency]:
        """Parse Pipfile."""
        try:
            data = self._safe_parse_toml(content)
            dependencies = []
            
            # Parse packages and dev-packages
            for section in ["packages", "dev-packages"]:
                packages = data.get(section, {})
                for name, version_spec in packages.items():
                    if isinstance(version_spec, dict):
                        version = version_spec.get("version", "unknown")
                    else:
                        version = str(version_spec)
                    
                    dependency = self._create_dependency(
                        name=name,
                        version=self._normalize_version(version),
                        file_path=file_path
                    )
                    dependencies.append(dependency)
            
            return dependencies
            
        except Exception as e:
            raise DependencyParsingError(f"Failed to parse Pipfile: {str(e)}") from e
    
    async def _parse_pipfile_lock(self, content: str, file_path: str) -> List[Dependency]:
        """Parse Pipfile.lock."""
        try:
            data = self._safe_parse_json(content)
            dependencies = []
            
            # Parse default and develop dependencies
            for section in ["default", "develop"]:
                packages = data.get(section, {})
                for name, package_info in packages.items():
                    version = package_info.get("version", "unknown")
                    
                    dependency = self._create_dependency(
                        name=name,
                        version=self._normalize_version(version),
                        file_path=file_path
                    )
                    dependencies.append(dependency)
            
            return dependencies
            
        except Exception as e:
            raise DependencyParsingError(f"Failed to parse Pipfile.lock: {str(e)}") from e
    
    async def _parse_pyproject_toml(self, content: str, file_path: str) -> List[Dependency]:
        """Parse pyproject.toml file."""
        try:
            data = self._safe_parse_toml(content)
            dependencies = []
            
            # Parse project dependencies
            project = data.get("project", {})
            deps = project.get("dependencies", [])
            
            for dep_spec in deps:
                dependency = self._parse_requirement_line(dep_spec, file_path)
                if dependency:
                    dependencies.append(dependency)
            
            # Parse optional dependencies
            optional_deps = project.get("optional-dependencies", {})
            for group_name, group_deps in optional_deps.items():
                for dep_spec in group_deps:
                    dependency = self._parse_requirement_line(dep_spec, file_path)
                    if dependency:
                        dependencies.append(dependency)
            
            return dependencies
            
        except Exception as e:
            raise DependencyParsingError(f"Failed to parse pyproject.toml: {str(e)}") from e