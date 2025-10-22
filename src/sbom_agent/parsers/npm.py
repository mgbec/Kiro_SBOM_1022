"""NPM package.json parser."""

from typing import List, Dict, Any

from .base import DependencyParser
from ..models import Dependency, PackageManager
from ..exceptions import DependencyParsingError


class NPMParser(DependencyParser):
    """Parser for NPM package.json files."""
    
    def __init__(self):
        super().__init__(PackageManager.NPM)
    
    def can_parse(self, filename: str) -> bool:
        """Check if this parser can handle the given filename."""
        return filename in ["package.json", "package-lock.json", "yarn.lock"]
    
    async def parse(self, content: str, file_path: str) -> List[Dependency]:
        """Parse NPM dependency file."""
        if file_path.endswith("package.json"):
            return await self._parse_package_json(content, file_path)
        elif file_path.endswith("package-lock.json"):
            return await self._parse_package_lock(content, file_path)
        elif file_path.endswith("yarn.lock"):
            return await self._parse_yarn_lock(content, file_path)
        else:
            raise DependencyParsingError(f"Unsupported NPM file: {file_path}")
    
    async def _parse_package_json(self, content: str, file_path: str) -> List[Dependency]:
        """Parse package.json file."""
        try:
            data = self._safe_parse_json(content)
            dependencies = []
            
            # Parse dependencies
            for dep_type in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
                deps = data.get(dep_type, {})
                for name, version in deps.items():
                    dependency = self._create_dependency(
                        name=name,
                        version=self._normalize_version(version),
                        file_path=file_path,
                        description=data.get("description") if name == data.get("name") else None,
                        homepage=data.get("homepage") if name == data.get("name") else None
                    )
                    dependencies.append(dependency)
            
            return dependencies
            
        except Exception as e:
            raise DependencyParsingError(f"Failed to parse package.json: {str(e)}") from e
    
    async def _parse_package_lock(self, content: str, file_path: str) -> List[Dependency]:
        """Parse package-lock.json file."""
        try:
            data = self._safe_parse_json(content)
            dependencies = []
            
            # Parse packages (npm v2+ format)
            packages = data.get("packages", {})
            for package_path, package_info in packages.items():
                if package_path == "":  # Skip root package
                    continue
                
                name = package_info.get("name")
                if not name:
                    # Extract name from path
                    name = package_path.split("/")[-1]
                
                version = package_info.get("version", "unknown")
                
                dependency = self._create_dependency(
                    name=name,
                    version=version,
                    file_path=file_path,
                    source_url=package_info.get("resolved"),
                    description=package_info.get("description")
                )
                dependencies.append(dependency)
            
            # Fallback to dependencies format (npm v1 format)
            if not dependencies:
                deps = data.get("dependencies", {})
                for name, dep_info in deps.items():
                    version = dep_info.get("version", "unknown")
                    dependency = self._create_dependency(
                        name=name,
                        version=version,
                        file_path=file_path,
                        source_url=dep_info.get("resolved")
                    )
                    dependencies.append(dependency)
            
            return dependencies
            
        except Exception as e:
            raise DependencyParsingError(f"Failed to parse package-lock.json: {str(e)}") from e
    
    async def _parse_yarn_lock(self, content: str, file_path: str) -> List[Dependency]:
        """Parse yarn.lock file."""
        try:
            dependencies = []
            current_package = None
            current_version = None
            
            for line in content.split('\n'):
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                # Package declaration line
                if line.endswith(':') and not line.startswith(' '):
                    # Extract package name and version constraint
                    package_spec = line[:-1]  # Remove trailing ':'
                    
                    # Handle multiple package specs on one line
                    if ',' in package_spec:
                        package_spec = package_spec.split(',')[0].strip()
                    
                    # Extract package name (before @version)
                    if '@' in package_spec and not package_spec.startswith('@'):
                        current_package = package_spec.rsplit('@', 1)[0]
                    elif package_spec.startswith('@'):
                        # Scoped package
                        parts = package_spec.split('@')
                        if len(parts) >= 3:
                            current_package = '@' + parts[1]
                        else:
                            current_package = package_spec
                    else:
                        current_package = package_spec
                
                # Version line
                elif line.startswith('version ') and current_package:
                    version_line = line[8:].strip()  # Remove 'version '
                    current_version = version_line.strip('"\'')
                    
                    dependency = self._create_dependency(
                        name=current_package,
                        version=current_version,
                        file_path=file_path
                    )
                    dependencies.append(dependency)
                    
                    current_package = None
                    current_version = None
            
            return dependencies
            
        except Exception as e:
            raise DependencyParsingError(f"Failed to parse yarn.lock: {str(e)}") from e