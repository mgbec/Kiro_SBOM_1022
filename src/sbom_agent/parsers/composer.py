"""PHP Composer parser."""

from typing import List

from .base import DependencyParser
from ..models import Dependency, PackageManager
from ..exceptions import DependencyParsingError


class ComposerParser(DependencyParser):
    """Parser for PHP Composer files."""
    
    def __init__(self):
        super().__init__(PackageManager.COMPOSER)
    
    def can_parse(self, filename: str) -> bool:
        """Check if this parser can handle the given filename."""
        return filename in ["composer.json", "composer.lock"]
    
    async def parse(self, content: str, file_path: str) -> List[Dependency]:
        """Parse Composer dependency file."""
        if file_path.endswith("composer.json"):
            return await self._parse_composer_json(content, file_path)
        elif file_path.endswith("composer.lock"):
            return await self._parse_composer_lock(content, file_path)
        else:
            raise DependencyParsingError(f"Unsupported Composer file: {file_path}")
    
    async def _parse_composer_json(self, content: str, file_path: str) -> List[Dependency]:
        """Parse composer.json file."""
        try:
            data = self._safe_parse_json(content)
            dependencies = []
            
            # Parse require and require-dev sections
            for section in ["require", "require-dev"]:
                packages = data.get(section, {})
                for name, version in packages.items():
                    # Skip PHP version requirement
                    if name == "php":
                        continue
                    
                    dependency = self._create_dependency(
                        name=name,
                        version=self._normalize_version(version),
                        file_path=file_path
                    )
                    dependencies.append(dependency)
            
            return dependencies
            
        except Exception as e:
            raise DependencyParsingError(f"Failed to parse composer.json: {str(e)}") from e
    
    async def _parse_composer_lock(self, content: str, file_path: str) -> List[Dependency]:
        """Parse composer.lock file."""
        try:
            data = self._safe_parse_json(content)
            dependencies = []
            
            # Parse packages and packages-dev
            for section in ["packages", "packages-dev"]:
                packages = data.get(section, [])
                for package in packages:
                    name = package.get("name")
                    version = package.get("version")
                    description = package.get("description")
                    homepage = package.get("homepage")
                    
                    if name and version:
                        dependency = self._create_dependency(
                            name=name,
                            version=version,
                            file_path=file_path,
                            description=description,
                            homepage=homepage
                        )
                        dependencies.append(dependency)
            
            return dependencies
            
        except Exception as e:
            raise DependencyParsingError(f"Failed to parse composer.lock: {str(e)}") from e