"""Go modules go.mod parser."""

import re
from typing import List

from .base import DependencyParser
from ..models import Dependency, PackageManager
from ..exceptions import DependencyParsingError


class GoModParser(DependencyParser):
    """Parser for Go modules go.mod files."""
    
    def __init__(self):
        super().__init__(PackageManager.GO_MOD)
    
    def can_parse(self, filename: str) -> bool:
        """Check if this parser can handle the given filename."""
        return filename in ["go.mod", "go.sum"]
    
    async def parse(self, content: str, file_path: str) -> List[Dependency]:
        """Parse Go modules file."""
        if file_path.endswith("go.mod"):
            return await self._parse_go_mod(content, file_path)
        elif file_path.endswith("go.sum"):
            return await self._parse_go_sum(content, file_path)
        else:
            raise DependencyParsingError(f"Unsupported Go file: {file_path}")
    
    async def _parse_go_mod(self, content: str, file_path: str) -> List[Dependency]:
        """Parse go.mod file."""
        try:
            dependencies = []
            in_require_block = False
            
            for line in content.split('\n'):
                line = line.strip()
                
                # Skip comments
                if line.startswith('//'):
                    continue
                
                # Check for require block
                if line.startswith('require ('):
                    in_require_block = True
                    continue
                elif line == ')' and in_require_block:
                    in_require_block = False
                    continue
                
                # Parse require statements
                if in_require_block or line.startswith('require '):
                    dependency = self._parse_require_line(line, file_path)
                    if dependency:
                        dependencies.append(dependency)
            
            return dependencies
            
        except Exception as e:
            raise DependencyParsingError(f"Failed to parse go.mod: {str(e)}") from e
    
    def _parse_require_line(self, line: str, file_path: str) -> Dependency:
        """Parse a single require line."""
        # Remove 'require' keyword if present
        if line.startswith('require '):
            line = line[8:].strip()
        
        # Remove comments
        if '//' in line:
            line = line.split('//')[0].strip()
        
        # Parse module and version
        # Format: module version
        parts = line.split()
        if len(parts) >= 2:
            module = parts[0]
            version = parts[1]
            
            return self._create_dependency(
                name=module,
                version=self._normalize_version(version),
                file_path=file_path
            )
        
        return None
    
    async def _parse_go_sum(self, content: str, file_path: str) -> List[Dependency]:
        """Parse go.sum file."""
        try:
            dependencies = []
            seen_modules = set()
            
            for line in content.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # go.sum format: module version hash
                parts = line.split()
                if len(parts) >= 2:
                    module = parts[0]
                    version = parts[1]
                    
                    # Remove /go.mod suffix from version if present
                    if version.endswith('/go.mod'):
                        version = version[:-7]
                    
                    # Avoid duplicates (go.sum has entries for both module and module/go.mod)
                    module_version = f"{module}@{version}"
                    if module_version not in seen_modules:
                        seen_modules.add(module_version)
                        
                        dependency = self._create_dependency(
                            name=module,
                            version=self._normalize_version(version),
                            file_path=file_path
                        )
                        dependencies.append(dependency)
            
            return dependencies
            
        except Exception as e:
            raise DependencyParsingError(f"Failed to parse go.sum: {str(e)}") from e