"""Gradle build.gradle parser."""

import re
from typing import List

from .base import DependencyParser
from ..models import Dependency, PackageManager
from ..exceptions import DependencyParsingError


class GradleParser(DependencyParser):
    """Parser for Gradle build.gradle files."""
    
    def __init__(self):
        super().__init__(PackageManager.GRADLE)
    
    def can_parse(self, filename: str) -> bool:
        """Check if this parser can handle the given filename."""
        return filename in ["build.gradle", "build.gradle.kts"]
    
    async def parse(self, content: str, file_path: str) -> List[Dependency]:
        """Parse Gradle build file."""
        try:
            dependencies = []
            
            # Find dependencies block
            in_dependencies_block = False
            brace_count = 0
            
            for line in content.split('\n'):
                line = line.strip()
                
                # Skip comments
                if line.startswith('//') or line.startswith('/*'):
                    continue
                
                # Check for dependencies block start
                if 'dependencies' in line and '{' in line:
                    in_dependencies_block = True
                    brace_count = line.count('{') - line.count('}')
                    continue
                
                if in_dependencies_block:
                    # Track braces to know when we exit the dependencies block
                    brace_count += line.count('{') - line.count('}')
                    
                    if brace_count <= 0:
                        in_dependencies_block = False
                        continue
                    
                    # Parse dependency declarations
                    dependency = self._parse_dependency_line(line, file_path)
                    if dependency:
                        dependencies.append(dependency)
            
            return dependencies
            
        except Exception as e:
            raise DependencyParsingError(f"Failed to parse Gradle file: {str(e)}") from e
    
    def _parse_dependency_line(self, line: str, file_path: str) -> Dependency:
        """Parse a single dependency line."""
        # Remove comments
        if '//' in line:
            line = line.split('//')[0].strip()
        
        # Common Gradle dependency patterns
        patterns = [
            # implementation 'group:artifact:version'
            r"(?:implementation|compile|api|testImplementation|testCompile|runtimeOnly|compileOnly)\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
            # implementation group: 'group', name: 'artifact', version: 'version'
            r"(?:implementation|compile|api|testImplementation|testCompile|runtimeOnly|compileOnly)\s+group:\s*['\"]([^'\"]+)['\"],\s*name:\s*['\"]([^'\"]+)['\"],\s*version:\s*['\"]([^'\"]+)['\"]",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                if len(match.groups()) == 3:
                    group, artifact, version = match.groups()
                    name = f"{group}:{artifact}"
                    
                    return self._create_dependency(
                        name=name,
                        version=self._normalize_version(version),
                        file_path=file_path
                    )
        
        return None