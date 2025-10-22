"""Maven pom.xml parser."""

import xml.etree.ElementTree as ET
from typing import List

from .base import DependencyParser
from ..models import Dependency, PackageManager
from ..exceptions import DependencyParsingError


class MavenParser(DependencyParser):
    """Parser for Maven pom.xml files."""
    
    def __init__(self):
        super().__init__(PackageManager.MAVEN)
    
    def can_parse(self, filename: str) -> bool:
        """Check if this parser can handle the given filename."""
        return filename == "pom.xml"
    
    async def parse(self, content: str, file_path: str) -> List[Dependency]:
        """Parse Maven pom.xml file."""
        try:
            # Parse XML
            root = ET.fromstring(content)
            
            # Handle namespace
            namespace = ""
            if root.tag.startswith("{"):
                namespace = root.tag.split("}")[0] + "}"
            
            dependencies = []
            
            # Find dependencies section
            deps_element = root.find(f"{namespace}dependencies")
            if deps_element is not None:
                for dep in deps_element.findall(f"{namespace}dependency"):
                    dependency = self._parse_dependency_element(dep, namespace, file_path)
                    if dependency:
                        dependencies.append(dependency)
            
            return dependencies
            
        except ET.ParseError as e:
            raise DependencyParsingError(f"Invalid XML in pom.xml: {str(e)}") from e
        except Exception as e:
            raise DependencyParsingError(f"Failed to parse pom.xml: {str(e)}") from e
    
    def _parse_dependency_element(self, dep_element: ET.Element, namespace: str, file_path: str) -> Dependency:
        """Parse a single dependency element."""
        group_id = self._get_element_text(dep_element, f"{namespace}groupId")
        artifact_id = self._get_element_text(dep_element, f"{namespace}artifactId")
        version = self._get_element_text(dep_element, f"{namespace}version", "unknown")
        scope = self._get_element_text(dep_element, f"{namespace}scope", "compile")
        
        if not group_id or not artifact_id:
            return None
        
        # Create full name in Maven format
        name = f"{group_id}:{artifact_id}"
        
        return self._create_dependency(
            name=name,
            version=self._normalize_version(version),
            file_path=file_path,
            description=f"Maven dependency (scope: {scope})"
        )
    
    def _get_element_text(self, parent: ET.Element, tag: str, default: str = None) -> str:
        """Get text content of a child element."""
        element = parent.find(tag)
        if element is not None and element.text:
            return element.text.strip()
        return default