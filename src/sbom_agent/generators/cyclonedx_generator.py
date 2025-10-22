"""CycloneDX format SBOM generator."""

import json
import uuid
from datetime import datetime
from typing import Dict, List, Any
from urllib.parse import urlparse

from ..models import RepositoryAnalysis, Dependency, SBOMReport, SBOMFormat
from ..config import Config
from ..exceptions import SBOMGenerationError


class CycloneDXGenerator:
    """Generates SBOM reports in CycloneDX format."""
    
    def __init__(self):
        self.cyclonedx_version = Config.CYCLONE_DX_VERSION
    
    async def generate(self, analysis: RepositoryAnalysis) -> Dict[str, Any]:
        """
        Generate CycloneDX SBOM report from repository analysis.
        
        Args:
            analysis: Repository analysis results
            
        Returns:
            Dict[str, Any]: CycloneDX SBOM document
        """
        try:
            # Create metadata
            metadata = self._create_metadata(analysis)
            
            # Create components from dependencies
            components = []
            for dep in analysis.dependencies:
                component = self._create_component_from_dependency(dep)
                components.append(component)
            
            # Create CycloneDX document
            cyclonedx_doc = {
                "bomFormat": "CycloneDX",
                "specVersion": self.cyclonedx_version,
                "serialNumber": f"urn:uuid:{str(uuid.uuid4())}",
                "version": 1,
                "metadata": metadata,
                "components": components
            }
            
            return cyclonedx_doc
            
        except Exception as e:
            raise SBOMGenerationError(f"Failed to generate CycloneDX SBOM: {str(e)}") from e
    
    def _create_metadata(self, analysis: RepositoryAnalysis) -> Dict[str, Any]:
        """Create CycloneDX metadata section."""
        repo_name = self._get_repo_name(analysis.repository_url)
        
        metadata = {
            "timestamp": analysis.scan_timestamp.isoformat() + "Z",
            "tools": [
                {
                    "vendor": "SBOM Security Agent",
                    "name": "SBOM Security Agent",
                    "version": "0.1.0"
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": f"pkg:github/{repo_name}@{analysis.branch}",
                "name": repo_name,
                "version": analysis.branch,
                "purl": f"pkg:github/{repo_name}@{analysis.branch}",
                "externalReferences": [
                    {
                        "type": "vcs",
                        "url": analysis.repository_url
                    }
                ]
            }
        }
        
        return metadata
    
    def _create_component_from_dependency(self, dependency: Dependency) -> Dict[str, Any]:
        """Convert a Dependency to a CycloneDX component."""
        # Determine component type based on package manager
        component_type = self._get_component_type(dependency.package_manager.value)
        
        # Generate Package URL (PURL)
        purl = self._generate_purl(dependency)
        
        # Create component
        component = {
            "type": component_type,
            "bom-ref": purl,
            "name": dependency.name,
            "version": dependency.version,
            "purl": purl
        }
        
        # Add optional fields
        if dependency.description:
            component["description"] = dependency.description
        
        if dependency.license:
            component["licenses"] = [
                {
                    "license": {
                        "name": dependency.license
                    }
                }
            ]
        
        # Add external references
        external_refs = []
        
        if dependency.homepage:
            external_refs.append({
                "type": "website",
                "url": dependency.homepage
            })
        
        if dependency.source_url:
            external_refs.append({
                "type": "distribution",
                "url": dependency.source_url
            })
        
        if external_refs:
            component["externalReferences"] = external_refs
        
        # Add properties for additional metadata
        properties = [
            {
                "name": "sbom:package_manager",
                "value": dependency.package_manager.value
            },
            {
                "name": "sbom:file_path",
                "value": dependency.file_path
            }
        ]
        
        component["properties"] = properties
        
        return component
    
    def _get_component_type(self, package_manager: str) -> str:
        """Get CycloneDX component type based on package manager."""
        type_mapping = {
            "npm": "library",
            "pip": "library", 
            "maven": "library",
            "gradle": "library",
            "cargo": "library",
            "go": "library",
            "composer": "library",
            "nuget": "library"
        }
        
        return type_mapping.get(package_manager, "library")
    
    def _generate_purl(self, dependency: Dependency) -> str:
        """Generate Package URL (PURL) for a dependency."""
        package_manager = dependency.package_manager.value
        name = dependency.name
        version = dependency.version
        
        # PURL type mapping
        purl_types = {
            "npm": "npm",
            "pip": "pypi",
            "maven": "maven",
            "gradle": "maven",  # Gradle uses Maven repositories
            "cargo": "cargo",
            "go": "golang",
            "composer": "composer",
            "nuget": "nuget"
        }
        
        purl_type = purl_types.get(package_manager, "generic")
        
        # Handle special cases
        if package_manager == "maven" and ":" in name:
            # Maven format: groupId:artifactId
            group_id, artifact_id = name.split(":", 1)
            return f"pkg:maven/{group_id}/{artifact_id}@{version}"
        elif package_manager == "npm" and name.startswith("@"):
            # Scoped npm package
            return f"pkg:npm/{name}@{version}"
        else:
            # Standard format
            return f"pkg:{purl_type}/{name}@{version}"
    
    def _get_repo_name(self, repo_url: str) -> str:
        """Extract repository name from URL."""
        try:
            parsed = urlparse(repo_url)
            path_parts = parsed.path.strip("/").split("/")
            if len(path_parts) >= 2:
                return f"{path_parts[-2]}/{path_parts[-1]}"
            return path_parts[-1] if path_parts else "unknown"
        except Exception:
            return "unknown"
    
    async def serialize_to_json(self, cyclonedx_doc: Dict[str, Any]) -> str:
        """
        Serialize CycloneDX SBOM document to JSON format.
        
        Args:
            cyclonedx_doc: CycloneDX document to serialize
            
        Returns:
            str: JSON representation of CycloneDX document
        """
        try:
            return json.dumps(cyclonedx_doc, indent=2, ensure_ascii=False)
        except Exception as e:
            raise SBOMGenerationError(f"Failed to serialize CycloneDX to JSON: {str(e)}") from e
    
    async def add_vulnerabilities(self, cyclonedx_doc: Dict[str, Any], vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """
        Add vulnerability information to CycloneDX document.
        
        Args:
            cyclonedx_doc: CycloneDX document
            vulnerabilities: List of vulnerability data
            
        Returns:
            Dict[str, Any]: Updated CycloneDX document with vulnerabilities
        """
        if not vulnerabilities:
            return cyclonedx_doc
        
        # Convert vulnerabilities to CycloneDX format
        cyclonedx_vulns = []
        
        for vuln in vulnerabilities:
            cyclonedx_vuln = {
                "id": vuln.get("advisory_id", "unknown"),
                "source": {
                    "name": "SBOM Security Agent",
                    "url": "https://github.com/sbom-security-agent"
                },
                "ratings": [
                    {
                        "source": {
                            "name": "SBOM Security Agent"
                        },
                        "severity": vuln.get("severity", "unknown").lower(),
                        "method": "other"
                    }
                ]
            }
            
            # Add CVE ID if available
            if vuln.get("cve_id"):
                cyclonedx_vuln["id"] = vuln["cve_id"]
            
            # Add description
            if vuln.get("summary"):
                cyclonedx_vuln["description"] = vuln["summary"]
            
            # Add references
            if vuln.get("references"):
                cyclonedx_vuln["advisories"] = [
                    {"url": ref} for ref in vuln["references"]
                ]
            
            # Add affected components
            if vuln.get("affected_components"):
                cyclonedx_vuln["affects"] = [
                    {"ref": comp} for comp in vuln["affected_components"]
                ]
            
            cyclonedx_vulns.append(cyclonedx_vuln)
        
        # Add vulnerabilities to document
        cyclonedx_doc["vulnerabilities"] = cyclonedx_vulns
        
        return cyclonedx_doc