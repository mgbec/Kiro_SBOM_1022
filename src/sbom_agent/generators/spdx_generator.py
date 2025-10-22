"""SPDX format SBOM generator."""

import json
from datetime import datetime
from typing import Dict, List, Any
from urllib.parse import urlparse

from ..models import RepositoryAnalysis, Dependency, SBOMReport, Package, Relationship, CreationInfo, SBOMFormat
from ..config import Config
from ..exceptions import SBOMGenerationError


class SPDXGenerator:
    """Generates SBOM reports in SPDX format."""
    
    def __init__(self):
        self.spdx_version = Config.SPDX_VERSION
    
    async def generate(self, analysis: RepositoryAnalysis) -> SBOMReport:
        """
        Generate SPDX SBOM report from repository analysis.
        
        Args:
            analysis: Repository analysis results
            
        Returns:
            SBOMReport: SBOM report in SPDX format
        """
        try:
            # Create creation info
            creation_info = CreationInfo(
                created=analysis.scan_timestamp,
                creators=["Tool: SBOM Security Agent"],
                license_list_version="3.19"
            )
            
            # Convert dependencies to SPDX packages
            packages = []
            relationships = []
            
            # Create root package for the repository
            repo_package = self._create_repository_package(analysis)
            packages.append(repo_package)
            
            # Process dependencies
            for dep in analysis.dependencies:
                package = self._create_package_from_dependency(dep)
                packages.append(package)
                
                # Create relationship between repository and dependency
                relationship = Relationship(
                    spdx_element_id=repo_package.spdx_id,
                    relationship_type="DEPENDS_ON",
                    related_spdx_element=package.spdx_id,
                    comment=f"Dependency declared in {dep.file_path}"
                )
                relationships.append(relationship)
            
            # Create SBOM report
            report = SBOMReport(
                format=SBOMFormat.SPDX,
                version=self.spdx_version,
                creation_info=creation_info,
                packages=packages,
                relationships=relationships,
                document_name=f"SBOM for {self._get_repo_name(analysis.repository_url)}",
                document_namespace=self._generate_document_namespace(analysis)
            )
            
            return report
            
        except Exception as e:
            raise SBOMGenerationError(f"Failed to generate SPDX SBOM: {str(e)}") from e
    
    def _create_repository_package(self, analysis: RepositoryAnalysis) -> Package:
        """Create SPDX package for the repository itself."""
        repo_name = self._get_repo_name(analysis.repository_url)
        
        return Package(
            name=repo_name,
            version="unknown",
            spdx_id="SPDXRef-DOCUMENT",
            download_location=analysis.repository_url,
            files_analyzed=False,
            license_concluded="NOASSERTION",
            license_declared="NOASSERTION",
            copyright_text="NOASSERTION",
            description=f"Repository: {analysis.repository_url}"
        )
    
    def _create_package_from_dependency(self, dependency: Dependency) -> Package:
        """Convert a Dependency to an SPDX Package."""
        # Generate SPDX ID
        safe_name = self._make_safe_spdx_id(dependency.name)
        spdx_id = f"SPDXRef-Package-{safe_name}-{dependency.version}"
        
        # Determine download location
        download_location = dependency.source_url or self._guess_download_location(dependency)
        
        return Package(
            name=dependency.name,
            version=dependency.version,
            spdx_id=spdx_id,
            download_location=download_location,
            files_analyzed=False,
            license_concluded=dependency.license or "NOASSERTION",
            license_declared=dependency.license or "NOASSERTION",
            copyright_text="NOASSERTION",
            homepage=dependency.homepage,
            description=dependency.description
        )
    
    def _make_safe_spdx_id(self, name: str) -> str:
        """Make a string safe for use in SPDX IDs."""
        # Replace invalid characters with hyphens
        safe_name = ""
        for char in name:
            if char.isalnum() or char in "-._":
                safe_name += char
            else:
                safe_name += "-"
        
        # Remove consecutive hyphens
        while "--" in safe_name:
            safe_name = safe_name.replace("--", "-")
        
        # Remove leading/trailing hyphens
        return safe_name.strip("-")
    
    def _guess_download_location(self, dependency: Dependency) -> str:
        """Guess the download location for a dependency based on package manager."""
        package_manager = dependency.package_manager.value
        
        if package_manager == "npm":
            return f"https://registry.npmjs.org/{dependency.name}/-/{dependency.name}-{dependency.version}.tgz"
        elif package_manager == "pip":
            return f"https://pypi.org/project/{dependency.name}/{dependency.version}/"
        elif package_manager == "maven":
            # Maven coordinates: groupId:artifactId
            if ":" in dependency.name:
                group_id, artifact_id = dependency.name.split(":", 1)
                group_path = group_id.replace(".", "/")
                return f"https://repo1.maven.org/maven2/{group_path}/{artifact_id}/{dependency.version}/"
        elif package_manager == "cargo":
            return f"https://crates.io/crates/{dependency.name}/{dependency.version}"
        elif package_manager == "go":
            return f"https://{dependency.name}@{dependency.version}"
        elif package_manager == "composer":
            return f"https://packagist.org/packages/{dependency.name}"
        elif package_manager == "nuget":
            return f"https://www.nuget.org/packages/{dependency.name}/{dependency.version}"
        
        return "NOASSERTION"
    
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
    
    def _generate_document_namespace(self, analysis: RepositoryAnalysis) -> str:
        """Generate SPDX document namespace."""
        repo_name = self._get_repo_name(analysis.repository_url)
        timestamp = analysis.scan_timestamp.strftime("%Y%m%d%H%M%S")
        return f"https://sbom-agent.example.com/{repo_name}/{timestamp}"
    
    async def serialize_to_json(self, report: SBOMReport) -> str:
        """
        Serialize SPDX SBOM report to JSON format.
        
        Args:
            report: SBOM report to serialize
            
        Returns:
            str: JSON representation of SPDX document
        """
        try:
            spdx_doc = {
                "spdxVersion": report.version,
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": report.document_name,
                "documentNamespace": report.document_namespace,
                "creationInfo": {
                    "created": report.creation_info.created.isoformat() + "Z",
                    "creators": report.creation_info.creators,
                    "licenseListVersion": report.creation_info.license_list_version
                },
                "packages": [
                    {
                        "SPDXID": pkg.spdx_id,
                        "name": pkg.name,
                        "versionInfo": pkg.version,
                        "downloadLocation": pkg.download_location,
                        "filesAnalyzed": pkg.files_analyzed,
                        "licenseConcluded": pkg.license_concluded,
                        "licenseDeclared": pkg.license_declared,
                        "copyrightText": pkg.copyright_text,
                        **({"homepage": pkg.homepage} if pkg.homepage else {}),
                        **({"description": pkg.description} if pkg.description else {})
                    }
                    for pkg in report.packages
                ],
                "relationships": [
                    {
                        "spdxElementId": rel.spdx_element_id,
                        "relationshipType": rel.relationship_type,
                        "relatedSpdxElement": rel.related_spdx_element,
                        **({"comment": rel.comment} if rel.comment else {})
                    }
                    for rel in report.relationships
                ]
            }
            
            return json.dumps(spdx_doc, indent=2, ensure_ascii=False)
            
        except Exception as e:
            raise SBOMGenerationError(f"Failed to serialize SPDX to JSON: {str(e)}") from e