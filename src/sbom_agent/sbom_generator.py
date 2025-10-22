"""Unified SBOM generation interface."""

from typing import Dict, Any, Optional
from datetime import datetime

from .models import RepositoryAnalysis, SBOMFormat, SBOMReport
from .generators import SPDXGenerator, CycloneDXGenerator
from .exceptions import SBOMGenerationError
from .streaming import StreamingQueue, ProgressTracker


class SBOMGenerator:
    """Unified interface for generating SBOM reports in multiple formats."""
    
    def __init__(self):
        self.spdx_generator = SPDXGenerator()
        self.cyclonedx_generator = CycloneDXGenerator()
    
    async def generate_sbom(
        self,
        analysis: RepositoryAnalysis,
        format: SBOMFormat,
        queue: Optional[StreamingQueue] = None
    ) -> Dict[str, Any]:
        """
        Generate SBOM report in specified format.
        
        Args:
            analysis: Repository analysis results
            format: SBOM format to generate
            queue: Optional streaming queue for progress updates
            
        Returns:
            Dict[str, Any]: Generated SBOM document
        """
        progress = ProgressTracker(queue, total_steps=100) if queue else None
        
        try:
            if progress:
                await progress.update(10, f"Starting {format.value} SBOM generation")
            
            if not analysis.dependencies:
                if queue:
                    await queue.put("⚠️ No dependencies found to include in SBOM")
            
            if progress:
                await progress.update(30, f"Processing {len(analysis.dependencies)} dependencies")
            
            if format == SBOMFormat.SPDX:
                if progress:
                    await progress.update(50, "Generating SPDX format")
                
                report = await self.spdx_generator.generate(analysis)
                
                if progress:
                    await progress.update(80, "Serializing SPDX document")
                
                json_content = await self.spdx_generator.serialize_to_json(report)
                
                result = {
                    "format": "SPDX",
                    "version": report.version,
                    "document": json_content,
                    "metadata": {
                        "repository_url": analysis.repository_url,
                        "branch": analysis.branch,
                        "scan_timestamp": analysis.scan_timestamp.isoformat(),
                        "total_packages": len(report.packages),
                        "total_relationships": len(report.relationships)
                    }
                }
                
            elif format == SBOMFormat.CYCLONE_DX:
                if progress:
                    await progress.update(50, "Generating CycloneDX format")
                
                cyclonedx_doc = await self.cyclonedx_generator.generate(analysis)
                
                if progress:
                    await progress.update(80, "Serializing CycloneDX document")
                
                json_content = await self.cyclonedx_generator.serialize_to_json(cyclonedx_doc)
                
                result = {
                    "format": "CycloneDX",
                    "version": cyclonedx_doc["specVersion"],
                    "document": json_content,
                    "metadata": {
                        "repository_url": analysis.repository_url,
                        "branch": analysis.branch,
                        "scan_timestamp": analysis.scan_timestamp.isoformat(),
                        "total_components": len(cyclonedx_doc.get("components", [])),
                        "serial_number": cyclonedx_doc.get("serialNumber")
                    }
                }
            else:
                raise SBOMGenerationError(f"Unsupported SBOM format: {format}")
            
            if progress:
                await progress.complete(f"{format.value} SBOM generated successfully")
            
            if queue:
                await queue.put(f"✅ {format.value} SBOM generated successfully!")
                await queue.put(f"📄 Document contains {len(analysis.dependencies)} dependencies")
            
            return result
            
        except Exception as e:
            error_msg = f"SBOM generation failed: {str(e)}"
            if queue:
                await queue.put(f"❌ {error_msg}")
            raise SBOMGenerationError(error_msg) from e
    
    async def generate_both_formats(
        self,
        analysis: RepositoryAnalysis,
        queue: Optional[StreamingQueue] = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        Generate SBOM reports in both SPDX and CycloneDX formats.
        
        Args:
            analysis: Repository analysis results
            queue: Optional streaming queue for progress updates
            
        Returns:
            Dict[str, Dict[str, Any]]: Both SBOM documents
        """
        progress = ProgressTracker(queue, total_steps=100) if queue else None
        
        try:
            if progress:
                await progress.update(10, "Generating SBOM reports in both formats")
            
            # Generate SPDX
            if progress:
                await progress.update(25, "Generating SPDX format")
            
            spdx_result = await self.generate_sbom(analysis, SBOMFormat.SPDX)
            
            # Generate CycloneDX
            if progress:
                await progress.update(65, "Generating CycloneDX format")
            
            cyclonedx_result = await self.generate_sbom(analysis, SBOMFormat.CYCLONE_DX)
            
            if progress:
                await progress.complete("Both SBOM formats generated successfully")
            
            if queue:
                await queue.put("🎉 Generated SBOM reports in both SPDX and CycloneDX formats!")
            
            return {
                "spdx": spdx_result,
                "cyclonedx": cyclonedx_result
            }
            
        except Exception as e:
            error_msg = f"Multi-format SBOM generation failed: {str(e)}"
            if queue:
                await queue.put(f"❌ {error_msg}")
            raise SBOMGenerationError(error_msg) from e
    
    def get_supported_formats(self) -> list[str]:
        """Get list of supported SBOM formats."""
        return [format.value for format in SBOMFormat]
    
    async def validate_sbom(self, sbom_content: str, format: SBOMFormat) -> Dict[str, Any]:
        """
        Validate SBOM document format and structure.
        
        Args:
            sbom_content: SBOM document content
            format: Expected SBOM format
            
        Returns:
            Dict[str, Any]: Validation results
        """
        try:
            import json
            
            # Parse JSON
            try:
                doc = json.loads(sbom_content)
            except json.JSONDecodeError as e:
                return {
                    "valid": False,
                    "errors": [f"Invalid JSON format: {str(e)}"]
                }
            
            errors = []
            warnings = []
            
            if format == SBOMFormat.SPDX:
                # Basic SPDX validation
                required_fields = ["spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace"]
                for field in required_fields:
                    if field not in doc:
                        errors.append(f"Missing required SPDX field: {field}")
                
                # Check SPDX version
                if doc.get("spdxVersion") != "SPDX-2.3":
                    warnings.append(f"SPDX version {doc.get('spdxVersion')} may not be fully supported")
                
            elif format == SBOMFormat.CYCLONE_DX:
                # Basic CycloneDX validation
                required_fields = ["bomFormat", "specVersion", "serialNumber", "version"]
                for field in required_fields:
                    if field not in doc:
                        errors.append(f"Missing required CycloneDX field: {field}")
                
                # Check format
                if doc.get("bomFormat") != "CycloneDX":
                    errors.append("Invalid bomFormat, expected 'CycloneDX'")
            
            return {
                "valid": len(errors) == 0,
                "errors": errors,
                "warnings": warnings,
                "format": format.value,
                "component_count": len(doc.get("components", doc.get("packages", [])))
            }
            
        except Exception as e:
            return {
                "valid": False,
                "errors": [f"Validation error: {str(e)}"]
            }