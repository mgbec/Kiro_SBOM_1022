"""Multi-format report export manager."""

import json
import csv
import io
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from urllib.parse import urlparse

from ..models import SecurityAnalysisResult, ExecutiveSummary
from ..config import Config
from ..exceptions import SBOMGenerationError


class ExportManager:
    """Manages export of reports in multiple formats."""
    
    def __init__(self):
        self.supported_formats = Config.SUPPORTED_EXPORT_FORMATS
    
    async def export_report(
        self,
        data: Union[Dict[str, Any], SecurityAnalysisResult, ExecutiveSummary],
        format: str,
        report_type: str = "security_analysis"
    ) -> Dict[str, Any]:
        """
        Export report in specified format.
        
        Args:
            data: Report data to export
            format: Export format (json, csv, html, pdf)
            report_type: Type of report (security_analysis, executive_summary, sbom)
            
        Returns:
            Dict[str, Any]: Export result with content and metadata
        """
        if format not in self.supported_formats:
            raise SBOMGenerationError(f"Unsupported export format: {format}")
        
        try:
            if format == "json":
                return await self._export_json(data, report_type)
            elif format == "csv":
                return await self._export_csv(data, report_type)
            elif format == "html":
                return await self._export_html(data, report_type)
            elif format == "pdf":
                return await self._export_pdf(data, report_type)
            else:
                raise SBOMGenerationError(f"Export format {format} not implemented")
                
        except Exception as e:
            raise SBOMGenerationError(f"Failed to export report as {format}: {str(e)}") from e
    
    async def _export_json(self, data: Any, report_type: str) -> Dict[str, Any]:
        """Export report as JSON."""
        if isinstance(data, dict):
            json_data = data
        elif hasattr(data, '__dict__'):
            # Convert dataclass or object to dict
            json_data = self._serialize_object(data)
        else:
            json_data = {"data": str(data)}
        
        # Add export metadata
        json_data["export_metadata"] = {
            "format": "json",
            "report_type": report_type,
            "exported_at": datetime.utcnow().isoformat() + "Z",
            "exporter": "SBOM Security Agent"
        }
        
        content = json.dumps(json_data, indent=2, ensure_ascii=False, default=str)
        
        return {
            "format": "json",
            "content": content,
            "filename": f"{report_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
            "mime_type": "application/json",
            "size_bytes": len(content.encode('utf-8'))
        }
    
    async def _export_csv(self, data: Any, report_type: str) -> Dict[str, Any]:
        """Export report as CSV."""
        output = io.StringIO()
        
        if isinstance(data, dict) and "vulnerabilities" in data:
            # Security report with vulnerabilities
            await self._write_vulnerabilities_csv(data, output)
        elif isinstance(data, SecurityAnalysisResult):
            # Security analysis result
            await self._write_security_analysis_csv(data, output)
        elif isinstance(data, dict) and "dependencies" in data:
            # SBOM or dependency data
            await self._write_dependencies_csv(data, output)
        else:
            # Generic data export
            await self._write_generic_csv(data, output)
        
        content = output.getvalue()
        output.close()
        
        return {
            "format": "csv",
            "content": content,
            "filename": f"{report_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
            "mime_type": "text/csv",
            "size_bytes": len(content.encode('utf-8'))
        }
    
    async def _write_vulnerabilities_csv(self, data: Dict[str, Any], output: io.StringIO) -> None:
        """Write vulnerabilities data to CSV."""
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            "Vulnerability ID", "CVE ID", "Severity", "Summary", 
            "Affected Versions", "Fixed Versions", "Published Date", "References"
        ])
        
        # Write vulnerability data
        vulnerabilities = data.get("vulnerabilities", {})
        for severity in ["critical", "high", "medium", "low"]:
            for vuln in vulnerabilities.get(severity, []):
                writer.writerow([
                    vuln.get("id", ""),
                    vuln.get("cve_id", ""),
                    severity.upper(),
                    vuln.get("summary", ""),
                    "; ".join(vuln.get("affected_versions", [])),
                    "; ".join(vuln.get("fixed_versions", [])),
                    vuln.get("published_date", ""),
                    "; ".join(vuln.get("references", []))
                ])
    
    async def _write_security_analysis_csv(self, data: SecurityAnalysisResult, output: io.StringIO) -> None:
        """Write security analysis result to CSV."""
        writer = csv.writer(output)
        
        # Write summary information
        writer.writerow(["Security Analysis Summary"])
        writer.writerow(["Repository", data.repository_analysis.repository_url])
        writer.writerow(["Total Dependencies", data.repository_analysis.total_dependencies])
        writer.writerow(["Total Vulnerabilities", data.total_vulnerabilities])
        writer.writerow(["Risk Score", f"{data.risk_score:.1f}"])
        writer.writerow([])
        
        # Write vulnerability details
        writer.writerow([
            "Vulnerability ID", "CVE ID", "Severity", "Summary", 
            "Affected Versions", "Fixed Versions", "Published Date"
        ])
        
        for vuln in data.vulnerabilities:
            writer.writerow([
                vuln.advisory_id,
                vuln.cve_id or "",
                vuln.severity.value,
                vuln.summary,
                "; ".join(vuln.affected_versions),
                "; ".join(vuln.fixed_versions),
                vuln.published_date.isoformat() if vuln.published_date else ""
            ])
    
    async def _write_dependencies_csv(self, data: Dict[str, Any], output: io.StringIO) -> None:
        """Write dependencies data to CSV."""
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            "Name", "Version", "Package Manager", "License", 
            "Source URL", "File Path", "Description"
        ])
        
        # Write dependency data
        dependencies = data.get("dependencies", [])
        for dep in dependencies:
            writer.writerow([
                dep.get("name", ""),
                dep.get("version", ""),
                dep.get("package_manager", ""),
                dep.get("license", ""),
                dep.get("source_url", ""),
                dep.get("file_path", ""),
                dep.get("description", "")
            ])
    
    async def _write_generic_csv(self, data: Any, output: io.StringIO) -> None:
        """Write generic data to CSV."""
        writer = csv.writer(output)
        
        if isinstance(data, dict):
            # Write key-value pairs
            writer.writerow(["Key", "Value"])
            for key, value in data.items():
                writer.writerow([key, str(value)])
        else:
            # Write single value
            writer.writerow(["Data"])
            writer.writerow([str(data)])
    
    async def _export_html(self, data: Any, report_type: str) -> Dict[str, Any]:
        """Export report as HTML."""
        html_content = await self._generate_html_report(data, report_type)
        
        return {
            "format": "html",
            "content": html_content,
            "filename": f"{report_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html",
            "mime_type": "text/html",
            "size_bytes": len(html_content.encode('utf-8'))
        }
    
    async def _generate_html_report(self, data: Any, report_type: str) -> str:
        """Generate HTML report content."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SBOM Security Report - {report_type.replace('_', ' ').title()}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
        .header {{ background-color: #f4f4f4; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .summary {{ background-color: #e8f4fd; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; font-weight: bold; }}
        .low {{ color: #388e3c; font-weight: bold; }}
        .vulnerability {{ border: 1px solid #ddd; padding: 15px; margin-bottom: 10px; border-radius: 5px; }}
        .vulnerability h3 {{ margin-top: 0; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 0.9em; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SBOM Security Analysis Report</h1>
        <p><strong>Report Type:</strong> {report_type.replace('_', ' ').title()}</p>
        <p><strong>Generated:</strong> {timestamp}</p>
    </div>
"""
        
        if isinstance(data, dict):
            if "summary" in data:
                # Security report
                html += await self._generate_security_html(data)
            elif "vulnerabilities" in data:
                # Vulnerability data
                html += await self._generate_vulnerability_html(data)
            else:
                # Generic data
                html += await self._generate_generic_html(data)
        else:
            html += await self._generate_generic_html({"data": str(data)})
        
        html += f"""
    <div class="footer">
        <p>Report generated by SBOM Security Agent on {timestamp}</p>
    </div>
</body>
</html>
"""
        
        return html
    
    async def _generate_security_html(self, data: Dict[str, Any]) -> str:
        """Generate HTML for security report data."""
        summary = data.get("summary", {})
        vulnerabilities = data.get("vulnerabilities", {})
        
        html = f"""
    <div class="summary">
        <h2>Executive Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Dependencies</td><td>{summary.get('total_dependencies', 0):,}</td></tr>
            <tr><td>Total Vulnerabilities</td><td>{summary.get('total_vulnerabilities', 0):,}</td></tr>
            <tr><td>Risk Score</td><td>{summary.get('risk_score', 0):.1f}/100</td></tr>
        </table>
        
        <h3>Vulnerability Breakdown</h3>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            <tr><td class="critical">Critical</td><td>{summary.get('severity_counts', {}).get('critical', 0)}</td></tr>
            <tr><td class="high">High</td><td>{summary.get('severity_counts', {}).get('high', 0)}</td></tr>
            <tr><td class="medium">Medium</td><td>{summary.get('severity_counts', {}).get('medium', 0)}</td></tr>
            <tr><td class="low">Low</td><td>{summary.get('severity_counts', {}).get('low', 0)}</td></tr>
        </table>
    </div>
"""
        
        # Add vulnerability details
        for severity in ["critical", "high", "medium", "low"]:
            severity_vulns = vulnerabilities.get(severity, [])
            if severity_vulns:
                html += f'<h2 class="{severity}">{severity.title()} Vulnerabilities</h2>\n'
                for vuln in severity_vulns[:10]:  # Limit to top 10
                    html += f"""
    <div class="vulnerability">
        <h3>{vuln.get('id', 'Unknown')}</h3>
        <p><strong>Summary:</strong> {vuln.get('summary', 'No summary available')}</p>
        {f"<p><strong>CVE ID:</strong> {vuln['cve_id']}</p>" if vuln.get('cve_id') else ""}
        {f"<p><strong>Fixed Versions:</strong> {', '.join(vuln['fixed_versions'])}</p>" if vuln.get('fixed_versions') else ""}
    </div>
"""
        
        return html
    
    async def _generate_vulnerability_html(self, data: Dict[str, Any]) -> str:
        """Generate HTML for vulnerability data."""
        vulnerabilities = data.get("vulnerabilities", [])
        
        html = "<h2>Vulnerabilities</h2>\n"
        
        for vuln in vulnerabilities:
            html += f"""
    <div class="vulnerability">
        <h3>{vuln.get('id', 'Unknown')}</h3>
        <p><strong>Severity:</strong> <span class="{vuln.get('severity', 'unknown').lower()}">{vuln.get('severity', 'Unknown')}</span></p>
        <p><strong>Summary:</strong> {vuln.get('summary', 'No summary available')}</p>
    </div>
"""
        
        return html
    
    async def _generate_generic_html(self, data: Dict[str, Any]) -> str:
        """Generate HTML for generic data."""
        html = "<h2>Report Data</h2>\n<table>\n<tr><th>Key</th><th>Value</th></tr>\n"
        
        for key, value in data.items():
            html += f"<tr><td>{key}</td><td>{str(value)}</td></tr>\n"
        
        html += "</table>\n"
        return html
    
    async def _export_pdf(self, data: Any, report_type: str) -> Dict[str, Any]:
        """Export report as PDF (placeholder implementation)."""
        # Note: PDF generation would require additional dependencies like reportlab or weasyprint
        # For now, we'll return a placeholder
        
        pdf_content = f"""PDF Report Generation Not Implemented
        
Report Type: {report_type}
Generated: {datetime.utcnow().isoformat()}

To implement PDF export, install additional dependencies:
- pip install reportlab
- or pip install weasyprint

Then implement PDF generation logic in this method.
"""
        
        return {
            "format": "pdf",
            "content": pdf_content,
            "filename": f"{report_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt",
            "mime_type": "text/plain",
            "size_bytes": len(pdf_content.encode('utf-8')),
            "note": "PDF generation not implemented - returning text placeholder"
        }
    
    def _serialize_object(self, obj: Any) -> Dict[str, Any]:
        """Serialize object to dictionary for JSON export."""
        if hasattr(obj, '__dict__'):
            result = {}
            for key, value in obj.__dict__.items():
                if hasattr(value, '__dict__'):
                    result[key] = self._serialize_object(value)
                elif isinstance(value, list):
                    result[key] = [self._serialize_object(item) if hasattr(item, '__dict__') else item for item in value]
                elif isinstance(value, datetime):
                    result[key] = value.isoformat()
                else:
                    result[key] = value
            return result
        else:
            return {"value": str(obj)}
    
    def get_supported_formats(self) -> List[str]:
        """Get list of supported export formats."""
        return self.supported_formats.copy()
    
    async def create_download_info(self, export_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create download information for exported report.
        
        Args:
            export_result: Result from export_report method
            
        Returns:
            Dict[str, Any]: Download information
        """
        return {
            "filename": export_result["filename"],
            "format": export_result["format"],
            "mime_type": export_result["mime_type"],
            "size_bytes": export_result["size_bytes"],
            "size_human": self._format_file_size(export_result["size_bytes"]),
            "download_url": f"/download/{export_result['filename']}",  # Placeholder URL
            "expires_at": (datetime.utcnow().timestamp() + 3600),  # 1 hour expiry
            "created_at": datetime.utcnow().isoformat() + "Z"
        }
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"