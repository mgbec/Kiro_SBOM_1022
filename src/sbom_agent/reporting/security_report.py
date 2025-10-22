"""Detailed security report generator."""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

from ..models import SecurityAnalysisResult, Vulnerability, SeverityLevel
from ..exceptions import SBOMGenerationError


class SecurityReportGenerator:
    """Generates detailed security analysis reports."""
    
    def __init__(self):
        pass
    
    async def generate_detailed_report(self, security_result: SecurityAnalysisResult) -> Dict[str, Any]:
        """
        Generate comprehensive security report.
        
        Args:
            security_result: Security analysis results
            
        Returns:
            Dict[str, Any]: Detailed security report
        """
        try:
            analysis = security_result.repository_analysis
            
            # Group vulnerabilities by severity
            vulnerabilities_by_severity = self._group_vulnerabilities_by_severity(security_result.vulnerabilities)
            
            # Generate dependency analysis
            dependency_analysis = await self._analyze_dependencies(analysis)
            
            # Generate remediation plan
            remediation_plan = await self._generate_remediation_plan(security_result.vulnerabilities)
            
            # Create detailed report
            report = {
                "metadata": {
                    "report_type": "detailed_security_analysis",
                    "generated_at": datetime.utcnow().isoformat() + "Z",
                    "repository_url": analysis.repository_url,
                    "branch": analysis.branch,
                    "scan_timestamp": analysis.scan_timestamp.isoformat() + "Z",
                    "agent_version": "0.1.0"
                },
                "summary": {
                    "total_dependencies": analysis.total_dependencies,
                    "total_vulnerabilities": security_result.total_vulnerabilities,
                    "risk_score": security_result.risk_score,
                    "severity_counts": {
                        "critical": security_result.critical_count,
                        "high": security_result.high_count,
                        "medium": security_result.medium_count,
                        "low": security_result.low_count
                    },
                    "package_managers": [pm.value for pm in analysis.package_managers]
                },
                "dependency_analysis": dependency_analysis,
                "vulnerabilities": {
                    "critical": [self._format_vulnerability(v) for v in vulnerabilities_by_severity[SeverityLevel.CRITICAL]],
                    "high": [self._format_vulnerability(v) for v in vulnerabilities_by_severity[SeverityLevel.HIGH]],
                    "medium": [self._format_vulnerability(v) for v in vulnerabilities_by_severity[SeverityLevel.MEDIUM]],
                    "low": [self._format_vulnerability(v) for v in vulnerabilities_by_severity[SeverityLevel.LOW]]
                },
                "remediation_plan": remediation_plan,
                "recommendations": await self._generate_detailed_recommendations(security_result)
            }
            
            return report
            
        except Exception as e:
            raise SBOMGenerationError(f"Failed to generate detailed security report: {str(e)}") from e
    
    def _group_vulnerabilities_by_severity(self, vulnerabilities: List[Vulnerability]) -> Dict[SeverityLevel, List[Vulnerability]]:
        """Group vulnerabilities by severity level."""
        groups = {
            SeverityLevel.CRITICAL: [],
            SeverityLevel.HIGH: [],
            SeverityLevel.MEDIUM: [],
            SeverityLevel.LOW: [],
            SeverityLevel.UNKNOWN: []
        }
        
        for vuln in vulnerabilities:
            groups[vuln.severity].append(vuln)
        
        return groups
    
    async def _analyze_dependencies(self, analysis) -> Dict[str, Any]:
        """Analyze dependency patterns and risks."""
        dependency_stats = {}
        
        # Count dependencies by package manager
        pm_counts = {}
        for dep in analysis.dependencies:
            pm = dep.package_manager.value
            pm_counts[pm] = pm_counts.get(pm, 0) + 1
        
        # Identify potentially risky dependencies
        risky_patterns = []
        for dep in analysis.dependencies:
            if dep.version == "unknown":
                risky_patterns.append(f"Unknown version for {dep.name}")
            elif "dev" in dep.version.lower() or "beta" in dep.version.lower():
                risky_patterns.append(f"Pre-release version: {dep.name}@{dep.version}")
        
        dependency_stats = {
            "package_manager_distribution": pm_counts,
            "total_unique_dependencies": len(analysis.dependencies),
            "risky_patterns": risky_patterns[:10],  # Limit to top 10
            "dependency_files_analyzed": len(set(dep.file_path for dep in analysis.dependencies))
        }
        
        return dependency_stats
    
    async def _generate_remediation_plan(self, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Generate detailed remediation plan."""
        plan = {
            "immediate_actions": [],
            "short_term_actions": [],
            "long_term_actions": [],
            "estimated_effort": "TBD"
        }
        
        # Group by severity for remediation planning
        critical_vulns = [v for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL]
        high_vulns = [v for v in vulnerabilities if v.severity == SeverityLevel.HIGH]
        medium_vulns = [v for v in vulnerabilities if v.severity == SeverityLevel.MEDIUM]
        
        # Immediate actions (Critical vulnerabilities)
        if critical_vulns:
            plan["immediate_actions"].extend([
                {
                    "action": "Emergency Patch Deployment",
                    "description": f"Immediately update {len(critical_vulns)} dependencies with critical vulnerabilities",
                    "timeline": "Within 24 hours",
                    "affected_vulnerabilities": [v.advisory_id for v in critical_vulns[:5]]
                },
                {
                    "action": "Security Incident Response",
                    "description": "Activate incident response procedures and assess potential impact",
                    "timeline": "Immediate",
                    "affected_vulnerabilities": []
                }
            ])
        
        # Short-term actions (High vulnerabilities)
        if high_vulns:
            plan["short_term_actions"].extend([
                {
                    "action": "High-Priority Updates",
                    "description": f"Update {len(high_vulns)} dependencies with high-severity vulnerabilities",
                    "timeline": "Within 7 days",
                    "affected_vulnerabilities": [v.advisory_id for v in high_vulns[:5]]
                },
                {
                    "action": "Security Testing",
                    "description": "Perform security testing after updates to ensure no regressions",
                    "timeline": "Within 14 days",
                    "affected_vulnerabilities": []
                }
            ])
        
        # Long-term actions
        if medium_vulns or vulnerabilities:
            plan["long_term_actions"].extend([
                {
                    "action": "Dependency Management Policy",
                    "description": "Establish formal dependency management and update policies",
                    "timeline": "Within 30 days",
                    "affected_vulnerabilities": []
                },
                {
                    "action": "Automated Security Scanning",
                    "description": "Implement automated vulnerability scanning in CI/CD pipeline",
                    "timeline": "Within 60 days",
                    "affected_vulnerabilities": []
                },
                {
                    "action": "Security Training",
                    "description": "Provide security training for development team on secure coding practices",
                    "timeline": "Within 90 days",
                    "affected_vulnerabilities": []
                }
            ])
        
        # Estimate effort
        total_vulns = len(vulnerabilities)
        if total_vulns == 0:
            plan["estimated_effort"] = "Low - Maintenance only"
        elif total_vulns < 10:
            plan["estimated_effort"] = "Medium - 1-2 weeks"
        elif total_vulns < 50:
            plan["estimated_effort"] = "High - 3-4 weeks"
        else:
            plan["estimated_effort"] = "Very High - 1-2 months"
        
        return plan
    
    async def _generate_detailed_recommendations(self, security_result: SecurityAnalysisResult) -> List[Dict[str, Any]]:
        """Generate detailed recommendations with specific actions."""
        recommendations = []
        
        # Vulnerability-specific recommendations
        if security_result.critical_count > 0:
            recommendations.append({
                "category": "Critical Vulnerabilities",
                "priority": "IMMEDIATE",
                "title": "Address Critical Security Vulnerabilities",
                "description": f"Your repository contains {security_result.critical_count} critical vulnerabilities that pose immediate security risks.",
                "actions": [
                    "Review all critical vulnerabilities and their impact",
                    "Update affected dependencies to patched versions",
                    "Test applications thoroughly after updates",
                    "Consider temporary mitigations if updates are not immediately available"
                ],
                "resources": [
                    "https://nvd.nist.gov/vuln/search",
                    "https://github.com/advisories"
                ]
            })
        
        if security_result.high_count > 0:
            recommendations.append({
                "category": "High-Severity Vulnerabilities",
                "priority": "HIGH",
                "title": "Update High-Risk Dependencies",
                "description": f"Address {security_result.high_count} high-severity vulnerabilities within one week.",
                "actions": [
                    "Prioritize high-severity vulnerabilities by exploitability",
                    "Create update schedule for affected dependencies",
                    "Implement regression testing for updated components",
                    "Monitor for new vulnerabilities in updated dependencies"
                ],
                "resources": [
                    "https://owasp.org/www-project-dependency-check/",
                    "https://snyk.io/vuln/"
                ]
            })
        
        # Process recommendations
        if security_result.repository_analysis.total_dependencies > 50:
            recommendations.append({
                "category": "Dependency Management",
                "priority": "MEDIUM",
                "title": "Implement Dependency Management Best Practices",
                "description": f"With {security_result.repository_analysis.total_dependencies} dependencies, establish formal dependency management processes.",
                "actions": [
                    "Create dependency inventory and ownership matrix",
                    "Establish dependency update policies and schedules",
                    "Implement automated dependency scanning",
                    "Set up dependency license compliance checking"
                ],
                "resources": [
                    "https://owasp.org/www-project-dependency-track/",
                    "https://cyclonedx.org/"
                ]
            })
        
        # Security practices recommendations
        recommendations.append({
            "category": "Security Practices",
            "priority": "ONGOING",
            "title": "Establish Continuous Security Monitoring",
            "description": "Implement ongoing security practices to prevent future vulnerabilities.",
            "actions": [
                "Integrate security scanning into CI/CD pipeline",
                "Set up automated alerts for new vulnerabilities",
                "Establish security review process for new dependencies",
                "Create incident response plan for security issues"
            ],
            "resources": [
                "https://owasp.org/www-project-devsecops-guideline/",
                "https://www.nist.gov/cyberframework"
            ]
        })
        
        return recommendations
    
    def _format_vulnerability(self, vulnerability: Vulnerability) -> Dict[str, Any]:
        """Format vulnerability for report output."""
        return {
            "id": vulnerability.cve_id or vulnerability.advisory_id,
            "cve_id": vulnerability.cve_id,
            "advisory_id": vulnerability.advisory_id,
            "severity": vulnerability.severity.value,
            "summary": vulnerability.summary,
            "affected_versions": vulnerability.affected_versions,
            "fixed_versions": vulnerability.fixed_versions,
            "references": vulnerability.references,
            "published_date": vulnerability.published_date.isoformat() + "Z" if vulnerability.published_date else None,
            "modified_date": vulnerability.modified_date.isoformat() + "Z" if vulnerability.modified_date else None
        }
    
    async def format_security_report_text(self, report: Dict[str, Any]) -> str:
        """
        Format detailed security report as readable text.
        
        Args:
            report: Detailed security report data
            
        Returns:
            str: Formatted text report
        """
        metadata = report["metadata"]
        summary = report["summary"]
        vulnerabilities = report["vulnerabilities"]
        
        repo_name = self._extract_repo_name(metadata["repository_url"])
        
        text_report = f"""
# DETAILED SECURITY ANALYSIS REPORT

## Repository Information
**Repository:** {repo_name}
**URL:** {metadata['repository_url']}
**Branch:** {metadata['branch']}
**Scan Date:** {datetime.fromisoformat(metadata['scan_timestamp'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S UTC')}

## Executive Summary
- **Total Dependencies:** {summary['total_dependencies']:,}
- **Total Vulnerabilities:** {summary['total_vulnerabilities']:,}
- **Risk Score:** {summary['risk_score']:.1f}/100
- **Package Managers:** {', '.join(summary['package_managers'])}

### Vulnerability Distribution
- 🔴 **Critical:** {summary['severity_counts']['critical']} vulnerabilities
- 🟠 **High:** {summary['severity_counts']['high']} vulnerabilities
- 🟡 **Medium:** {summary['severity_counts']['medium']} vulnerabilities
- 🟢 **Low:** {summary['severity_counts']['low']} vulnerabilities

"""
        
        # Add critical vulnerabilities section
        if vulnerabilities["critical"]:
            text_report += "## 🔴 CRITICAL VULNERABILITIES\n\n"
            for vuln in vulnerabilities["critical"][:10]:  # Limit to top 10
                text_report += f"### {vuln['id']}\n"
                text_report += f"**Summary:** {vuln['summary']}\n"
                if vuln['fixed_versions']:
                    text_report += f"**Fixed in:** {', '.join(vuln['fixed_versions'])}\n"
                text_report += "\n"
        
        # Add high vulnerabilities section
        if vulnerabilities["high"]:
            text_report += "## 🟠 HIGH-SEVERITY VULNERABILITIES\n\n"
            for vuln in vulnerabilities["high"][:10]:  # Limit to top 10
                text_report += f"### {vuln['id']}\n"
                text_report += f"**Summary:** {vuln['summary']}\n"
                if vuln['fixed_versions']:
                    text_report += f"**Fixed in:** {', '.join(vuln['fixed_versions'])}\n"
                text_report += "\n"
        
        # Add remediation plan
        remediation = report["remediation_plan"]
        text_report += "## REMEDIATION PLAN\n\n"
        text_report += f"**Estimated Effort:** {remediation['estimated_effort']}\n\n"
        
        if remediation["immediate_actions"]:
            text_report += "### Immediate Actions (24 hours)\n"
            for action in remediation["immediate_actions"]:
                text_report += f"- **{action['action']}:** {action['description']}\n"
            text_report += "\n"
        
        if remediation["short_term_actions"]:
            text_report += "### Short-term Actions (1-2 weeks)\n"
            for action in remediation["short_term_actions"]:
                text_report += f"- **{action['action']}:** {action['description']}\n"
            text_report += "\n"
        
        if remediation["long_term_actions"]:
            text_report += "### Long-term Actions (1-3 months)\n"
            for action in remediation["long_term_actions"]:
                text_report += f"- **{action['action']}:** {action['description']}\n"
            text_report += "\n"
        
        # Add recommendations
        text_report += "## DETAILED RECOMMENDATIONS\n\n"
        for rec in report["recommendations"]:
            text_report += f"### {rec['title']} ({rec['priority']})\n"
            text_report += f"{rec['description']}\n\n"
            text_report += "**Actions:**\n"
            for action in rec['actions']:
                text_report += f"- {action}\n"
            text_report += "\n"
        
        text_report += f"""
---
*Report generated by SBOM Security Agent v{metadata['agent_version']} on {metadata['generated_at']}*
"""
        
        return text_report.strip()
    
    def _extract_repo_name(self, repo_url: str) -> str:
        """Extract repository name from URL."""
        try:
            parsed = urlparse(repo_url)
            path_parts = parsed.path.strip("/").split("/")
            if len(path_parts) >= 2:
                return f"{path_parts[-2]}/{path_parts[-1]}"
            return path_parts[-1] if path_parts else "Unknown Repository"
        except Exception:
            return "Unknown Repository"