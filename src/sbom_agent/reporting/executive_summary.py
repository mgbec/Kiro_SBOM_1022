"""Executive summary report generator."""

from datetime import datetime
from typing import Dict, List, Any
from urllib.parse import urlparse

from ..models import SecurityAnalysisResult, ExecutiveSummary, SeverityLevel
from ..exceptions import SBOMGenerationError


class ExecutiveSummaryGenerator:
    """Generates executive-level security summary reports."""
    
    def __init__(self):
        self.compliance_standards = ["NIST", "OWASP", "CIS", "ISO 27001"]
    
    async def generate_summary(self, security_result: SecurityAnalysisResult) -> ExecutiveSummary:
        """
        Generate executive summary from security analysis results.
        
        Args:
            security_result: Security analysis results
            
        Returns:
            ExecutiveSummary: Executive summary report
        """
        try:
            analysis = security_result.repository_analysis
            
            # Calculate severity breakdown
            severity_breakdown = {
                "critical": security_result.critical_count,
                "high": security_result.high_count,
                "medium": security_result.medium_count,
                "low": security_result.low_count
            }
            
            # Generate top recommendations
            recommendations = await self._generate_recommendations(security_result)
            
            # Assess compliance status
            compliance_status = await self._assess_compliance(security_result)
            
            summary = ExecutiveSummary(
                repository_url=analysis.repository_url,
                scan_date=analysis.scan_timestamp,
                total_dependencies=analysis.total_dependencies,
                total_vulnerabilities=security_result.total_vulnerabilities,
                risk_score=security_result.risk_score,
                severity_breakdown=severity_breakdown,
                top_recommendations=recommendations,
                compliance_status=compliance_status
            )
            
            return summary
            
        except Exception as e:
            raise SBOMGenerationError(f"Failed to generate executive summary: {str(e)}") from e
    
    async def _generate_recommendations(self, security_result: SecurityAnalysisResult) -> List[str]:
        """Generate top recommendations based on security analysis."""
        recommendations = []
        
        # Critical vulnerabilities
        if security_result.critical_count > 0:
            recommendations.append(
                f"IMMEDIATE ACTION REQUIRED: {security_result.critical_count} critical vulnerabilities "
                f"identified that require immediate patching to prevent potential security breaches."
            )
        
        # High severity vulnerabilities
        if security_result.high_count > 0:
            recommendations.append(
                f"HIGH PRIORITY: {security_result.high_count} high-severity vulnerabilities should be "
                f"addressed within 7 days to maintain security posture."
            )
        
        # Risk score assessment
        if security_result.risk_score > 50:
            recommendations.append(
                f"ELEVATED RISK: Current risk score of {security_result.risk_score:.1f} indicates "
                f"significant security exposure. Implement comprehensive vulnerability management program."
            )
        elif security_result.risk_score > 20:
            recommendations.append(
                f"MODERATE RISK: Risk score of {security_result.risk_score:.1f} suggests need for "
                f"proactive security measures and regular dependency updates."
            )
        
        # Dependency management
        if security_result.repository_analysis.total_dependencies > 100:
            recommendations.append(
                f"DEPENDENCY MANAGEMENT: With {security_result.repository_analysis.total_dependencies} "
                f"dependencies, implement automated dependency scanning and update policies."
            )
        
        # General security practices
        if security_result.total_vulnerabilities > 0:
            recommendations.append(
                "SECURITY PRACTICES: Establish regular security audits, implement CI/CD security gates, "
                "and maintain an inventory of all software components."
            )
        else:
            recommendations.append(
                "MAINTAIN VIGILANCE: No vulnerabilities currently detected. Continue regular scanning "
                "and maintain current security practices."
            )
        
        return recommendations[:5]  # Limit to top 5 recommendations
    
    async def _assess_compliance(self, security_result: SecurityAnalysisResult) -> Dict[str, Any]:
        """Assess compliance status against security standards."""
        compliance_status = {
            "overall_status": "compliant",
            "standards_checked": self.compliance_standards,
            "findings": [],
            "recommendations": []
        }
        
        # NIST Cybersecurity Framework assessment
        nist_findings = []
        if security_result.critical_count > 0:
            nist_findings.append("Critical vulnerabilities present - violates NIST 'Protect' function")
            compliance_status["overall_status"] = "non_compliant"
        
        if security_result.high_count > 5:
            nist_findings.append("High number of high-severity vulnerabilities - requires immediate attention")
            compliance_status["overall_status"] = "needs_attention"
        
        if nist_findings:
            compliance_status["findings"].extend(nist_findings)
        
        # OWASP Top 10 assessment
        owasp_findings = []
        if security_result.total_vulnerabilities > 0:
            owasp_findings.append("Vulnerable dependencies identified - relates to OWASP A06:2021 Vulnerable Components")
        
        if owasp_findings:
            compliance_status["findings"].extend(owasp_findings)
        
        # CIS Controls assessment
        cis_findings = []
        if not self._has_inventory_control(security_result):
            cis_findings.append("Software inventory management needed - CIS Control 2")
        
        if security_result.total_vulnerabilities > 0:
            cis_findings.append("Vulnerability management process required - CIS Control 7")
        
        if cis_findings:
            compliance_status["findings"].extend(cis_findings)
        
        # Generate compliance recommendations
        if compliance_status["overall_status"] != "compliant":
            compliance_status["recommendations"] = [
                "Implement automated vulnerability scanning in CI/CD pipeline",
                "Establish vulnerability management policy with defined SLAs",
                "Create software bill of materials (SBOM) for all applications",
                "Regular security assessments and penetration testing",
                "Staff training on secure development practices"
            ]
        
        return compliance_status
    
    def _has_inventory_control(self, security_result: SecurityAnalysisResult) -> bool:
        """Check if proper software inventory control is in place."""
        # This is a simplified check - in practice, you'd have more sophisticated logic
        return security_result.repository_analysis.total_dependencies > 0
    
    async def format_executive_summary(self, summary: ExecutiveSummary) -> str:
        """
        Format executive summary as readable text report.
        
        Args:
            summary: Executive summary data
            
        Returns:
            str: Formatted executive summary report
        """
        repo_name = self._extract_repo_name(summary.repository_url)
        
        report = f"""
# EXECUTIVE SECURITY SUMMARY

## Repository: {repo_name}
**Scan Date:** {summary.scan_date.strftime('%Y-%m-%d %H:%M:%S UTC')}
**Repository URL:** {summary.repository_url}

## SECURITY OVERVIEW

**Risk Score:** {summary.risk_score:.1f}/100
**Total Dependencies:** {summary.total_dependencies:,}
**Total Vulnerabilities:** {summary.total_vulnerabilities:,}

### Vulnerability Breakdown
- 🔴 **Critical:** {summary.severity_breakdown['critical']} vulnerabilities
- 🟠 **High:** {summary.severity_breakdown['high']} vulnerabilities  
- 🟡 **Medium:** {summary.severity_breakdown['medium']} vulnerabilities
- 🟢 **Low:** {summary.severity_breakdown['low']} vulnerabilities

## KEY RECOMMENDATIONS

"""
        
        for i, recommendation in enumerate(summary.top_recommendations, 1):
            report += f"{i}. {recommendation}\n\n"
        
        report += f"""
## COMPLIANCE STATUS

**Overall Status:** {summary.compliance_status['overall_status'].replace('_', ' ').title()}
**Standards Assessed:** {', '.join(summary.compliance_status['standards_checked'])}

"""
        
        if summary.compliance_status.get('findings'):
            report += "### Compliance Findings\n"
            for finding in summary.compliance_status['findings']:
                report += f"- {finding}\n"
            report += "\n"
        
        if summary.compliance_status.get('recommendations'):
            report += "### Compliance Recommendations\n"
            for rec in summary.compliance_status['recommendations']:
                report += f"- {rec}\n"
            report += "\n"
        
        report += f"""
## NEXT STEPS

1. **Immediate Actions:** Address all critical and high-severity vulnerabilities
2. **Short-term (1-4 weeks):** Implement automated security scanning
3. **Medium-term (1-3 months):** Establish comprehensive vulnerability management program
4. **Long-term (3-12 months):** Achieve and maintain compliance with security standards

---
*Report generated by SBOM Security Agent on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}*
"""
        
        return report.strip()
    
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