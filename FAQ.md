# Frequently Asked Questions - SBOM Security Agent

## General Questions

### What is an SBOM?
**SBOM** stands for "Software Bill of Materials." Think of it like an ingredient list for your software - it shows all the components, libraries, and packages your project uses, along with their versions and sources.

### Why do I need security analysis?
Modern software uses many third-party components that can have security vulnerabilities. Regular security analysis helps you:
- Find and fix security problems before they're exploited
- Meet compliance requirements
- Protect your organization and customers
- Make informed decisions about software risks

### Is this safe to use with my private code?
Yes! The agent:
- Only analyzes dependency files (like package.json, requirements.txt)
- Never reads or stores your actual source code
- Uses secure, encrypted connections
- Follows enterprise security standards
- Only needs read-only access to repositories

## Using the Agent

### What repositories can I analyze?
- **Public GitHub repositories**: Anyone can analyze these
- **Private repositories**: You must own them or have access
- **Organization repositories**: You need appropriate permissions
- **Any programming language**: The agent supports 8+ package managers

### How long does analysis take?
- **Small projects** (< 50 dependencies): 1-2 minutes
- **Medium projects** (50-200 dependencies): 3-5 minutes  
- **Large projects** (200+ dependencies): 5-15 minutes
- **Very large projects**: May take longer, but you'll see progress updates

### What if I get authentication errors?
Try these steps:
1. Make sure you're signed in to GitHub
2. Click the authorization link again
3. Check that you have access to the repository
4. For organization repositories, you may need admin approval

### Can I analyze multiple repositories?
Yes! You can analyze as many repositories as you want. Just provide each repository URL when requested.

## Understanding Results

### What does "Critical" vulnerability mean?
Critical vulnerabilities are severe security flaws that:
- Could allow attackers to take control of your system
- Are easy to exploit
- Have known attack methods
- **Need immediate attention** (fix within 24 hours)

### Should I worry about "Low" severity issues?
Low severity vulnerabilities are less urgent but still worth addressing:
- They represent potential security improvements
- May become more serious over time
- Good to fix during regular maintenance
- Help maintain overall security hygiene

### What if I have hundreds of vulnerabilities?
This is actually common and manageable:
1. **Start with Critical and High severity** issues first
2. **Many can be fixed easily** by updating package versions
3. **Focus on vulnerabilities that affect your specific use case**
4. **The agent provides prioritized action plans**

### How accurate are the vulnerability reports?
The agent uses multiple authoritative sources:
- **OSV Database**: Comprehensive open-source vulnerability data
- **GitHub Security Advisories**: GitHub's curated security information
- **National Vulnerability Database**: Government-maintained CVE database
- Results are cross-referenced for accuracy

## Technical Questions

### What programming languages are supported?
The agent analyzes dependencies for:
- **JavaScript/Node.js** (npm, yarn)
- **Python** (pip, pipenv, poetry)
- **Java** (Maven, Gradle)
- **Rust** (Cargo)
- **Go** (Go modules)
- **PHP** (Composer)
- **.NET** (NuGet)
- **More languages** being added regularly

### What formats can I export reports in?
- **JSON**: For integration with other tools
- **CSV**: For spreadsheet analysis
- **HTML**: For web viewing and sharing
- **PDF**: For professional documentation (coming soon)

### Can I integrate this with my existing tools?
Yes! The agent provides:
- **Standard SBOM formats** (SPDX, CycloneDX) that work with most security tools
- **JSON exports** for custom integrations
- **API-friendly outputs** for automation

## Compliance and Governance

### Does this help with regulatory compliance?
Yes! The agent helps with:
- **Executive Order 14028** (US Federal SBOM requirements)
- **EU Cyber Resilience Act** preparation
- **ISO 27001** security management
- **NIST Cybersecurity Framework** alignment
- **SOC 2** security controls

### Can I share these reports with auditors?
Absolutely! The reports are designed for:
- **Internal security teams**
- **External auditors**
- **Compliance officers**
- **Executive leadership**
- **Regulatory bodies**

### How often should I run analysis?
**Recommended schedule:**
- **Active development**: Weekly
- **Production systems**: Monthly
- **Before releases**: Always
- **After security alerts**: As needed
- **Compliance audits**: Quarterly

## Troubleshooting

### The agent says "Repository not found"
Check these items:
- Is the repository URL correct?
- Is the repository public, or do you have access?
- Are you signed in to the right GitHub account?
- For organization repos, do you have the right permissions?

### Analysis failed or stopped
Common causes and solutions:
- **Network issues**: Try again in a few minutes
- **Large repository**: Be patient, it may take longer
- **Rate limiting**: Wait and try again later
- **Repository issues**: Check if the repository has dependency files

### I don't understand the technical details
That's okay! The agent provides:
- **Executive summaries** in plain language
- **Risk scores** instead of technical jargon
- **Clear action items** with priorities
- **Explanations** when you ask for them

### Can I get help interpreting results?
Yes! Just ask the agent:
- "What does this vulnerability mean?"
- "How serious is this issue?"
- "What should I do first?"
- "Explain this in simple terms"

## Getting More Help

### Who can I contact for support?
- **Ask the agent directly** - it can explain most issues
- **Your IT or security team** for organization-specific guidance
- **GitHub support** for repository access issues
- **Your compliance team** for regulatory questions

### Where can I learn more about security?
- **NIST Cybersecurity Framework**: cybersecurity guidance
- **OWASP**: web application security resources
- **SANS**: security training and resources
- **Your organization's security policies**

---

*Still have questions? Just ask the SBOM Security Agent - it's designed to help users at all technical levels!*