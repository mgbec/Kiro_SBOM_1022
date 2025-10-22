"""
SBOM Security Agent - Main application entry point.

This agent analyzes GitHub repositories to generate Software Bill of Materials (SBOM) 
reports and performs comprehensive security vulnerability analysis.
"""

import asyncio
import json
import os
from typing import Optional

from bedrock_agentcore import BedrockAgentCoreApp
from bedrock_agentcore.identity.auth import requires_access_token
from strands import Agent

from src.sbom_agent.auth import auth_manager, authenticate_github, needs_authentication
from src.sbom_agent.config import Config, SYSTEM_PROMPTS
from src.sbom_agent.streaming import StreamingQueue, stream_with_error_handling
from src.sbom_agent.dependency_analyzer import DependencyAnalyzer
from src.sbom_agent.sbom_generator import SBOMGenerator
from src.sbom_agent.vulnerability import VulnerabilityScanner
from src.sbom_agent.reporting import ExecutiveSummaryGenerator, SecurityReportGenerator, ExportManager
from src.sbom_agent.models import SBOMFormat
from src.sbom_agent.tools import (
    analyze_repository, generate_sbom_report, scan_vulnerabilities,
    generate_security_report, export_report, get_supported_package_managers,
    get_agent_capabilities
)

# Environment configuration
os.environ["STRANDS_OTEL_ENABLE_CONSOLE_EXPORT"] = "true"
os.environ["OTEL_PYTHON_EXCLUDED_URLS"] = "/ping,/invocations"

# Initialize AgentCore app
app = BedrockAgentCoreApp()

# Initialize components
dependency_analyzer = DependencyAnalyzer()
sbom_generator = SBOMGenerator()
vulnerability_scanner = VulnerabilityScanner()
executive_summary_generator = ExecutiveSummaryGenerator()
security_report_generator = SecurityReportGenerator()
export_manager = ExportManager()

# Initialize streaming queue
queue = StreamingQueue()


async def on_auth_url(url: str) -> None:
    """Callback for authentication URL during OAuth flow."""
    print(f"GitHub Authorization URL: {url}")
    await queue.put(f"🔐 Please visit this URL to authorize GitHub access: {url}")
    await queue.put("After authorization, I'll continue with your request.")


def extract_response_text(response) -> str:
    """Extract text content from agent response."""
    if isinstance(response.message, dict):
        content = response.message.get('content', [])
        if isinstance(content, list):
            return "".join(
                item.get('text', '') for item in content 
                if isinstance(item, dict) and 'text' in item
            )
    return str(response.message)


async def perform_comprehensive_analysis(repository_url: str, branch: str = "main") -> None:
    """Perform comprehensive repository analysis with all features."""
    try:
        await queue.put(f"🚀 Starting comprehensive analysis of {repository_url}")
        
        # Step 1: Analyze repository dependencies
        await queue.put("📊 Step 1: Analyzing repository dependencies...")
        analysis = await dependency_analyzer.analyze_repository(repository_url, branch, queue)
        
        if analysis.analysis_status != "completed":
            await queue.put(f"❌ Repository analysis failed: {', '.join(analysis.error_messages)}")
            return
        
        await queue.put(f"✅ Found {len(analysis.dependencies)} dependencies across {len(analysis.package_managers)} package managers")
        
        # Step 2: Generate SBOM reports
        await queue.put("📄 Step 2: Generating SBOM reports...")
        sbom_results = await sbom_generator.generate_both_formats(analysis, queue)
        
        await queue.put("✅ SBOM reports generated in both SPDX and CycloneDX formats")
        
        # Step 3: Scan for vulnerabilities
        await queue.put("🔍 Step 3: Scanning for security vulnerabilities...")
        security_result = await vulnerability_scanner.scan_vulnerabilities(analysis, queue)
        
        await queue.put(f"✅ Vulnerability scan complete: {security_result.total_vulnerabilities} vulnerabilities found")
        
        # Step 4: Generate reports
        await queue.put("📋 Step 4: Generating security reports...")
        
        # Executive summary
        executive_summary = await executive_summary_generator.generate_summary(security_result)
        exec_summary_text = await executive_summary_generator.format_executive_summary(executive_summary)
        
        # Detailed security report
        detailed_report = await security_report_generator.generate_detailed_report(security_result)
        detailed_report_text = await security_report_generator.format_security_report_text(detailed_report)
        
        await queue.put("✅ Security reports generated")
        
        # Step 5: Present results
        await queue.put("📊 Analysis Results Summary:")
        await queue.put(f"Repository: {repository_url}")
        await queue.put(f"Dependencies: {analysis.total_dependencies}")
        await queue.put(f"Vulnerabilities: {security_result.total_vulnerabilities}")
        await queue.put(f"Risk Score: {security_result.risk_score:.1f}/100")
        await queue.put(f"Critical: {security_result.critical_count}, High: {security_result.high_count}, Medium: {security_result.medium_count}, Low: {security_result.low_count}")
        
        # Provide executive summary
        await queue.put("\n" + "="*50)
        await queue.put("EXECUTIVE SUMMARY")
        await queue.put("="*50)
        await queue.put(exec_summary_text)
        
        # Offer export options
        await queue.put("\n" + "="*50)
        await queue.put("EXPORT OPTIONS")
        await queue.put("="*50)
        await queue.put("Reports can be exported in the following formats:")
        await queue.put("• JSON - Machine-readable format for integration")
        await queue.put("• CSV - Spreadsheet format for analysis")
        await queue.put("• HTML - Web-friendly format for sharing")
        await queue.put("• PDF - Professional format for documentation")
        
        await queue.put("🎉 Comprehensive analysis completed successfully!")
        
    except Exception as e:
        await queue.put(f"❌ Analysis failed: {str(e)}")
        print(f"Analysis error: {e}")


async def agent_task(user_message: str) -> None:
    """Execute agent task with authentication and analysis handling."""
    try:
        await queue.put("🤖 SBOM Security Agent starting...")
        
        # Set auth queue for streaming messages
        auth_manager.set_auth_queue(queue)
        
        # Initial agent call
        response = agent(user_message)
        response_text = extract_response_text(response)
        
        # Check if authentication is needed
        if needs_authentication(response_text) or not auth_manager.is_authenticated():
            await queue.put("🔐 GitHub authentication required. Starting OAuth2 flow...")
            
            try:
                await authenticate_github(access_token='')
                await queue.put("✅ GitHub authentication successful! Continuing with your request...")
                
                # Retry with authentication
                response = agent(user_message)
                response_text = extract_response_text(response)
                
            except Exception as auth_error:
                print(f"Authentication error: {auth_error}")
                await queue.put(f"❌ Authentication failed: {str(auth_error)}")
                return
        
        # Parse response for analysis requests
        try:
            response_data = json.loads(response_text)
            
            if response_data.get("status") == "starting_analysis":
                # Comprehensive analysis requested
                repo_url = response_data.get("repository_url")
                branch = response_data.get("branch", "main")
                await perform_comprehensive_analysis(repo_url, branch)
                
            elif response_data.get("status") == "starting_sbom_generation":
                # SBOM generation requested
                repo_url = response_data.get("repository_url")
                branch = response_data.get("branch", "main")
                format_type = response_data.get("format", "both")
                
                await queue.put(f"📄 Generating {format_type.upper()} SBOM for {repo_url}")
                
                # Analyze repository first
                analysis = await dependency_analyzer.analyze_repository(repo_url, branch, queue)
                
                if format_type.lower() == "both":
                    sbom_results = await sbom_generator.generate_both_formats(analysis, queue)
                elif format_type.lower() == "spdx":
                    sbom_results = await sbom_generator.generate_sbom(analysis, SBOMFormat.SPDX, queue)
                elif format_type.lower() == "cyclonedx":
                    sbom_results = await sbom_generator.generate_sbom(analysis, SBOMFormat.CYCLONE_DX, queue)
                
                await queue.put("✅ SBOM generation completed!")
                
            elif response_data.get("status") == "starting_vulnerability_scan":
                # Vulnerability scan requested
                repo_url = response_data.get("repository_url")
                branch = response_data.get("branch", "main")
                
                await queue.put(f"🔍 Scanning {repo_url} for vulnerabilities")
                
                # Analyze repository first
                analysis = await dependency_analyzer.analyze_repository(repo_url, branch, queue)
                security_result = await vulnerability_scanner.scan_vulnerabilities(analysis, queue)
                
                await queue.put(f"✅ Vulnerability scan completed: {security_result.total_vulnerabilities} vulnerabilities found")
                
            elif response_data.get("status") == "starting_security_report":
                # Security report requested
                repo_url = response_data.get("repository_url")
                branch = response_data.get("branch", "main")
                report_type = response_data.get("report_type", "detailed")
                
                await queue.put(f"📋 Generating {report_type} security report for {repo_url}")
                
                # Perform analysis
                analysis = await dependency_analyzer.analyze_repository(repo_url, branch, queue)
                security_result = await vulnerability_scanner.scan_vulnerabilities(analysis, queue)
                
                if report_type.lower() in ["executive", "both"]:
                    executive_summary = await executive_summary_generator.generate_summary(security_result)
                    exec_text = await executive_summary_generator.format_executive_summary(executive_summary)
                    await queue.put("\n" + exec_text)
                
                if report_type.lower() in ["detailed", "both"]:
                    detailed_report = await security_report_generator.generate_detailed_report(security_result)
                    detailed_text = await security_report_generator.format_security_report_text(detailed_report)
                    await queue.put("\n" + detailed_text)
                
                await queue.put("✅ Security report generation completed!")
                
            else:
                # Regular agent response
                await queue.put(response_text)
                
        except json.JSONDecodeError:
            # Not JSON response, treat as regular text
            await queue.put(response_text)
        
        await queue.put("✨ Task completed successfully!")
        
    except Exception as e:
        await queue.put(f"❌ Error: {str(e)}")
        print(f"Agent task error: {e}")
    finally:
        await queue.finish()


# Create agent instance with tools
agent = Agent(
    model=Config.CLAUDE_MODEL,
    tools=[
        analyze_repository,
        generate_sbom_report, 
        scan_vulnerabilities,
        generate_security_report,
        export_report,
        get_supported_package_managers,
        get_agent_capabilities
    ],
    system_prompt=SYSTEM_PROMPTS["main"]
)


@app.entrypoint
async def agent_invocation(payload):
    """Main entrypoint for agent invocation."""
    user_message = payload.get(
        "prompt", 
        "Hello! I'm the SBOM Security Agent. I can help you analyze GitHub repositories for dependencies, generate SBOM reports, and perform security vulnerability analysis. What would you like me to help you with?"
    )
    
    # Create and start the agent task
    task = asyncio.create_task(agent_task(user_message))
    
    async def stream_with_task():
        """Stream results while ensuring task completion."""
        async for item in queue.stream():
            yield item
        await task  # Ensure task completes
    
    return stream_with_task()


if __name__ == "__main__":
    app.run()