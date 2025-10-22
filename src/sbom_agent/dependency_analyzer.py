"""Unified dependency analysis interface."""

from datetime import datetime
from typing import Dict, List

from .github_client import GitHubClient
from .models import RepositoryAnalysis, Dependency, PackageManager
from .parsers import (
    NPMParser, PipParser, MavenParser, GradleParser, 
    CargoParser, GoModParser, ComposerParser, NuGetParser
)
from .exceptions import DependencyParsingError, RepositoryAccessError
from .streaming import StreamingQueue, ProgressTracker


class DependencyAnalyzer:
    """Analyzes repositories for dependencies across multiple package managers."""
    
    def __init__(self):
        self.github_client = GitHubClient()
        self.parsers = {
            PackageManager.NPM: NPMParser(),
            PackageManager.PIP: PipParser(),
            PackageManager.MAVEN: MavenParser(),
            PackageManager.GRADLE: GradleParser(),
            PackageManager.CARGO: CargoParser(),
            PackageManager.GO_MOD: GoModParser(),
            PackageManager.COMPOSER: ComposerParser(),
            PackageManager.NUGET: NuGetParser(),
        }
    
    async def analyze_repository(
        self, 
        repo_url: str, 
        branch: str = "main",
        queue: StreamingQueue = None
    ) -> RepositoryAnalysis:
        """
        Analyze a GitHub repository for dependencies.
        
        Args:
            repo_url: GitHub repository URL
            branch: Git branch to analyze
            queue: Optional streaming queue for progress updates
            
        Returns:
            RepositoryAnalysis: Analysis results
        """
        progress = ProgressTracker(queue, total_steps=100) if queue else None
        
        try:
            if progress:
                await progress.update(10, "Validating repository access")
            
            # Validate repository access
            if not await self.github_client.validate_repository_access(repo_url):
                raise RepositoryAccessError(f"Cannot access repository: {repo_url}")
            
            if progress:
                await progress.update(20, "Finding dependency files")
            
            # Find dependency files
            dependency_files = await self.github_client.find_dependency_files(repo_url, branch)
            
            if not dependency_files:
                if queue:
                    await queue.put("No dependency files found in repository")
                
                return RepositoryAnalysis(
                    repository_url=repo_url,
                    branch=branch,
                    scan_timestamp=datetime.utcnow(),
                    analysis_status="completed",
                    error_messages=["No dependency files found"]
                )
            
            if progress:
                await progress.update(30, f"Found {sum(len(files) for files in dependency_files.values())} dependency files")
            
            # Parse dependencies
            all_dependencies = []
            total_files = sum(len(files) for files in dependency_files.values())
            processed_files = 0
            
            for pkg_manager, files in dependency_files.items():
                parser = self.parsers.get(PackageManager(pkg_manager))
                if not parser:
                    continue
                
                for file_path in files:
                    try:
                        if progress:
                            progress_pct = 30 + (processed_files / total_files) * 50
                            await progress.update(int(progress_pct), f"Parsing {file_path}")
                        
                        # Get file content
                        content = await self.github_client.get_file_content(repo_url, file_path, branch)
                        
                        # Parse dependencies
                        dependencies = await parser.parse(content, file_path)
                        all_dependencies.extend(dependencies)
                        
                        if queue:
                            await queue.put(f"✅ Parsed {len(dependencies)} dependencies from {file_path}")
                        
                    except Exception as e:
                        error_msg = f"Failed to parse {file_path}: {str(e)}"
                        if queue:
                            await queue.put(f"⚠️ {error_msg}")
                        print(error_msg)
                    
                    processed_files += 1
            
            if progress:
                await progress.update(90, "Finalizing analysis")
            
            # Create analysis result
            analysis = RepositoryAnalysis(
                repository_url=repo_url,
                branch=branch,
                scan_timestamp=datetime.utcnow(),
                dependencies=all_dependencies,
                analysis_status="completed"
            )
            
            if progress:
                await progress.complete(f"Analysis complete: {len(all_dependencies)} dependencies found")
            
            if queue:
                await queue.put(f"🎉 Repository analysis completed successfully!")
                await queue.put(f"📊 Found {len(all_dependencies)} dependencies across {len(analysis.package_managers)} package managers")
            
            return analysis
            
        except Exception as e:
            error_msg = f"Repository analysis failed: {str(e)}"
            if queue:
                await queue.put(f"❌ {error_msg}")
            
            return RepositoryAnalysis(
                repository_url=repo_url,
                branch=branch,
                scan_timestamp=datetime.utcnow(),
                analysis_status="failed",
                error_messages=[error_msg]
            )
    
    def get_supported_package_managers(self) -> List[str]:
        """Get list of supported package managers."""
        return [pm.value for pm in self.parsers.keys()]
    
    def get_parser_for_file(self, filename: str) -> str:
        """
        Get the appropriate parser for a given filename.
        
        Args:
            filename: Name of the dependency file
            
        Returns:
            str: Package manager name or None if not supported
        """
        for pkg_manager, parser in self.parsers.items():
            if parser.can_parse(filename):
                return pkg_manager.value
        return None