"""Core data models for the SBOM Security Agent."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
from enum import Enum


class SeverityLevel(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class PackageManager(str, Enum):
    """Supported package managers."""
    NPM = "npm"
    PIP = "pip"
    MAVEN = "maven"
    GRADLE = "gradle"
    CARGO = "cargo"
    GO_MOD = "go"
    COMPOSER = "composer"
    NUGET = "nuget"


class SBOMFormat(str, Enum):
    """Supported SBOM formats."""
    SPDX = "SPDX"
    CYCLONE_DX = "CycloneDX"


@dataclass
class Dependency:
    """Represents a software dependency."""
    name: str
    version: str
    package_manager: PackageManager
    license: Optional[str] = None
    source_url: Optional[str] = None
    dependencies: List['Dependency'] = field(default_factory=list)
    file_path: str = ""
    description: Optional[str] = None
    homepage: Optional[str] = None
    
    def __post_init__(self) -> None:
        """Validate dependency data after initialization."""
        if not self.name:
            raise ValueError("Dependency name cannot be empty")
        if not self.version:
            raise ValueError("Dependency version cannot be empty")


@dataclass
class Vulnerability:
    """Represents a security vulnerability."""
    cve_id: Optional[str]
    advisory_id: str
    severity: SeverityLevel
    summary: str
    affected_versions: List[str] = field(default_factory=list)
    fixed_versions: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    
    def __post_init__(self) -> None:
        """Validate vulnerability data after initialization."""
        if not self.advisory_id:
            raise ValueError("Advisory ID cannot be empty")
        if not self.summary:
            raise ValueError("Vulnerability summary cannot be empty")


@dataclass
class RepositoryAnalysis:
    """Results of repository dependency analysis."""
    repository_url: str
    branch: str
    scan_timestamp: datetime
    dependencies: List[Dependency] = field(default_factory=list)
    package_managers: List[PackageManager] = field(default_factory=list)
    analysis_status: str = "pending"
    error_messages: List[str] = field(default_factory=list)
    total_dependencies: int = 0
    
    def __post_init__(self) -> None:
        """Update computed fields after initialization."""
        self.total_dependencies = len(self.dependencies)
        # Extract unique package managers from dependencies
        if self.dependencies:
            managers = {dep.package_manager for dep in self.dependencies}
            self.package_managers = list(managers)


@dataclass
class CreationInfo:
    """SBOM creation metadata."""
    created: datetime
    creators: List[str] = field(default_factory=lambda: ["Tool: SBOM Security Agent"])
    license_list_version: Optional[str] = None
    
    def __post_init__(self) -> None:
        """Set default creation timestamp if not provided."""
        if not self.created:
            self.created = datetime.utcnow()


@dataclass
class Package:
    """SBOM package representation."""
    name: str
    version: str
    spdx_id: str
    download_location: Optional[str] = None
    files_analyzed: bool = False
    license_concluded: Optional[str] = None
    license_declared: Optional[str] = None
    copyright_text: Optional[str] = None
    homepage: Optional[str] = None
    description: Optional[str] = None
    
    def __post_init__(self) -> None:
        """Generate SPDX ID if not provided."""
        if not self.spdx_id:
            # Create a valid SPDX identifier
            safe_name = self.name.replace("/", "-").replace("@", "")
            self.spdx_id = f"SPDXRef-Package-{safe_name}-{self.version}"


@dataclass
class Relationship:
    """SBOM relationship between packages."""
    spdx_element_id: str
    relationship_type: str
    related_spdx_element: str
    comment: Optional[str] = None


@dataclass
class SBOMReport:
    """Complete SBOM report."""
    format: SBOMFormat
    version: str
    creation_info: CreationInfo
    packages: List[Package] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    document_name: str = "SBOM Security Analysis Report"
    document_namespace: str = ""
    
    def __post_init__(self) -> None:
        """Set default values and validate report."""
        if not self.document_namespace:
            timestamp = self.creation_info.created.strftime("%Y%m%d%H%M%S")
            self.document_namespace = f"https://sbom-agent.example.com/{timestamp}"


@dataclass
class SecurityAnalysisResult:
    """Results of security vulnerability analysis."""
    repository_analysis: RepositoryAnalysis
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    risk_score: float = 0.0
    
    def __post_init__(self) -> None:
        """Calculate vulnerability statistics."""
        self.total_vulnerabilities = len(self.vulnerabilities)
        
        # Count vulnerabilities by severity
        severity_counts = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 0,
            SeverityLevel.MEDIUM: 0,
            SeverityLevel.LOW: 0,
        }
        
        for vuln in self.vulnerabilities:
            if vuln.severity in severity_counts:
                severity_counts[vuln.severity] += 1
        
        self.critical_count = severity_counts[SeverityLevel.CRITICAL]
        self.high_count = severity_counts[SeverityLevel.HIGH]
        self.medium_count = severity_counts[SeverityLevel.MEDIUM]
        self.low_count = severity_counts[SeverityLevel.LOW]
        
        # Calculate risk score (weighted by severity)
        self.risk_score = (
            self.critical_count * 10.0 +
            self.high_count * 7.0 +
            self.medium_count * 4.0 +
            self.low_count * 1.0
        )


@dataclass
class ExecutiveSummary:
    """Executive summary of security analysis."""
    repository_url: str
    scan_date: datetime
    total_dependencies: int
    total_vulnerabilities: int
    risk_score: float
    severity_breakdown: dict = field(default_factory=dict)
    top_recommendations: List[str] = field(default_factory=list)
    compliance_status: dict = field(default_factory=dict)
    
    def __post_init__(self) -> None:
        """Initialize default values."""
        if not self.severity_breakdown:
            self.severity_breakdown = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        
        if not self.compliance_status:
            self.compliance_status = {
                "overall_status": "needs_review",
                "standards_checked": ["NIST", "OWASP", "CIS"]
            }