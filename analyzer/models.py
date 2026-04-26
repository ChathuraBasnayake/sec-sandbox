"""Pydantic data models for threat analysis verdicts."""

from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class Category(str, Enum):
    CREDENTIAL_THEFT = "credential_theft"
    DATA_EXFILTRATION = "data_exfiltration"
    REVERSE_SHELL = "reverse_shell"
    RECON = "recon"
    PERSISTENCE = "persistence"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


class Finding(BaseModel):
    """A single security finding from the analysis."""
    severity: Severity
    category: Category
    description: str
    evidence: str


class ThreatVerdict(BaseModel):
    """Complete threat analysis verdict for a detonated package."""
    package_name: str
    detonation_id: str
    threat_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    findings: list[Finding] = []
    recommendation: str
    analyzed_at: datetime = Field(default_factory=datetime.now)
    analysis_method: str = "hybrid"  # "rules", "llm", or "hybrid"
    events_analyzed: int = 0
    execve_count: int = 0
    openat_count: int = 0


class SyscallEvent(BaseModel):
    """A single syscall event from the Kafka telemetry stream."""
    package_name: str
    container_id: str
    detonation_id: str
    pid: int
    ppid: int
    timestamp_ns: int
    event_type: str  # "EXECVE" or "OPENAT"
    process_name: str
    filename: str
    captured_at: str
