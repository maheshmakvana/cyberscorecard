"""Data models for cyberscorecard — SMB cybersecurity governance."""
from __future__ import annotations

import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


class ControlDomain(str, Enum):
    ACCESS_CONTROL = "access_control"
    DATA_PROTECTION = "data_protection"
    NETWORK_SECURITY = "network_security"
    ENDPOINT_SECURITY = "endpoint_security"
    INCIDENT_RESPONSE = "incident_response"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    BACKUP_RECOVERY = "backup_recovery"
    SECURITY_AWARENESS = "security_awareness"
    THIRD_PARTY_RISK = "third_party_risk"
    COMPLIANCE = "compliance"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MaturityLevel(str, Enum):
    INITIAL = "initial"        # 1 — ad hoc, reactive
    DEVELOPING = "developing"  # 2 — some processes in place
    DEFINED = "defined"        # 3 — documented, repeatable
    MANAGED = "managed"        # 4 — measured and controlled
    OPTIMIZED = "optimized"    # 5 — continuous improvement


class ControlStatus(str, Enum):
    NOT_IMPLEMENTED = "not_implemented"
    PARTIAL = "partial"
    IMPLEMENTED = "implemented"
    NOT_APPLICABLE = "not_applicable"


class SecurityControl(BaseModel):
    """A single security control to be assessed."""

    control_id: str
    domain: ControlDomain
    title: str
    description: str
    severity: Severity
    status: ControlStatus = ControlStatus.NOT_IMPLEMENTED
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence: str = ""
    remediation_steps: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)  # CIS, NIST, ISO 27001
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("control_id", "title")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Field must not be empty")
        return v.strip()


class RiskFinding(BaseModel):
    """A security risk finding from assessment."""

    finding_id: str
    control_id: str
    domain: ControlDomain
    severity: Severity
    title: str
    description: str
    remediation: str
    effort: str = "medium"       # low, medium, high
    cost_estimate: str = "unknown"
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DomainScore(BaseModel):
    """Score for a single security domain."""

    domain: ControlDomain
    score: float = Field(ge=0.0, le=100.0)
    maturity: MaturityLevel
    controls_total: int = 0
    controls_implemented: int = 0
    controls_partial: int = 0
    critical_gaps: int = 0


class SecurityScorecard(BaseModel):
    """Full security scorecard for an organization."""

    org_id: str
    org_name: str
    overall_score: float = Field(ge=0.0, le=100.0)
    maturity: MaturityLevel
    domain_scores: List[DomainScore] = Field(default_factory=list)
    findings: List[RiskFinding] = Field(default_factory=list)
    controls: List[SecurityControl] = Field(default_factory=list)
    assessed_at: datetime = Field(default_factory=datetime.utcnow)
    next_review: Optional[datetime] = None
    frameworks: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def critical_findings(self) -> List[RiskFinding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    def summary(self) -> Dict[str, Any]:
        return {
            "org_id": self.org_id,
            "overall_score": round(self.overall_score, 1),
            "maturity": self.maturity.value,
            "critical_findings": len(self.critical_findings()),
            "total_findings": len(self.findings),
            "assessed_at": self.assessed_at.isoformat(),
        }
