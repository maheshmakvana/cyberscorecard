"""Security assessment engine for cyberscorecard."""
from __future__ import annotations

import logging
from typing import Dict, List, Optional

from cyberscorecard.exceptions import AssessmentError
from cyberscorecard.models import (
    ControlDomain,
    ControlStatus,
    DomainScore,
    MaturityLevel,
    RiskFinding,
    SecurityControl,
    SecurityScorecard,
    Severity,
)

logger = logging.getLogger(__name__)

# Severity weights for score calculation
_SEVERITY_WEIGHTS: Dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    Severity.INFO: 0.1,
}

# Domain weights (must sum to 1.0)
_DOMAIN_WEIGHTS: Dict[ControlDomain, float] = {
    ControlDomain.ACCESS_CONTROL: 0.15,
    ControlDomain.DATA_PROTECTION: 0.15,
    ControlDomain.NETWORK_SECURITY: 0.12,
    ControlDomain.ENDPOINT_SECURITY: 0.10,
    ControlDomain.INCIDENT_RESPONSE: 0.10,
    ControlDomain.VULNERABILITY_MANAGEMENT: 0.10,
    ControlDomain.BACKUP_RECOVERY: 0.10,
    ControlDomain.SECURITY_AWARENESS: 0.08,
    ControlDomain.THIRD_PARTY_RISK: 0.05,
    ControlDomain.COMPLIANCE: 0.05,
}

# CIS Controls v8 baseline for SMBs (IG1)
CIS_IG1_CONTROLS: List[Dict] = [
    {"control_id": "CIS-1.1", "domain": ControlDomain.ENDPOINT_SECURITY, "title": "Establish and Maintain Detailed Enterprise Asset Inventory", "description": "Maintain an accurate, detailed inventory of all enterprise assets.", "severity": Severity.HIGH, "frameworks": ["CIS Controls v8"], "remediation_steps": ["Deploy asset discovery tool", "Schedule quarterly inventory reviews"]},
    {"control_id": "CIS-2.1", "domain": ControlDomain.ENDPOINT_SECURITY, "title": "Establish and Maintain a Software Inventory", "description": "Maintain an inventory of all licensed software.", "severity": Severity.HIGH, "frameworks": ["CIS Controls v8"], "remediation_steps": ["Deploy software inventory tool", "Remove unauthorized software"]},
    {"control_id": "CIS-3.3", "domain": ControlDomain.DATA_PROTECTION, "title": "Configure Data Access Control Lists", "description": "Configure data access control lists based on a user's need to know.", "severity": Severity.CRITICAL, "frameworks": ["CIS Controls v8"], "remediation_steps": ["Audit file share permissions", "Apply least-privilege ACLs"]},
    {"control_id": "CIS-4.1", "domain": ControlDomain.ACCESS_CONTROL, "title": "Establish and Maintain a Secure Configuration Process", "description": "Establish and maintain a secure configuration process for enterprise assets.", "severity": Severity.HIGH, "frameworks": ["CIS Controls v8"], "remediation_steps": ["Define secure baseline configs", "Automate config compliance checks"]},
    {"control_id": "CIS-5.2", "domain": ControlDomain.ACCESS_CONTROL, "title": "Use Unique Passwords", "description": "Use unique passwords for all enterprise assets.", "severity": Severity.CRITICAL, "frameworks": ["CIS Controls v8"], "remediation_steps": ["Deploy password manager", "Enforce password policy via GPO/MDM"]},
    {"control_id": "CIS-5.4", "domain": ControlDomain.ACCESS_CONTROL, "title": "Restrict Administrator Privileges to Dedicated Admin Accounts", "description": "Restrict administrator privileges to dedicated admin accounts.", "severity": Severity.CRITICAL, "frameworks": ["CIS Controls v8"], "remediation_steps": ["Create separate admin accounts", "Remove admin rights from daily-use accounts"]},
    {"control_id": "CIS-6.3", "domain": ControlDomain.ACCESS_CONTROL, "title": "Require MFA for Externally-Exposed Applications", "description": "Require MFA for all externally-exposed enterprise applications.", "severity": Severity.CRITICAL, "frameworks": ["CIS Controls v8"], "remediation_steps": ["Enable MFA on email and VPN", "Enforce MFA via IdP policy"]},
    {"control_id": "CIS-7.1", "domain": ControlDomain.VULNERABILITY_MANAGEMENT, "title": "Establish and Maintain a Vulnerability Management Process", "description": "Establish and maintain a documented vulnerability management process.", "severity": Severity.HIGH, "frameworks": ["CIS Controls v8"], "remediation_steps": ["Subscribe to CVE feeds", "Schedule monthly patch cycles"]},
    {"control_id": "CIS-8.2", "domain": ControlDomain.BACKUP_RECOVERY, "title": "Perform Automated Backups", "description": "Perform automated backups of in-scope enterprise assets.", "severity": Severity.HIGH, "frameworks": ["CIS Controls v8"], "remediation_steps": ["Configure automated daily backups", "Test restoration quarterly"]},
    {"control_id": "CIS-9.4", "domain": ControlDomain.NETWORK_SECURITY, "title": "Restrict Unnecessary or Unauthorized Network Services", "description": "Restrict network services on assets to only those required for operation.", "severity": Severity.MEDIUM, "frameworks": ["CIS Controls v8"], "remediation_steps": ["Audit open ports with nmap", "Block unused services in firewall"]},
    {"control_id": "CIS-14.1", "domain": ControlDomain.SECURITY_AWARENESS, "title": "Establish and Maintain a Security Awareness Program", "description": "Establish a security awareness program for all employees.", "severity": Severity.MEDIUM, "frameworks": ["CIS Controls v8"], "remediation_steps": ["Launch phishing simulation", "Run annual security training"]},
    {"control_id": "CIS-17.1", "domain": ControlDomain.INCIDENT_RESPONSE, "title": "Designate Personnel to Manage Incident Handling", "description": "Designate one or more personnel to manage incident handling.", "severity": Severity.HIGH, "frameworks": ["CIS Controls v8"], "remediation_steps": ["Assign incident response owner", "Document IR runbook"]},
]


def build_default_controls() -> List[SecurityControl]:
    return [SecurityControl(**c) for c in CIS_IG1_CONTROLS]


def _maturity_from_score(score: float) -> MaturityLevel:
    if score < 20:
        return MaturityLevel.INITIAL
    if score < 40:
        return MaturityLevel.DEVELOPING
    if score < 65:
        return MaturityLevel.DEFINED
    if score < 85:
        return MaturityLevel.MANAGED
    return MaturityLevel.OPTIMIZED


class SecurityAssessor:
    """Assess an organization's security posture against CIS Controls."""

    def __init__(self, controls: Optional[List[SecurityControl]] = None) -> None:
        self._controls = controls or build_default_controls()

    def _score_domain(self, domain: ControlDomain, controls: List[SecurityControl]) -> DomainScore:
        domain_controls = [c for c in controls if c.domain == domain]
        if not domain_controls:
            return DomainScore(domain=domain, score=0.0, maturity=MaturityLevel.INITIAL)

        total_weight = sum(_SEVERITY_WEIGHTS[c.severity] for c in domain_controls)
        earned = 0.0
        implemented = 0
        partial = 0
        critical_gaps = 0

        for c in domain_controls:
            w = _SEVERITY_WEIGHTS[c.severity]
            if c.status in (ControlStatus.IMPLEMENTED, ControlStatus.NOT_APPLICABLE):
                earned += w
                implemented += 1
            elif c.status == ControlStatus.PARTIAL:
                earned += w * 0.5
                partial += 1
            elif c.status == ControlStatus.NOT_IMPLEMENTED and c.severity in (Severity.CRITICAL, Severity.HIGH):
                critical_gaps += 1

        raw_score = (earned / total_weight * 100) if total_weight > 0 else 0.0
        return DomainScore(
            domain=domain,
            score=round(raw_score, 1),
            maturity=_maturity_from_score(raw_score),
            controls_total=len(domain_controls),
            controls_implemented=implemented,
            controls_partial=partial,
            critical_gaps=critical_gaps,
        )

    def _generate_findings(self, controls: List[SecurityControl]) -> List[RiskFinding]:
        findings: List[RiskFinding] = []
        for ctrl in controls:
            if ctrl.status in (ControlStatus.NOT_IMPLEMENTED, ControlStatus.PARTIAL):
                findings.append(RiskFinding(
                    finding_id=f"FINDING-{ctrl.control_id}",
                    control_id=ctrl.control_id,
                    domain=ctrl.domain,
                    severity=ctrl.severity,
                    title=f"{'Gap' if ctrl.status == ControlStatus.NOT_IMPLEMENTED else 'Partial'}: {ctrl.title}",
                    description=ctrl.description,
                    remediation="; ".join(ctrl.remediation_steps) if ctrl.remediation_steps else "See control documentation",
                    effort="low" if ctrl.severity == Severity.LOW else "medium",
                ))
        return sorted(findings, key=lambda f: list(Severity).index(f.severity))

    def assess(
        self,
        org_id: str,
        org_name: str,
        control_responses: Dict[str, ControlStatus],
        frameworks: Optional[List[str]] = None,
    ) -> SecurityScorecard:
        """
        Run a security assessment.

        Args:
            org_id: Organization identifier.
            org_name: Display name.
            control_responses: Map of control_id → ControlStatus (user answers).
            frameworks: Optional framework tags (e.g. ['CIS Controls v8']).
        """
        controls = [c.model_copy() for c in self._controls]
        for ctrl in controls:
            if ctrl.control_id in control_responses:
                ctrl.status = control_responses[ctrl.control_id]
                ctrl.score = {
                    ControlStatus.IMPLEMENTED: 1.0,
                    ControlStatus.PARTIAL: 0.5,
                    ControlStatus.NOT_IMPLEMENTED: 0.0,
                    ControlStatus.NOT_APPLICABLE: 1.0,
                }.get(ctrl.status, 0.0)

        domain_scores: List[DomainScore] = []
        for domain in ControlDomain:
            domain_scores.append(self._score_domain(domain, controls))

        overall = sum(
            ds.score * _DOMAIN_WEIGHTS.get(ds.domain, 0.0)
            for ds in domain_scores
        )

        findings = self._generate_findings(controls)

        scorecard = SecurityScorecard(
            org_id=org_id,
            org_name=org_name,
            overall_score=round(overall, 1),
            maturity=_maturity_from_score(overall),
            domain_scores=domain_scores,
            findings=findings,
            controls=controls,
            frameworks=frameworks or ["CIS Controls v8"],
        )
        logger.info(
            "Assessment complete for %s: score=%.1f maturity=%s findings=%d",
            org_id, overall, scorecard.maturity.value, len(findings),
        )
        return scorecard
