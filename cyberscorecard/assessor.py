"""Security assessment engine for cyberscorecard."""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set

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

# Severity weights — used in domain score calculation
_SEVERITY_WEIGHTS: Dict[Severity, float] = {
    Severity.CRITICAL: 1.00,
    Severity.HIGH:     0.75,
    Severity.MEDIUM:   0.50,
    Severity.LOW:      0.25,
    Severity.INFO:     0.10,
}

# Domain weights — must sum to 1.0
_DOMAIN_WEIGHTS: Dict[ControlDomain, float] = {
    ControlDomain.ACCESS_CONTROL:          0.15,
    ControlDomain.DATA_PROTECTION:         0.15,
    ControlDomain.NETWORK_SECURITY:        0.12,
    ControlDomain.ENDPOINT_SECURITY:       0.10,
    ControlDomain.INCIDENT_RESPONSE:       0.10,
    ControlDomain.VULNERABILITY_MANAGEMENT: 0.10,
    ControlDomain.BACKUP_RECOVERY:         0.10,
    ControlDomain.SECURITY_AWARENESS:      0.08,
    ControlDomain.THIRD_PARTY_RISK:        0.05,
    ControlDomain.COMPLIANCE:              0.05,
}

# Evidence quality multipliers — high-quality evidence earns full control credit;
# controls with no evidence are capped even when marked Implemented.
_EVIDENCE_QUALITY_MULTIPLIER: Dict[str, float] = {
    "verified":    1.00,   # verified by assessor or tooling
    "documented":  0.90,   # documented but not independently verified
    "verbal":      0.70,   # claimed verbally — no artifact
    "none":        0.55,   # no evidence provided
}

# CIS Controls v8 baseline for SMBs (IG1)
CIS_IG1_CONTROLS: List[Dict] = [
    {
        "control_id": "CIS-1.1",
        "domain": ControlDomain.ENDPOINT_SECURITY,
        "title": "Establish and Maintain Detailed Enterprise Asset Inventory",
        "description": "Maintain an accurate, detailed inventory of all enterprise assets with asset type, owner, and network address.",
        "severity": Severity.HIGH,
        "frameworks": ["CIS Controls v8"],
        "remediation_steps": ["Deploy asset discovery tool (e.g., Lansweeper, Snipe-IT)", "Schedule quarterly inventory reviews", "Tag assets with owner and classification"],
    },
    {
        "control_id": "CIS-2.1",
        "domain": ControlDomain.ENDPOINT_SECURITY,
        "title": "Establish and Maintain a Software Inventory",
        "description": "Maintain an inventory of all licensed software installed on enterprise assets.",
        "severity": Severity.HIGH,
        "frameworks": ["CIS Controls v8"],
        "remediation_steps": ["Deploy software inventory tool (e.g., PDQ Inventory)", "Remove unauthorized or unlicensed software", "Block installation of unapproved software via MDM/GPO"],
    },
    {
        "control_id": "CIS-3.3",
        "domain": ControlDomain.DATA_PROTECTION,
        "title": "Configure Data Access Control Lists",
        "description": "Configure data access control lists based on a user's need to know. Apply least-privilege to all file shares and data stores.",
        "severity": Severity.CRITICAL,
        "frameworks": ["CIS Controls v8"],
        "remediation_steps": ["Audit all file share permissions and remove 'Everyone' access", "Apply least-privilege ACLs per role", "Enable access logging on sensitive data stores"],
    },
    {
        "control_id": "CIS-4.1",
        "domain": ControlDomain.ACCESS_CONTROL,
        "title": "Establish and Maintain a Secure Configuration Process",
        "description": "Establish and maintain a secure configuration process for enterprise assets and software.",
        "severity": Severity.HIGH,
        "frameworks": ["CIS Controls v8"],
        "remediation_steps": ["Define secure baseline configs (CIS Benchmarks)", "Automate config compliance checks with a tool (e.g., CIS-CAT)", "Document and review configurations quarterly"],
    },
    {
        "control_id": "CIS-5.2",
        "domain": ControlDomain.ACCESS_CONTROL,
        "title": "Use Unique Passwords",
        "description": "Use unique passwords for all enterprise assets and software. Enforce minimum password complexity.",
        "severity": Severity.CRITICAL,
        "frameworks": ["CIS Controls v8"],
        "remediation_steps": ["Deploy enterprise password manager (e.g., 1Password, Bitwarden Teams)", "Enforce minimum password policy via AD/Entra GPO or MDM", "Audit for shared or default credentials"],
    },
    {
        "control_id": "CIS-5.4",
        "domain": ControlDomain.ACCESS_CONTROL,
        "title": "Restrict Administrator Privileges to Dedicated Admin Accounts",
        "description": "Restrict administrator privileges to dedicated admin accounts. Daily-use accounts must not have local or domain admin rights.",
        "severity": Severity.CRITICAL,
        "frameworks": ["CIS Controls v8"],
        "remediation_steps": ["Create separate named admin accounts for all admins", "Remove local admin rights from standard user accounts via GPO/MDM", "Audit privileged group membership monthly"],
    },
    {
        "control_id": "CIS-6.3",
        "domain": ControlDomain.ACCESS_CONTROL,
        "title": "Require MFA for Externally-Exposed Applications",
        "description": "Require multi-factor authentication for all externally-exposed enterprise applications, including email, VPN, and remote access.",
        "severity": Severity.CRITICAL,
        "frameworks": ["CIS Controls v8"],
        "remediation_steps": ["Enable MFA on all cloud email and Microsoft 365 / Google Workspace accounts", "Enforce MFA via Conditional Access or IdP policy (Okta, Entra ID)", "Require hardware or app-based MFA — disable SMS where possible"],
    },
    {
        "control_id": "CIS-7.1",
        "domain": ControlDomain.VULNERABILITY_MANAGEMENT,
        "title": "Establish and Maintain a Vulnerability Management Process",
        "description": "Establish and maintain a documented, repeatable vulnerability management process including scan, remediate, and verify.",
        "severity": Severity.HIGH,
        "frameworks": ["CIS Controls v8"],
        "remediation_steps": ["Subscribe to CISA KEV and vendor CVE feeds", "Schedule monthly authenticated vulnerability scans", "Define SLA targets: critical=7d, high=30d, medium=90d"],
    },
    {
        "control_id": "CIS-8.2",
        "domain": ControlDomain.BACKUP_RECOVERY,
        "title": "Perform Automated Backups",
        "description": "Perform automated backups of in-scope enterprise assets. Maintain at least one offsite or cloud backup copy.",
        "severity": Severity.HIGH,
        "frameworks": ["CIS Controls v8"],
        "remediation_steps": ["Configure automated daily encrypted backups", "Maintain offsite or immutable cloud backup (3-2-1 rule)", "Test full restoration quarterly and document results"],
    },
    {
        "control_id": "CIS-9.4",
        "domain": ControlDomain.NETWORK_SECURITY,
        "title": "Restrict Unnecessary or Unauthorized Network Services",
        "description": "Restrict network services on assets to only those required for business operation. Block inbound access to unused ports.",
        "severity": Severity.MEDIUM,
        "frameworks": ["CIS Controls v8"],
        "remediation_steps": ["Audit open ports using authenticated network scan", "Block unused inbound services at perimeter firewall", "Disable or remove unnecessary network services on endpoints"],
    },
    {
        "control_id": "CIS-14.1",
        "domain": ControlDomain.SECURITY_AWARENESS,
        "title": "Establish and Maintain a Security Awareness Program",
        "description": "Establish a documented security awareness program covering all employees with at minimum annual training.",
        "severity": Severity.MEDIUM,
        "frameworks": ["CIS Controls v8"],
        "remediation_steps": ["Launch phishing simulation with a platform (e.g., KnowBe4, Proofpoint)", "Schedule annual security awareness training for all staff", "Track completion rates and re-train failures"],
    },
    {
        "control_id": "CIS-17.1",
        "domain": ControlDomain.INCIDENT_RESPONSE,
        "title": "Designate Personnel to Manage Incident Handling",
        "description": "Designate one or more personnel to manage incident handling. Document roles and escalation paths in a written IR plan.",
        "severity": Severity.HIGH,
        "frameworks": ["CIS Controls v8"],
        "remediation_steps": ["Assign a named incident response owner (internal or MSP)", "Document an IR runbook covering detection, containment, eradication, recovery", "Test the IR plan with a tabletop exercise annually"],
    },
]


def build_default_controls() -> List[SecurityControl]:
    """Return a list of SecurityControl objects based on the CIS IG1 baseline."""
    return [SecurityControl(**c) for c in CIS_IG1_CONTROLS]


def _maturity_from_score(score: float) -> MaturityLevel:
    """Map a numeric score to a MaturityLevel tier."""
    if score < 20:
        return MaturityLevel.INITIAL
    if score < 40:
        return MaturityLevel.DEVELOPING
    if score < 65:
        return MaturityLevel.DEFINED
    if score < 85:
        return MaturityLevel.MANAGED
    return MaturityLevel.OPTIMIZED


def _evidence_multiplier(control: SecurityControl) -> float:
    """Return an evidence quality multiplier for a control."""
    evidence_type = (control.evidence or "").lower().strip()
    if not evidence_type:
        return _EVIDENCE_QUALITY_MULTIPLIER["none"]
    for key in ("verified", "documented", "verbal"):
        if key in evidence_type:
            return _EVIDENCE_QUALITY_MULTIPLIER[key]
    # Any evidence string is treated as 'documented' if it's present
    return _EVIDENCE_QUALITY_MULTIPLIER["documented"]


class SecurityAssessor:
    """
    Assess an organization's security posture against CIS Controls v8 IG1.

    Improvements over the baseline scorer:
    - Evidence quality weighting: controls marked Implemented but without
      supporting evidence are scored at 55–90% of their full weight, preventing
      paper-compliant scorecards that inflate the overall score.
    - Criticality-first domain scoring: critical/high controls contribute
      proportionally more to the domain score than medium/low controls.
    - Incremental re-assessment: `reassess()` accepts only the changed responses,
      applies them to the last scorecard, and returns an updated scorecard with
      a diff of changed findings — without requiring a full re-run.
    - Finding prioritisation: findings are sorted by severity then by quick-win
      status (derived from effort estimate) so the remediation list is
      immediately actionable.
    """

    def __init__(self, controls: Optional[List[SecurityControl]] = None) -> None:
        self._controls = controls or build_default_controls()
        self._last_scorecard: Optional[SecurityScorecard] = None

    def _score_domain(self, domain: ControlDomain, controls: List[SecurityControl]) -> DomainScore:
        """Compute a domain score with severity weighting and evidence quality adjustment."""
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
            ev_mult = _evidence_multiplier(c)

            if c.status in (ControlStatus.IMPLEMENTED, ControlStatus.NOT_APPLICABLE):
                # Evidence quality adjusts the earned weight for implemented controls
                earned += w * ev_mult
                implemented += 1
            elif c.status == ControlStatus.PARTIAL:
                # Partial credit: 50% × evidence quality
                earned += w * 0.5 * ev_mult
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
        """
        Generate RiskFindings for all open/partial controls, sorted by:
        1. Severity (critical first)
        2. Quick-win status (low-effort items surface earlier)
        """
        findings: List[RiskFinding] = []
        severity_order = list(Severity)  # [CRITICAL, HIGH, MEDIUM, LOW, INFO]

        for ctrl in controls:
            if ctrl.status in (ControlStatus.NOT_IMPLEMENTED, ControlStatus.PARTIAL):
                # Estimate effort from severity and partial status
                if ctrl.severity in (Severity.CRITICAL, Severity.HIGH) and ctrl.status == ControlStatus.PARTIAL:
                    effort = "medium"
                elif ctrl.severity in (Severity.MEDIUM, Severity.LOW):
                    effort = "low"
                else:
                    effort = "high"

                findings.append(RiskFinding(
                    finding_id=f"FINDING-{ctrl.control_id}",
                    control_id=ctrl.control_id,
                    domain=ctrl.domain,
                    severity=ctrl.severity,
                    title=(
                        f"{'Gap' if ctrl.status == ControlStatus.NOT_IMPLEMENTED else 'Partial'}: "
                        f"{ctrl.title}"
                    ),
                    description=ctrl.description,
                    remediation=(
                        "; ".join(ctrl.remediation_steps)
                        if ctrl.remediation_steps
                        else "See CIS Controls documentation for implementation guidance."
                    ),
                    effort=effort,
                ))

        # Sort: severity first, then effort (low-effort = quick wins first)
        effort_order = {"low": 0, "medium": 1, "high": 2}
        return sorted(
            findings,
            key=lambda f: (severity_order.index(f.severity), effort_order.get(f.effort, 1)),
        )

    def assess(
        self,
        org_id: str,
        org_name: str,
        control_responses: Dict[str, ControlStatus],
        frameworks: Optional[List[str]] = None,
    ) -> SecurityScorecard:
        """
        Run a full security assessment.

        Args:
            org_id: Unique organization identifier.
            org_name: Display name of the organization.
            control_responses: Mapping of control_id → ControlStatus (user-provided answers).
                               Also accepts a nested dict with 'status' and 'evidence' keys
                               for evidence quality tracking:
                               {"CIS-5.2": {"status": ControlStatus.IMPLEMENTED, "evidence": "verified"}}
            frameworks: Optional list of compliance framework tags.
        """
        controls = [c.model_copy() for c in self._controls]

        for ctrl in controls:
            response = control_responses.get(ctrl.control_id)
            if response is None:
                continue

            # Support both simple ControlStatus and dict with evidence
            if isinstance(response, dict):
                status = response.get("status", ControlStatus.NOT_IMPLEMENTED)
                evidence = str(response.get("evidence", ""))
            else:
                status = response
                evidence = ctrl.evidence or ""

            ctrl.status = status
            ctrl.evidence = evidence
            ctrl.score = {
                ControlStatus.IMPLEMENTED:    1.0,
                ControlStatus.PARTIAL:        0.5,
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
        self._last_scorecard = scorecard
        logger.info(
            "Assessment complete for '%s': score=%.1f maturity=%s findings=%d critical_gaps=%d",
            org_id, overall, scorecard.maturity.value, len(findings),
            sum(ds.critical_gaps for ds in domain_scores),
        )
        return scorecard

    def reassess(
        self,
        changed_responses: Dict[str, ControlStatus],
    ) -> SecurityScorecard:
        """
        Re-run assessment applying only changed control responses.

        Requires that `assess()` has been called at least once. Merges the
        changed responses with the previous control states and returns a
        new scorecard. Useful for tracking progress after remediations without
        re-entering all control answers.

        Args:
            changed_responses: Only the controls that have changed since the
                               last assessment.
        """
        if self._last_scorecard is None:
            raise AssessmentError(
                "No prior assessment found. Call assess() before reassess()."
            )
        # Rebuild the previous full response map from the last scorecard's controls
        prior_responses: Dict[str, ControlStatus] = {
            c.control_id: c.status for c in self._last_scorecard.controls
        }
        # Merge: updated responses override prior ones
        merged = {**prior_responses, **changed_responses}
        return self.assess(
            org_id=self._last_scorecard.org_id,
            org_name=self._last_scorecard.org_name,
            control_responses=merged,
            frameworks=self._last_scorecard.frameworks,
        )

    def score_delta(
        self,
        previous: SecurityScorecard,
        current: SecurityScorecard,
    ) -> Dict[str, object]:
        """
        Compute the score delta between two scorecards.

        Returns a structured dict showing overall score change, new findings
        resolved, and new gaps introduced since the previous assessment.
        """
        prev_finding_ids: Set[str] = {f.finding_id for f in previous.findings}
        curr_finding_ids: Set[str] = {f.finding_id for f in current.findings}

        resolved = list(prev_finding_ids - curr_finding_ids)
        new_gaps = list(curr_finding_ids - prev_finding_ids)

        return {
            "score_change": round(current.overall_score - previous.overall_score, 1),
            "previous_score": previous.overall_score,
            "current_score": current.overall_score,
            "maturity_change": (
                f"{previous.maturity.value} → {current.maturity.value}"
                if previous.maturity != current.maturity
                else "unchanged"
            ),
            "findings_resolved": resolved,
            "new_gaps_introduced": new_gaps,
            "net_finding_delta": len(resolved) - len(new_gaps),
        }
