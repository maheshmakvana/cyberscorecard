"""Advanced features for cyberscorecard — caching, pipeline, async, observability, diff, security."""
from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple, TypeVar

from cyberscorecard.models import RiskFinding, SecurityControl, SecurityScorecard, Severity

logger = logging.getLogger(__name__)
T = TypeVar("T")


# ─────────────────────────────────────────────────────────────────────────────
# CACHING
# ─────────────────────────────────────────────────────────────────────────────

class ScorecardCache:
    """LRU + TTL cache for security scorecards."""

    def __init__(self, max_size: int = 128, ttl_seconds: float = 86400.0) -> None:
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._store: OrderedDict[str, Tuple[Any, float]] = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._lock = threading.Lock()

    def _key(self, *args: Any, **kwargs: Any) -> str:
        raw = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key not in self._store:
                self._misses += 1
                return None
            value, expires_at = self._store[key]
            if time.monotonic() > expires_at:
                del self._store[key]
                self._misses += 1
                return None
            self._store.move_to_end(key)
            self._hits += 1
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (value, time.monotonic() + self.ttl_seconds)
            while len(self._store) > self.max_size:
                self._store.popitem(last=False)

    def memoize(self, fn: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            key = self._key(fn.__name__, *args, **kwargs)
            cached = self.get(key)
            if cached is not None:
                return cached  # type: ignore[return-value]
            result = fn(*args, **kwargs)
            self.set(key, result)
            return result
        return wrapper

    def stats(self) -> Dict[str, Any]:
        total = self._hits + self._misses
        return {"hits": self._hits, "misses": self._misses, "hit_rate": round(self._hits / total, 3) if total else 0.0, "size": len(self._store)}

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def save(self, path: str) -> None:
        import pickle
        with self._lock:
            with open(path, "wb") as f:
                pickle.dump(dict(self._store), f)

    def load(self, path: str) -> None:
        import pickle
        with open(path, "rb") as f:
            data = pickle.load(f)
        with self._lock:
            self._store = OrderedDict(data)


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _Step:
    name: str
    fn: Callable
    args: Tuple = field(default_factory=tuple)
    kwargs: Dict = field(default_factory=dict)


class AssessmentPipeline:
    """Fluent pipeline for chaining security assessment transforms."""

    def __init__(self) -> None:
        self._steps: List[_Step] = []
        self._audit: List[Dict[str, Any]] = []
        self._retry_count = 0
        self._retry_delay = 0.5

    def map(self, fn: Callable[[List[RiskFinding]], List[RiskFinding]], name: str = "") -> "AssessmentPipeline":
        self._steps.append(_Step(name=name or fn.__name__, fn=fn))
        return self

    def filter(self, predicate: Callable[[RiskFinding], bool], name: str = "") -> "AssessmentPipeline":
        def _f(findings: List[RiskFinding]) -> List[RiskFinding]:
            return [f for f in findings if predicate(f)]
        self._steps.append(_Step(name=name or "filter", fn=_f))
        return self

    def with_retry(self, count: int = 3, delay: float = 0.5) -> "AssessmentPipeline":
        self._retry_count = count
        self._retry_delay = delay
        return self

    def run(self, findings: List[RiskFinding]) -> List[RiskFinding]:
        result = findings
        for step in self._steps:
            attempts = 0
            while True:
                try:
                    t0 = time.monotonic()
                    result = step.fn(result)
                    self._audit.append({"step": step.name, "in": len(findings), "out": len(result), "elapsed_ms": round((time.monotonic() - t0) * 1000, 2), "ok": True})
                    break
                except Exception as exc:
                    attempts += 1
                    if attempts > self._retry_count:
                        self._audit.append({"step": step.name, "error": str(exc), "ok": False})
                        raise
                    time.sleep(self._retry_delay)
        return result

    async def arun(self, findings: List[RiskFinding]) -> List[RiskFinding]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.run(findings))

    def audit_log(self) -> List[Dict[str, Any]]:
        return list(self._audit)


# ─────────────────────────────────────────────────────────────────────────────
# VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ControlRule:
    rule_type: str  # "required_domain", "min_score", "required_framework", "evidence_required"
    value: Any
    message: str = ""


class ControlValidator:
    """Declarative validator for security controls."""

    def __init__(self) -> None:
        self._rules: List[ControlRule] = []

    def add_rule(self, rule: ControlRule) -> "ControlValidator":
        self._rules.append(rule)
        return self

    def validate(self, control: SecurityControl) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        for rule in self._rules:
            if rule.rule_type == "min_score" and control.score < rule.value:
                errors.append(rule.message or f"Control {control.control_id}: score {control.score} below minimum {rule.value}")
            elif rule.rule_type == "required_framework" and rule.value not in control.frameworks:
                errors.append(rule.message or f"Control {control.control_id}: missing required framework {rule.value}")
            elif rule.rule_type == "evidence_required" and not control.evidence:
                errors.append(rule.message or f"Control {control.control_id}: evidence is required")
        return len(errors) == 0, errors

    def validate_batch(self, controls: List[SecurityControl]) -> Dict[str, List[str]]:
        return {c.control_id: self.validate(c)[1] for c in controls if not self.validate(c)[0]}


# ─────────────────────────────────────────────────────────────────────────────
# ASYNC & CONCURRENCY
# ─────────────────────────────────────────────────────────────────────────────

class RateLimiter:
    def __init__(self, rate: float, capacity: float) -> None:
        self.rate = rate
        self.capacity = capacity
        self._tokens = capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
        self._last = now

    def acquire(self, tokens: float = 1.0) -> bool:
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    async def async_acquire(self, tokens: float = 1.0) -> bool:
        while not self.acquire(tokens):
            await asyncio.sleep(0.05)
        return True


class CancellationToken:
    def __init__(self) -> None:
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled


def batch_assess(
    org_ids: List[str],
    assess_fn: Callable[[str], SecurityScorecard],
    max_workers: int = 4,
    token: Optional[CancellationToken] = None,
) -> List[SecurityScorecard]:
    results: List[SecurityScorecard] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(assess_fn, org_id): org_id for org_id in org_ids}
        for future in as_completed(futures):
            if token and token.is_cancelled:
                break
            results.append(future.result())
    return results


async def abatch_assess(
    org_ids: List[str],
    assess_fn: Callable[[str], SecurityScorecard],
    max_concurrency: int = 4,
    token: Optional[CancellationToken] = None,
) -> List[SecurityScorecard]:
    sem = asyncio.Semaphore(max_concurrency)
    loop = asyncio.get_event_loop()

    async def run_one(org_id: str) -> SecurityScorecard:
        async with sem:
            if token and token.is_cancelled:
                raise asyncio.CancelledError()
            return await loop.run_in_executor(None, lambda: assess_fn(org_id))

    return list(await asyncio.gather(*[run_one(org_id) for org_id in org_ids]))


# ─────────────────────────────────────────────────────────────────────────────
# OBSERVABILITY
# ─────────────────────────────────────────────────────────────────────────────

class AssessmentProfiler:
    def __init__(self) -> None:
        self._records: List[Dict[str, Any]] = []

    def profile(self, fn: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            t0 = time.monotonic()
            try:
                result = fn(*args, **kwargs)
                self._records.append({"fn": fn.__name__, "elapsed_ms": round((time.monotonic() - t0) * 1000, 2), "ok": True})
                return result
            except Exception as exc:
                self._records.append({"fn": fn.__name__, "elapsed_ms": round((time.monotonic() - t0) * 1000, 2), "error": str(exc), "ok": False})
                raise
        return wrapper

    def report(self) -> List[Dict[str, Any]]:
        return list(self._records)


class ScoreTrend:
    """Track rolling security score trends with volatility."""

    def __init__(self, window: int = 10) -> None:
        self._window = window
        self._scores: List[float] = []

    def record(self, score: float) -> None:
        self._scores.append(score)
        if len(self._scores) > self._window:
            self._scores.pop(0)

    def trend(self) -> str:
        if len(self._scores) < 2:
            return "insufficient_data"
        first_half = self._scores[: len(self._scores) // 2]
        second_half = self._scores[len(self._scores) // 2 :]
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)
        if avg_second > avg_first * 1.05:
            return "improving"
        if avg_second < avg_first * 0.95:
            return "declining"
        return "stable"

    def volatility(self) -> float:
        import statistics
        if len(self._scores) < 2:
            return 0.0
        return round(statistics.stdev(self._scores), 4)


class ScorecardExporter:
    """Export SecurityScorecard to JSON, CSV, Markdown."""

    @staticmethod
    def to_json(scorecard: SecurityScorecard) -> str:
        return json.dumps(scorecard.summary(), indent=2)

    @staticmethod
    def to_csv(scorecard: SecurityScorecard) -> str:
        lines = ["finding_id,domain,severity,title,remediation"]
        for f in scorecard.findings:
            lines.append(f"{f.finding_id},{f.domain.value},{f.severity.value},{f.title.replace(',', ';')},{f.remediation.replace(',', ';')}")
        return "\n".join(lines)

    @staticmethod
    def to_markdown(scorecard: SecurityScorecard) -> str:
        s = scorecard.summary()
        lines = [f"# Security Scorecard — {scorecard.org_name}", ""]
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        for k, v in s.items():
            lines.append(f"| {k} | {v} |")
        lines.append("")
        lines.append("## Critical Findings")
        for f in scorecard.critical_findings():
            lines.append(f"- **{f.title}**: {f.remediation}")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# STREAMING
# ─────────────────────────────────────────────────────────────────────────────

def stream_findings(findings: List[RiskFinding]) -> Generator[RiskFinding, None, None]:
    for f in findings:
        yield f


def findings_to_ndjson(findings: List[RiskFinding]) -> Generator[str, None, None]:
    for f in findings:
        yield f.model_dump_json() + "\n"


# ─────────────────────────────────────────────────────────────────────────────
# DIFF
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScorecardDiff:
    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    modified: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    score_change: float = 0.0

    def summary(self) -> Dict[str, Any]:
        return {"added": len(self.added), "removed": len(self.removed), "modified": len(self.modified), "score_change": round(self.score_change, 2)}

    def to_json(self) -> str:
        return json.dumps({"added": self.added, "removed": self.removed, "modified": self.modified, "score_change": self.score_change})


def diff_scorecards(a: SecurityScorecard, b: SecurityScorecard) -> ScorecardDiff:
    map_a = {f.finding_id: f for f in a.findings}
    map_b = {f.finding_id: f for f in b.findings}
    diff = ScorecardDiff(
        added=[fid for fid in map_b if fid not in map_a],
        removed=[fid for fid in map_a if fid not in map_b],
        score_change=b.overall_score - a.overall_score,
    )
    for fid in set(map_a) & set(map_b):
        changes: Dict[str, Any] = {}
        for f in ("severity", "title"):
            va, vb = getattr(map_a[fid], f), getattr(map_b[fid], f)
            if va != vb:
                changes[f] = {"old": str(va), "new": str(vb)}
        if changes:
            diff.modified[fid] = changes
    return diff


class RegressionTracker:
    """Track security score regressions across assessments."""

    def __init__(self) -> None:
        self._history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def record(self, scorecard: SecurityScorecard) -> None:
        with self._lock:
            self._history.append({
                "ts": datetime.utcnow().isoformat(),
                "org_id": scorecard.org_id,
                "score": scorecard.overall_score,
                "maturity": scorecard.maturity.value,
                "critical_count": len(scorecard.critical_findings()),
            })

    def latest_regression(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            if len(self._history) < 2:
                return None
            prev, latest = self._history[-2], self._history[-1]
            if latest["score"] < prev["score"]:
                return {"from_score": prev["score"], "to_score": latest["score"], "delta": latest["score"] - prev["score"]}
            return None

    def history(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._history)


# ─────────────────────────────────────────────────────────────────────────────
# SECURITY
# ─────────────────────────────────────────────────────────────────────────────

class AuditLog:
    def __init__(self) -> None:
        self._entries: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def record(self, action: str, org_id: str, detail: Optional[str] = None) -> None:
        with self._lock:
            self._entries.append({"ts": datetime.utcnow().isoformat(), "action": action, "org_id": org_id, "detail": detail})

    def export(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._entries)


class PIIScrubber:
    import re as _re
    _EMAIL = _re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

    @classmethod
    def scrub(cls, text: str) -> str:
        return cls._EMAIL.sub("[EMAIL]", text)


# ─────────────────────────────────────────────────────────────────────────────
# EXPERT: THREAT INTELLIGENCE FEED
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ThreatIndicator:
    """A single Indicator of Compromise (IOC) or CVE record."""
    ioc_id: str
    ioc_type: str           # "ip", "domain", "hash", "cve", "url"
    value: str
    severity: str           # "critical", "high", "medium", "low"
    source: str = "manual"
    description: str = ""
    added_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    tags: List[str] = field(default_factory=list)


class ThreatIntelFeed:
    """
    In-memory threat intelligence feed for IOC/CVE lookup.

    Maintains a local registry of known-bad indicators that can be cross-referenced
    against asset inventories, network logs, or control evidence. Supports bulk
    import from STIX-like dicts and fast O(1) lookup by value or type.
    """

    def __init__(self) -> None:
        self._by_value: Dict[str, ThreatIndicator] = {}
        self._by_type: Dict[str, List[ThreatIndicator]] = {}
        self._lock = threading.Lock()

    def add(self, indicator: ThreatIndicator) -> None:
        """Register a single indicator."""
        with self._lock:
            self._by_value[indicator.value] = indicator
            self._by_type.setdefault(indicator.ioc_type, []).append(indicator)
        logger.debug("ThreatIntelFeed: added %s %s", indicator.ioc_type, indicator.value)

    def bulk_add(self, indicators: List[ThreatIndicator]) -> int:
        """Register multiple indicators; returns count added."""
        for ind in indicators:
            self.add(ind)
        return len(indicators)

    def lookup(self, value: str) -> Optional[ThreatIndicator]:
        """Return indicator matching exact value, or None."""
        with self._lock:
            return self._by_value.get(value)

    def get_by_type(self, ioc_type: str) -> List[ThreatIndicator]:
        """Return all indicators of a given type."""
        with self._lock:
            return list(self._by_type.get(ioc_type, []))

    def match_findings(self, findings: List[RiskFinding]) -> List[Dict[str, Any]]:
        """
        Cross-reference RiskFindings against the feed.
        Returns list of {finding_id, matched_ioc} for any title/description overlap.
        """
        matches: List[Dict[str, Any]] = []
        with self._lock:
            for finding in findings:
                for value, ind in self._by_value.items():
                    if value.lower() in finding.title.lower() or value.lower() in finding.description.lower():
                        matches.append({"finding_id": finding.finding_id, "matched_ioc": value, "ioc_type": ind.ioc_type, "severity": ind.severity})
        return matches

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {"total": len(self._by_value), "by_type": {k: len(v) for k, v in self._by_type.items()}}


# ─────────────────────────────────────────────────────────────────────────────
# EXPERT: ATTACK SURFACE MAPPER
# ─────────────────────────────────────────────────────────────────────────────

# Pre-defined SMB attack vectors mapped to CIS control IDs and likelihood
_SMB_ATTACK_VECTORS: List[Dict[str, Any]] = [
    {
        "vector_id": "ATK-001", "name": "Phishing / BEC", "likelihood": 0.85,
        "related_controls": ["CIS-6.3", "CIS-14.1"],
        "description": "Email-borne attacks targeting credential theft or wire fraud",
        "mitigations": ["Enable MFA on email", "Run phishing simulation training"],
    },
    {
        "vector_id": "ATK-002", "name": "RDP Brute-Force", "likelihood": 0.72,
        "related_controls": ["CIS-4.1", "CIS-5.4"],
        "description": "Internet-exposed RDP endpoints attacked by automated credential-stuffing",
        "mitigations": ["Disable public RDP", "Enforce NLA + account lockout policy"],
    },
    {
        "vector_id": "ATK-003", "name": "Unpatched Application Exploitation", "likelihood": 0.68,
        "related_controls": ["CIS-7.1", "CIS-2.1"],
        "description": "Known CVEs exploited in unpatched software on endpoints or servers",
        "mitigations": ["Monthly patch cycle", "Subscribe to CVE alert feeds"],
    },
    {
        "vector_id": "ATK-004", "name": "Lateral Movement via Shared Credentials", "likelihood": 0.61,
        "related_controls": ["CIS-5.2", "CIS-5.4"],
        "description": "Attacker pivots across network using reused or default passwords",
        "mitigations": ["Enforce unique passwords via password manager", "Segment network"],
    },
    {
        "vector_id": "ATK-005", "name": "Ransomware Deployment", "likelihood": 0.58,
        "related_controls": ["CIS-8.2", "CIS-9.4"],
        "description": "Ransomware encryption of data following initial access",
        "mitigations": ["Immutable offsite backups", "Restrict SMB laterally in firewall"],
    },
    {
        "vector_id": "ATK-006", "name": "Supply Chain / Third-Party Compromise", "likelihood": 0.42,
        "related_controls": ["CIS-1.1"],
        "description": "Attackers enter via a trusted vendor or MSP with elevated access",
        "mitigations": ["Audit vendor access rights", "Require MFA for all vendor accounts"],
    },
    {
        "vector_id": "ATK-007", "name": "Insider Threat / Data Exfiltration", "likelihood": 0.35,
        "related_controls": ["CIS-3.3", "CIS-17.1"],
        "description": "Malicious or negligent insider exfiltrates sensitive data",
        "mitigations": ["Apply least-privilege DLP policies", "Enable audit logging for sensitive data access"],
    },
]


class AttackSurfaceMapper:
    """
    Map an organization's security posture to likely SMB attack vectors.

    Uses the scorecard's control statuses to calculate residual risk exposure
    for each pre-loaded attack vector. Vectors whose mitigating controls are
    unimplemented receive higher exposure scores.
    """

    def __init__(self) -> None:
        self._vectors = _SMB_ATTACK_VECTORS

    def map_to_scorecard(self, scorecard: SecurityScorecard) -> List[Dict[str, Any]]:
        """
        Return a list of attack vectors with residual_risk scores (0-1).
        residual_risk = likelihood * (1 - avg_control_coverage)
        """
        implemented_ids = {
            c.control_id for c in scorecard.controls
            if c.status.value in ("implemented", "not_applicable")
        }
        partial_ids = {c.control_id for c in scorecard.controls if c.status.value == "partial"}
        results = []
        for vec in self._vectors:
            related = vec["related_controls"]
            if not related:
                coverage = 0.0
            else:
                scores = []
                for cid in related:
                    if cid in implemented_ids:
                        scores.append(1.0)
                    elif cid in partial_ids:
                        scores.append(0.5)
                    else:
                        scores.append(0.0)
                coverage = sum(scores) / len(scores)
            residual = round(vec["likelihood"] * (1.0 - coverage), 3)
            results.append({
                "vector_id": vec["vector_id"],
                "name": vec["name"],
                "likelihood": vec["likelihood"],
                "control_coverage": round(coverage, 3),
                "residual_risk": residual,
                "risk_level": "critical" if residual > 0.6 else "high" if residual > 0.4 else "medium" if residual > 0.2 else "low",
                "description": vec["description"],
                "mitigations": vec["mitigations"],
            })
        return sorted(results, key=lambda x: x["residual_risk"], reverse=True)

    def risk_matrix(self, scorecard: SecurityScorecard) -> str:
        """Return a markdown risk matrix table."""
        rows = self.map_to_scorecard(scorecard)
        lines = ["# Attack Surface Risk Matrix", "",
                 "| Vector | Likelihood | Coverage | Residual Risk | Level |",
                 "|--------|-----------|----------|---------------|-------|"]
        for r in rows:
            lines.append(f"| {r['name']} | {r['likelihood']} | {r['control_coverage']} | {r['residual_risk']} | {r['risk_level'].upper()} |")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# EXPERT: COMPLIANCE GAP MAPPER
# ─────────────────────────────────────────────────────────────────────────────

# Mapping of compliance requirement → CIS control IDs that satisfy it
_FRAMEWORK_CONTROL_MAP: Dict[str, Dict[str, List[str]]] = {
    "HIPAA": {
        "Access Control (164.312(a)(1))": ["CIS-5.2", "CIS-5.4", "CIS-6.3"],
        "Audit Controls (164.312(b))": ["CIS-17.1"],
        "Transmission Security (164.312(e)(1))": ["CIS-9.4"],
        "Contingency Plan (164.312(a)(2)(ii))": ["CIS-8.2"],
        "Integrity Controls (164.312(c)(1))": ["CIS-3.3"],
    },
    "PCI-DSS": {
        "Req 2: Secure Configs": ["CIS-4.1"],
        "Req 6: Vulnerability Management": ["CIS-7.1"],
        "Req 7: Access Control": ["CIS-5.4", "CIS-3.3"],
        "Req 8: Unique IDs + MFA": ["CIS-5.2", "CIS-6.3"],
        "Req 10: Logging and Monitoring": ["CIS-17.1"],
        "Req 12: Asset Inventory": ["CIS-1.1", "CIS-2.1"],
    },
    "SOC2": {
        "CC6.1 - Logical Access": ["CIS-5.2", "CIS-5.4", "CIS-6.3"],
        "CC6.3 - Access Removal": ["CIS-5.4"],
        "CC7.1 - System Monitoring": ["CIS-17.1", "CIS-9.4"],
        "A1.2 - Backup": ["CIS-8.2"],
        "CC9.2 - Vendor Risk": ["CIS-1.1"],
    },
    "NIST CSF": {
        "ID.AM-1: Asset Inventory": ["CIS-1.1", "CIS-2.1"],
        "PR.AC-1: Identity Management": ["CIS-5.2", "CIS-5.4"],
        "PR.AC-3: Remote Access MFA": ["CIS-6.3"],
        "DE.CM-8: Vulnerability Scanning": ["CIS-7.1"],
        "RS.RP-1: IR Plan": ["CIS-17.1"],
        "PR.IP-4: Backups": ["CIS-8.2"],
    },
    "ISO 27001": {
        "A.8.1 - Asset Management": ["CIS-1.1", "CIS-2.1"],
        "A.9.2 - User Access Provisioning": ["CIS-5.4", "CIS-5.2"],
        "A.9.4 - System Access Controls": ["CIS-6.3"],
        "A.12.6 - Vulnerability Management": ["CIS-7.1"],
        "A.12.3 - Backup": ["CIS-8.2"],
        "A.16.1 - IR Management": ["CIS-17.1"],
    },
}


class ComplianceGapMapper:
    """
    Map a SecurityScorecard against HIPAA, PCI-DSS, SOC 2, NIST CSF, and ISO 27001.

    For each framework requirement, checks whether the mapped CIS controls are
    implemented. Produces per-framework gap reports and a multi-framework summary.
    """

    FRAMEWORKS = list(_FRAMEWORK_CONTROL_MAP.keys())

    def gap_report(self, scorecard: SecurityScorecard, framework: str) -> Dict[str, Any]:
        """Return a gap report for a single framework."""
        if framework not in _FRAMEWORK_CONTROL_MAP:
            raise ValueError(f"Unknown framework: {framework}. Choose from {self.FRAMEWORKS}")
        implemented_ids = {
            c.control_id for c in scorecard.controls
            if c.status.value in ("implemented", "not_applicable")
        }
        partial_ids = {c.control_id for c in scorecard.controls if c.status.value == "partial"}
        requirements = _FRAMEWORK_CONTROL_MAP[framework]
        results = []
        for req_name, control_ids in requirements.items():
            met = [cid for cid in control_ids if cid in implemented_ids]
            partial = [cid for cid in control_ids if cid in partial_ids]
            gaps = [cid for cid in control_ids if cid not in implemented_ids and cid not in partial_ids]
            status = "met" if not gaps and not partial else "partial" if met or partial else "gap"
            results.append({"requirement": req_name, "status": status, "met_controls": met, "partial_controls": partial, "gap_controls": gaps})
        total = len(results)
        met_count = sum(1 for r in results if r["status"] == "met")
        compliance_pct = round(met_count / total * 100, 1) if total else 0.0
        return {"framework": framework, "compliance_percentage": compliance_pct, "requirements": results}

    def multi_framework_report(self, scorecard: SecurityScorecard) -> Dict[str, Any]:
        """Return compliance percentages across all 5 frameworks."""
        reports = {fw: self.gap_report(scorecard, fw) for fw in self.FRAMEWORKS}
        summary = {fw: data["compliance_percentage"] for fw, data in reports.items()}
        overall = round(sum(summary.values()) / len(summary), 1)
        return {"org_id": scorecard.org_id, "overall_compliance_avg": overall, "by_framework": summary, "details": reports}


# ─────────────────────────────────────────────────────────────────────────────
# EXPERT: REMEDIATION ROADMAP GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

_EFFORT_MAP: Dict[str, Dict[str, Any]] = {
    "CIS-5.2": {"effort": "1-day", "cost_usd": "0-500", "quick_win": True},
    "CIS-5.4": {"effort": "1-day", "cost_usd": "0-500", "quick_win": True},
    "CIS-6.3": {"effort": "1-week", "cost_usd": "0-1000", "quick_win": True},
    "CIS-8.2": {"effort": "1-week", "cost_usd": "500-2000", "quick_win": True},
    "CIS-14.1": {"effort": "1-week", "cost_usd": "500-3000", "quick_win": False},
    "CIS-7.1": {"effort": "1-month", "cost_usd": "1000-5000", "quick_win": False},
    "CIS-4.1": {"effort": "1-month", "cost_usd": "1000-5000", "quick_win": False},
    "CIS-9.4": {"effort": "1-week", "cost_usd": "0-500", "quick_win": True},
    "CIS-17.1": {"effort": "1-month", "cost_usd": "0-2000", "quick_win": False},
    "CIS-3.3": {"effort": "1-month", "cost_usd": "500-3000", "quick_win": False},
    "CIS-1.1": {"effort": "1-month", "cost_usd": "1000-5000", "quick_win": False},
    "CIS-2.1": {"effort": "1-month", "cost_usd": "500-2000", "quick_win": False},
}


class RemediationRoadmapGenerator:
    """
    Generate a prioritized remediation roadmap from a SecurityScorecard.

    Findings are ranked by severity then by quick-win status. Each item gets
    an effort estimate (1-day / 1-week / 1-month) and a cost range. The
    roadmap can be exported as structured data or Markdown.
    """

    def generate(self, scorecard: SecurityScorecard) -> List[Dict[str, Any]]:
        """Return ordered roadmap items for all open findings."""
        roadmap = []
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for finding in scorecard.findings:
            cid = finding.control_id
            meta = _EFFORT_MAP.get(cid, {"effort": "1-month", "cost_usd": "unknown", "quick_win": False})
            roadmap.append({
                "finding_id": finding.finding_id,
                "control_id": cid,
                "title": finding.title,
                "severity": finding.severity.value,
                "domain": finding.domain.value,
                "effort": meta["effort"],
                "cost_usd": meta["cost_usd"],
                "quick_win": meta["quick_win"],
                "remediation": finding.remediation,
                "priority_score": severity_order.get(finding.severity.value, 5) * 10 + (0 if meta["quick_win"] else 5),
            })
        return sorted(roadmap, key=lambda x: x["priority_score"])

    def quick_wins(self, scorecard: SecurityScorecard) -> List[Dict[str, Any]]:
        """Return only quick-win items (completable in 1-day or 1-week)."""
        return [item for item in self.generate(scorecard) if item["quick_win"]]

    def to_markdown(self, scorecard: SecurityScorecard) -> str:
        """Export the full roadmap as a Markdown action plan."""
        items = self.generate(scorecard)
        lines = [f"# Remediation Roadmap — {scorecard.org_name}", f"Overall Score: {scorecard.overall_score}", ""]
        lines.append("| Priority | Control | Severity | Effort | Cost (USD) | Quick Win |")
        lines.append("|----------|---------|----------|--------|------------|-----------|")
        for i, item in enumerate(items, 1):
            qw = "YES" if item["quick_win"] else "no"
            lines.append(f"| {i} | {item['control_id']} | {item['severity'].upper()} | {item['effort']} | {item['cost_usd']} | {qw} |")
        lines.append("")
        lines.append("## Action Details")
        for item in items:
            lines.append(f"### {item['control_id']} — {item['title']}")
            lines.append(f"- **Severity**: {item['severity'].upper()}")
            lines.append(f"- **Effort**: {item['effort']}  **Cost**: ${item['cost_usd']}")
            lines.append(f"- **Steps**: {item['remediation']}")
            lines.append("")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# EXPERT: SECURITY SPAN EMITTER (OpenTelemetry with stdlib fallback)
# ─────────────────────────────────────────────────────────────────────────────

class SecuritySpanEmitter:
    """
    Emit OpenTelemetry spans for security assessment operations.
    Falls back to structured logging when opentelemetry-sdk is not installed.
    """

    def __init__(self, service_name: str = "cyberscorecard") -> None:
        self._service = service_name
        self._otel_available = False
        self._tracer: Any = None
        try:
            from opentelemetry import trace
            from opentelemetry.sdk.trace import TracerProvider
            provider = TracerProvider()
            trace.set_tracer_provider(provider)
            self._tracer = trace.get_tracer(service_name)
            self._otel_available = True
            logger.debug("SecuritySpanEmitter: OpenTelemetry tracer initialised")
        except ImportError:
            logger.debug("SecuritySpanEmitter: opentelemetry not installed — using log fallback")

    def span(self, operation: str, attributes: Optional[Dict[str, Any]] = None) -> Any:
        """Context manager: emit an OTEL span or log span start/end."""
        if self._otel_available and self._tracer is not None:
            span = self._tracer.start_span(operation)
            if attributes:
                for k, v in attributes.items():
                    span.set_attribute(k, str(v))
            return span
        return _LogSpan(operation, attributes or {}, self._service)

    def emit_assessment(self, scorecard: SecurityScorecard) -> None:
        """Emit a span summarising a completed assessment."""
        attrs = {
            "org_id": scorecard.org_id,
            "overall_score": scorecard.overall_score,
            "maturity": scorecard.maturity.value,
            "findings_count": len(scorecard.findings),
        }
        with self.span("assessment.complete", attrs):
            pass

    def emit_finding(self, finding: RiskFinding) -> None:
        """Emit a span for a single risk finding."""
        attrs = {"finding_id": finding.finding_id, "severity": finding.severity.value, "domain": finding.domain.value}
        with self.span("finding.detected", attrs):
            pass


class _LogSpan:
    """Stdlib-logging fallback span used when OTEL is unavailable."""

    def __init__(self, name: str, attrs: Dict[str, Any], service: str) -> None:
        self._name = name
        self._attrs = attrs
        self._service = service
        self._t0 = time.monotonic()

    def __enter__(self) -> "_LogSpan":
        logger.debug("[span:start] service=%s operation=%s attrs=%s", self._service, self._name, self._attrs)
        return self

    def __exit__(self, *args: Any) -> None:
        elapsed = round((time.monotonic() - self._t0) * 1000, 2)
        logger.debug("[span:end] service=%s operation=%s elapsed_ms=%s", self._service, self._name, elapsed)


# ─────────────────────────────────────────────────────────────────────────────
# EXPERT v1.2.0: ZERO TRUST SCORECARD
# ─────────────────────────────────────────────────────────────────────────────

# Zero Trust pillars mapped to CIS control IDs that satisfy them
_ZT_PILLAR_CONTROLS: Dict[str, Dict[str, Any]] = {
    "Identity": {
        "description": "Verify every identity with strong authentication before granting access.",
        "controls": ["CIS-5.2", "CIS-5.4", "CIS-6.3"],
        "weight": 0.25,
    },
    "Devices": {
        "description": "Ensure only compliant, managed devices access resources.",
        "controls": ["CIS-1.1", "CIS-2.1", "CIS-4.1"],
        "weight": 0.20,
    },
    "Network": {
        "description": "Segment networks and encrypt all traffic in transit.",
        "controls": ["CIS-9.4", "CIS-12.1"],
        "weight": 0.20,
    },
    "Applications": {
        "description": "Secure application access with least-privilege and patching.",
        "controls": ["CIS-7.1", "CIS-3.3"],
        "weight": 0.15,
    },
    "Data": {
        "description": "Classify and protect data at rest and in transit.",
        "controls": ["CIS-3.3", "CIS-8.2"],
        "weight": 0.10,
    },
    "Visibility": {
        "description": "Continuous monitoring and threat detection across all pillars.",
        "controls": ["CIS-17.1"],
        "weight": 0.10,
    },
}


@dataclass
class ZeroTrustPillarScore:
    """Score for a single Zero Trust pillar."""
    pillar: str
    description: str
    coverage: float       # 0.0 – 1.0
    weighted_score: float
    gap_controls: List[str]
    maturity: str         # "initial", "developing", "defined", "advanced"


@dataclass
class ZeroTrustAssessment:
    """Overall Zero Trust posture assessment derived from a SecurityScorecard."""
    org_id: str
    zt_score: float            # 0.0 – 100.0
    maturity: str
    pillar_scores: List[ZeroTrustPillarScore]
    critical_gaps: List[str]
    next_steps: List[str]

    def summary(self) -> Dict[str, Any]:
        return {
            "org_id": self.org_id,
            "zt_score": round(self.zt_score, 1),
            "maturity": self.maturity,
            "critical_gaps": self.critical_gaps,
            "pillar_scores": [
                {"pillar": p.pillar, "coverage": round(p.coverage, 3), "maturity": p.maturity}
                for p in self.pillar_scores
            ],
        }


class ZeroTrustScorecard:
    """
    Derive a Zero Trust Architecture (ZTA) posture score from a SecurityScorecard.

    Maps CIS Controls v8 IG1 implementation status onto NIST SP 800-207 Zero Trust
    pillars (Identity, Devices, Network, Applications, Data, Visibility) and
    produces a weighted ZT score (0–100) with per-pillar gap analysis and
    next-step recommendations.

    Usage::

        zt = ZeroTrustScorecard()
        assessment = zt.assess(scorecard)
        print(assessment.zt_score)          # e.g. 62.5
        print(zt.to_markdown(assessment))
    """

    def assess(self, scorecard: SecurityScorecard) -> ZeroTrustAssessment:
        """Produce a full Zero Trust posture assessment."""
        implemented = {
            c.control_id for c in scorecard.controls
            if c.status.value in ("implemented", "not_applicable")
        }
        partial = {c.control_id for c in scorecard.controls if c.status.value == "partial"}

        pillar_scores: List[ZeroTrustPillarScore] = []
        total_weighted = 0.0
        critical_gaps: List[str] = []

        for pillar, meta in _ZT_PILLAR_CONTROLS.items():
            controls = meta["controls"]
            weight = meta["weight"]
            scores = []
            gaps = []
            for cid in controls:
                if cid in implemented:
                    scores.append(1.0)
                elif cid in partial:
                    scores.append(0.5)
                else:
                    scores.append(0.0)
                    gaps.append(cid)
            coverage = sum(scores) / len(scores) if scores else 0.0
            weighted = coverage * weight
            total_weighted += weighted

            if coverage < 0.4:
                mat = "initial"
            elif coverage < 0.65:
                mat = "developing"
            elif coverage < 0.85:
                mat = "defined"
            else:
                mat = "advanced"

            if coverage < 0.4 and pillar in ("Identity", "Devices"):
                critical_gaps.extend(gaps)

            pillar_scores.append(ZeroTrustPillarScore(
                pillar=pillar,
                description=meta["description"],
                coverage=coverage,
                weighted_score=weighted,
                gap_controls=gaps,
                maturity=mat,
            ))

        zt_score = round(total_weighted * 100.0, 1)
        if zt_score < 30:
            overall_mat = "initial"
        elif zt_score < 55:
            overall_mat = "developing"
        elif zt_score < 75:
            overall_mat = "defined"
        else:
            overall_mat = "advanced"

        next_steps = self._next_steps(pillar_scores)
        return ZeroTrustAssessment(
            org_id=scorecard.org_id,
            zt_score=zt_score,
            maturity=overall_mat,
            pillar_scores=pillar_scores,
            critical_gaps=list(dict.fromkeys(critical_gaps)),
            next_steps=next_steps,
        )

    def _next_steps(self, pillar_scores: List[ZeroTrustPillarScore]) -> List[str]:
        """Generate ordered next-step recommendations targeting weakest pillars first."""
        steps: List[str] = []
        for ps in sorted(pillar_scores, key=lambda x: x.coverage):
            if ps.gap_controls:
                cids = ", ".join(ps.gap_controls[:3])
                steps.append(
                    f"Improve {ps.pillar} pillar (currently {ps.maturity}): "
                    f"implement {cids}."
                )
            if len(steps) >= 5:
                break
        return steps

    def to_markdown(self, assessment: ZeroTrustAssessment) -> str:
        """Render a full Zero Trust posture Markdown report."""
        lines = [
            f"# Zero Trust Posture Report — {assessment.org_id}",
            f"**ZT Score**: {assessment.zt_score} / 100  |  **Maturity**: {assessment.maturity.upper()}",
            "",
            "## Pillar Scores",
            "",
            "| Pillar | Coverage | Maturity | Gap Controls |",
            "|--------|----------|----------|--------------|",
        ]
        for ps in assessment.pillar_scores:
            gaps = ", ".join(ps.gap_controls) if ps.gap_controls else "—"
            lines.append(
                f"| {ps.pillar} | {ps.coverage:.0%} | {ps.maturity.upper()} | {gaps} |"
            )
        lines += ["", "## Next Steps", ""]
        for step in assessment.next_steps:
            lines.append(f"- {step}")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# EXPERT v1.2.0: INCIDENT RESPONSE PLAYBOOK GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

_IR_PLAYBOOK_TEMPLATES: Dict[str, List[str]] = {
    "ransomware": [
        "1. DETECT: Identify affected hosts via EDR alerts or file-change monitoring.",
        "2. CONTAIN: Isolate affected systems from the network immediately.",
        "3. ERADICATE: Remove malware; wipe and restore from known-good backup.",
        "4. RECOVER: Restore systems from clean backups; apply pending patches.",
        "5. POST-INCIDENT: Conduct forensic analysis; identify patient-zero; report to law enforcement.",
        "6. IMPROVE: Review CIS-8.2 (Backup) and CIS-7.1 (Vuln Mgmt) gaps; test backups monthly.",
    ],
    "phishing": [
        "1. DETECT: User reports suspicious email; check mail gateway logs.",
        "2. CONTAIN: Remove phishing email from all inboxes; block sender domain.",
        "3. ASSESS: Determine if credentials were submitted; check for unauthorised logins.",
        "4. REMEDIATE: Reset compromised credentials; enable MFA (CIS-6.3).",
        "5. NOTIFY: Alert affected users; consider regulatory notification if PII exposed.",
        "6. IMPROVE: Run phishing simulation; reinforce security awareness training (CIS-14.1).",
    ],
    "credential_compromise": [
        "1. DETECT: Unusual login patterns or MFA bypass alerts.",
        "2. CONTAIN: Disable compromised accounts; invalidate active sessions.",
        "3. INVESTIGATE: Review access logs for lateral movement.",
        "4. REMEDIATE: Force password reset; enforce MFA on all accounts (CIS-6.3).",
        "5. RECOVER: Review permissions granted during compromise window; revoke excess access.",
        "6. IMPROVE: Audit privileged accounts (CIS-5.2, CIS-5.4); implement PAM tooling.",
    ],
    "data_breach": [
        "1. DETECT: DLP alert, SIEM anomaly, or third-party notification.",
        "2. CONTAIN: Revoke access to affected data store; disable compromised service accounts.",
        "3. ASSESS: Determine scope — records count, data classification, affected users.",
        "4. NOTIFY: Engage legal and compliance; notify regulator within required timeframe.",
        "5. REMEDIATE: Patch exploited vulnerability; rotate secrets; segment affected network.",
        "6. IMPROVE: Implement data classification (CIS-3.3) and encryption at rest (CIS-9.4).",
    ],
    "insider_threat": [
        "1. DETECT: UEBA alert, anomalous data export, or HR notification.",
        "2. CONTAIN: Immediately revoke access; preserve evidence before account deletion.",
        "3. INVESTIGATE: Audit access logs; preserve forensic copy of activity.",
        "4. ESCALATE: Engage HR, legal, and law enforcement as appropriate.",
        "5. RECOVER: Review data accessed or exfiltrated; notify affected parties.",
        "6. IMPROVE: Implement least-privilege access reviews quarterly (CIS-5.4); enable DLP.",
    ],
    "generic": [
        "1. DETECT: Identify and confirm the incident via alert, ticket, or report.",
        "2. CONTAIN: Limit the blast radius — isolate affected assets.",
        "3. ERADICATE: Remove root cause — patch, remove malware, revoke access.",
        "4. RECOVER: Restore services from clean state; validate integrity.",
        "5. COMMUNICATE: Notify stakeholders, legal, and regulators as required.",
        "6. IMPROVE: Conduct post-incident review; update controls based on gaps identified.",
    ],
}

_SEVERITY_TO_INCIDENT_TYPE: Dict[str, str] = {
    "ransomware": "ransomware",
    "phishing": "phishing",
    "credential": "credential_compromise",
    "data": "data_breach",
    "insider": "insider_threat",
}


@dataclass
class IRPlaybook:
    """A generated Incident Response playbook for an organisation."""
    org_id: str
    incident_type: str
    severity: str
    triggered_by: List[str]   # finding_ids that triggered this playbook
    steps: List[str]
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "org_id": self.org_id,
            "incident_type": self.incident_type,
            "severity": self.severity,
            "triggered_by": self.triggered_by,
            "steps": self.steps,
            "generated_at": self.generated_at,
        }

    def to_markdown(self) -> str:
        lines = [
            f"# IR Playbook — {self.incident_type.replace('_', ' ').title()}",
            f"**Org**: {self.org_id}  |  **Severity**: {self.severity.upper()}  |  **Generated**: {self.generated_at}",
            f"**Triggered by findings**: {', '.join(self.triggered_by) or 'manual'}",
            "",
            "## Response Steps",
            "",
        ]
        for step in self.steps:
            lines.append(step)
        return "\n".join(lines)


class IncidentResponsePlaybookGenerator:
    """
    Auto-generate Incident Response playbooks from a SecurityScorecard's findings.

    Classifies the most likely incident type from open critical/high findings and
    returns a step-by-step IR playbook aligned with NIST SP 800-61 phases
    (Detect → Contain → Eradicate → Recover → Improve).

    Usage::

        gen = IncidentResponsePlaybookGenerator()
        playbook = gen.generate(scorecard)
        print(playbook.to_markdown())

        # Or generate for a specific incident type:
        playbook = gen.generate(scorecard, incident_type="ransomware")
    """

    def generate(
        self,
        scorecard: SecurityScorecard,
        incident_type: Optional[str] = None,
    ) -> IRPlaybook:
        """Generate an IR playbook, inferring incident type from findings if not given."""
        triggered = [f.finding_id for f in scorecard.findings if f.severity.value in ("critical", "high")]
        if incident_type is None:
            incident_type = self._infer_type(scorecard)
        steps = _IR_PLAYBOOK_TEMPLATES.get(incident_type, _IR_PLAYBOOK_TEMPLATES["generic"])
        severity = "critical" if any(
            f.severity.value == "critical" for f in scorecard.findings
        ) else "high"
        return IRPlaybook(
            org_id=scorecard.org_id,
            incident_type=incident_type,
            severity=severity,
            triggered_by=triggered[:10],
            steps=steps,
        )

    def _infer_type(self, scorecard: SecurityScorecard) -> str:
        """Guess most likely incident type from finding titles."""
        text = " ".join(f.title.lower() + " " + f.description.lower() for f in scorecard.findings)
        for keyword, itype in _SEVERITY_TO_INCIDENT_TYPE.items():
            if keyword in text:
                return itype
        return "generic"

    def all_playbooks(self, scorecard: SecurityScorecard) -> List[IRPlaybook]:
        """Generate playbooks for all incident types; useful for tabletop exercises."""
        return [self.generate(scorecard, itype) for itype in _IR_PLAYBOOK_TEMPLATES]

    def to_markdown(self, playbooks: List[IRPlaybook]) -> str:
        """Render an index of all playbooks."""
        lines = [f"# IR Playbook Library — {playbooks[0].org_id if playbooks else ''}", ""]
        for pb in playbooks:
            lines.append(f"## {pb.incident_type.replace('_', ' ').title()}")
            for step in pb.steps:
                lines.append(f"  {step}")
            lines.append("")
        return "\n".join(lines)
