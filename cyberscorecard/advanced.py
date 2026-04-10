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
