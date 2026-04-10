"""Tests for cyberscorecard — SMB cybersecurity governance."""
import asyncio
import json
import pytest

from cyberscorecard import (
    SecurityAssessor,
    ControlStatus,
    ControlDomain,
    Severity,
    MaturityLevel,
    build_default_controls,
    ScorecardCache,
    AssessmentPipeline,
    ControlValidator,
    ControlRule,
    ScoreTrend,
    RegressionTracker,
    ScorecardExporter,
    diff_scorecards,
    stream_findings,
    findings_to_ndjson,
    AuditLog,
    PIIScrubber,
    RateLimiter,
    CancellationToken,
)


def make_full_responses(status: ControlStatus = ControlStatus.IMPLEMENTED):
    controls = build_default_controls()
    return {c.control_id: status for c in controls}


# ─── Controls ─────────────────────────────────────────────────────────────────

def test_default_controls_loaded():
    controls = build_default_controls()
    assert len(controls) >= 5
    ids = {c.control_id for c in controls}
    assert "CIS-5.2" in ids
    assert "CIS-6.3" in ids


def test_control_has_remediation():
    controls = build_default_controls()
    for c in controls:
        assert len(c.remediation_steps) >= 1


# ─── Assessor ─────────────────────────────────────────────────────────────────

def test_all_implemented_high_score():
    assessor = SecurityAssessor()
    responses = make_full_responses(ControlStatus.IMPLEMENTED)
    scorecard = assessor.assess("ORG-1", "Test Org", responses)
    assert scorecard.overall_score > 80
    assert scorecard.maturity in (MaturityLevel.MANAGED, MaturityLevel.OPTIMIZED)


def test_all_not_implemented_low_score():
    assessor = SecurityAssessor()
    responses = make_full_responses(ControlStatus.NOT_IMPLEMENTED)
    scorecard = assessor.assess("ORG-1", "Test Org", responses)
    assert scorecard.overall_score < 10
    assert scorecard.maturity == MaturityLevel.INITIAL


def test_partial_implementation_medium_score():
    assessor = SecurityAssessor()
    responses = make_full_responses(ControlStatus.PARTIAL)
    scorecard = assessor.assess("ORG-1", "Test Org", responses)
    assert 0 < scorecard.overall_score < 100


def test_findings_generated_for_unimplemented():
    assessor = SecurityAssessor()
    responses = make_full_responses(ControlStatus.NOT_IMPLEMENTED)
    scorecard = assessor.assess("ORG-1", "Test Org", responses)
    assert len(scorecard.findings) > 0


def test_no_findings_when_all_implemented():
    assessor = SecurityAssessor()
    responses = make_full_responses(ControlStatus.IMPLEMENTED)
    scorecard = assessor.assess("ORG-1", "Test Org", responses)
    assert len(scorecard.findings) == 0


def test_critical_findings():
    assessor = SecurityAssessor()
    responses = {}  # empty = all NOT_IMPLEMENTED
    scorecard = assessor.assess("ORG-1", "Test Org", responses)
    critical = scorecard.critical_findings()
    assert len(critical) > 0
    assert all(f.severity == Severity.CRITICAL for f in critical)


def test_scorecard_summary():
    assessor = SecurityAssessor()
    responses = make_full_responses(ControlStatus.IMPLEMENTED)
    scorecard = assessor.assess("ORG-1", "Test Corp", responses)
    s = scorecard.summary()
    assert s["org_id"] == "ORG-1"
    assert "overall_score" in s
    assert "maturity" in s


def test_domain_scores_generated():
    assessor = SecurityAssessor()
    responses = make_full_responses(ControlStatus.IMPLEMENTED)
    scorecard = assessor.assess("ORG-1", "Test Org", responses)
    assert len(scorecard.domain_scores) > 0


def test_not_applicable_treated_as_implemented():
    assessor = SecurityAssessor()
    responses = make_full_responses(ControlStatus.NOT_APPLICABLE)
    scorecard = assessor.assess("ORG-1", "Test Org", responses)
    assert scorecard.overall_score > 50


# ─── Cache ────────────────────────────────────────────────────────────────────

def test_cache_set_get():
    cache = ScorecardCache(max_size=10, ttl_seconds=60)
    cache.set("k1", "v1")
    assert cache.get("k1") == "v1"
    assert cache.get("miss") is None


def test_cache_memoize():
    cache = ScorecardCache()
    calls = [0]

    @cache.memoize
    def fn(x):
        calls[0] += 1
        return x

    assert fn("a") == "a"
    assert fn("a") == "a"
    assert calls[0] == 1


def test_cache_stats():
    cache = ScorecardCache(max_size=10, ttl_seconds=60)
    cache.set("k", "v")
    cache.get("k")
    cache.get("miss")
    s = cache.stats()
    assert s["hits"] == 1
    assert s["misses"] == 1


# ─── Pipeline ─────────────────────────────────────────────────────────────────

def test_pipeline_filter_critical():
    assessor = SecurityAssessor()
    scorecard = assessor.assess("ORG-1", "Test", make_full_responses(ControlStatus.NOT_IMPLEMENTED))
    pipeline = AssessmentPipeline().filter(lambda f: f.severity == Severity.CRITICAL, name="critical_only")
    result = pipeline.run(scorecard.findings)
    assert all(f.severity == Severity.CRITICAL for f in result)


def test_pipeline_audit_log():
    assessor = SecurityAssessor()
    scorecard = assessor.assess("ORG-1", "Test", make_full_responses(ControlStatus.NOT_IMPLEMENTED))
    pipeline = AssessmentPipeline().filter(lambda f: True, name="all")
    pipeline.run(scorecard.findings)
    log = pipeline.audit_log()
    assert log[0]["ok"] is True


def test_pipeline_async():
    assessor = SecurityAssessor()
    scorecard = assessor.assess("ORG-1", "Test", make_full_responses(ControlStatus.NOT_IMPLEMENTED))
    pipeline = AssessmentPipeline().filter(lambda f: True)
    result = asyncio.run(pipeline.arun(scorecard.findings))
    assert isinstance(result, list)


# ─── Validator ────────────────────────────────────────────────────────────────

def test_validator_evidence_required():
    validator = ControlValidator()
    validator.add_rule(ControlRule("evidence_required", True))
    controls = build_default_controls()
    errors = validator.validate_batch(controls)
    # Controls have no evidence set — should all fail
    assert len(errors) == len(controls)


def test_validator_passes_with_evidence():
    validator = ControlValidator()
    validator.add_rule(ControlRule("evidence_required", True))
    controls = [c.model_copy(update={"evidence": "Policy document on file"}) for c in build_default_controls()]
    errors = validator.validate_batch(controls)
    assert len(errors) == 0


# ─── Score Trend ──────────────────────────────────────────────────────────────

def test_score_trend_improving():
    trend = ScoreTrend(window=6)
    for s in [20, 30, 35, 45, 55, 70]:
        trend.record(s)
    assert trend.trend() == "improving"


def test_score_trend_stable():
    trend = ScoreTrend(window=6)
    for s in [60, 60, 61, 60, 59, 60]:
        trend.record(s)
    assert trend.trend() == "stable"


def test_score_trend_declining():
    trend = ScoreTrend(window=6)
    for s in [80, 70, 60, 50, 40, 30]:
        trend.record(s)
    assert trend.trend() == "declining"


def test_score_volatility():
    trend = ScoreTrend(window=4)
    for s in [20, 80, 20, 80]:
        trend.record(s)
    assert trend.volatility() > 20


# ─── Regression Tracker ───────────────────────────────────────────────────────

def test_regression_tracker_no_regression():
    assessor = SecurityAssessor()
    tracker = RegressionTracker()
    sc1 = assessor.assess("ORG-1", "T", make_full_responses(ControlStatus.PARTIAL))
    sc2 = assessor.assess("ORG-1", "T", make_full_responses(ControlStatus.IMPLEMENTED))
    tracker.record(sc1)
    tracker.record(sc2)
    assert tracker.latest_regression() is None


def test_regression_tracker_detects_regression():
    assessor = SecurityAssessor()
    tracker = RegressionTracker()
    sc1 = assessor.assess("ORG-1", "T", make_full_responses(ControlStatus.IMPLEMENTED))
    sc2 = assessor.assess("ORG-1", "T", make_full_responses(ControlStatus.NOT_IMPLEMENTED))
    tracker.record(sc1)
    tracker.record(sc2)
    regression = tracker.latest_regression()
    assert regression is not None
    assert regression["delta"] < 0


# ─── Exporter ─────────────────────────────────────────────────────────────────

def test_exporter_to_json():
    assessor = SecurityAssessor()
    sc = assessor.assess("ORG-1", "Test", make_full_responses(ControlStatus.IMPLEMENTED))
    j = ScorecardExporter.to_json(sc)
    data = json.loads(j)
    assert "org_id" in data


def test_exporter_to_csv():
    assessor = SecurityAssessor()
    sc = assessor.assess("ORG-1", "Test", make_full_responses(ControlStatus.NOT_IMPLEMENTED))
    csv = ScorecardExporter.to_csv(sc)
    assert "finding_id" in csv


def test_exporter_to_markdown():
    assessor = SecurityAssessor()
    sc = assessor.assess("ORG-1", "Test", make_full_responses(ControlStatus.NOT_IMPLEMENTED))
    md = ScorecardExporter.to_markdown(sc)
    assert "# Security Scorecard" in md


# ─── Diff ─────────────────────────────────────────────────────────────────────

def test_diff_scorecards():
    assessor = SecurityAssessor()
    sc_a = assessor.assess("ORG-1", "Test", make_full_responses(ControlStatus.NOT_IMPLEMENTED))
    sc_b = assessor.assess("ORG-1", "Test", make_full_responses(ControlStatus.IMPLEMENTED))
    diff = diff_scorecards(sc_a, sc_b)
    assert diff.score_change > 0
    s = diff.summary()
    assert "score_change" in s


# ─── Streaming ────────────────────────────────────────────────────────────────

def test_stream_findings():
    assessor = SecurityAssessor()
    sc = assessor.assess("ORG-1", "Test", make_full_responses(ControlStatus.NOT_IMPLEMENTED))
    result = list(stream_findings(sc.findings))
    assert len(result) == len(sc.findings)


def test_findings_to_ndjson():
    assessor = SecurityAssessor()
    sc = assessor.assess("ORG-1", "Test", make_full_responses(ControlStatus.NOT_IMPLEMENTED))
    lines = list(findings_to_ndjson(sc.findings))
    assert len(lines) == len(sc.findings)
    if lines:
        assert lines[0].endswith("\n")


# ─── Audit & PII ──────────────────────────────────────────────────────────────

def test_audit_log():
    log = AuditLog()
    log.record("assessed", "ACME-001", detail="score=72")
    entries = log.export()
    assert entries[0]["org_id"] == "ACME-001"


def test_pii_scrubber():
    result = PIIScrubber.scrub("admin@company.com is responsible")
    assert "[EMAIL]" in result
    assert "admin@company.com" not in result
