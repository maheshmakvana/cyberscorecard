# cyberscorecard

**SMB cybersecurity governance scorecard** — CIS Controls v8 assessment, risk findings, maturity scoring, and actionable remediation roadmap for small businesses.

4 in 5 SMBs have been breached. Average breach cost: $3.31M. There are only 35,000 CISOs for 359M businesses globally. `cyberscorecard` gives every Python developer the tools to build CISO-grade governance into any platform.

[![PyPI version](https://badge.fury.io/py/cyberscorecard.svg)](https://pypi.org/project/cyberscorecard/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)

## Installation

```bash
pip install cyberscorecard
```

## Quick Start

```python
from cyberscorecard import SecurityAssessor, ControlStatus

assessor = SecurityAssessor()  # Pre-loaded with CIS Controls v8 IG1

# Self-assessment: provide status for each control
responses = {
    "CIS-5.2": ControlStatus.IMPLEMENTED,       # Unique passwords
    "CIS-6.3": ControlStatus.PARTIAL,            # MFA — partially deployed
    "CIS-8.2": ControlStatus.IMPLEMENTED,        # Automated backups
    "CIS-3.3": ControlStatus.NOT_IMPLEMENTED,    # Data access control
    "CIS-5.4": ControlStatus.NOT_IMPLEMENTED,    # Admin privilege separation
}

scorecard = assessor.assess(
    org_id="ACME-001",
    org_name="Acme Corp",
    control_responses=responses,
)

print(f"Overall score: {scorecard.overall_score}/100")
print(f"Maturity: {scorecard.maturity.value}")
print(f"Critical findings: {len(scorecard.critical_findings())}")
print(scorecard.summary())
```

## Maturity Levels

| Level | Score | Description |
|---|---|---|
| Initial | 0–20 | Ad hoc, reactive — no formal processes |
| Developing | 20–40 | Some controls in place, inconsistently applied |
| Defined | 40–65 | Documented and repeatable processes |
| Managed | 65–85 | Measured and controlled |
| Optimized | 85–100 | Continuous improvement culture |

## Security Domains

10 domains are assessed and scored individually:

`access_control`, `data_protection`, `network_security`, `endpoint_security`, `incident_response`, `vulnerability_management`, `backup_recovery`, `security_awareness`, `third_party_risk`, `compliance`

## CIS Controls v8 IG1 Baseline

Pre-loaded controls include:

- CIS-1.1: Enterprise Asset Inventory
- CIS-3.3: Data Access Control Lists
- CIS-5.2: Unique Passwords
- CIS-5.4: Admin Privilege Separation
- CIS-6.3: MFA for External Applications
- CIS-7.1: Vulnerability Management Process
- CIS-8.2: Automated Backups
- CIS-9.4: Network Service Restriction
- CIS-14.1: Security Awareness Program
- CIS-17.1: Incident Response Owner

Each control includes **severity**, **remediation steps**, and **framework tags**.

## Advanced Features

### Pipeline

```python
from cyberscorecard import AssessmentPipeline

pipeline = (
    AssessmentPipeline()
    .filter(lambda f: f.severity.value in ["critical", "high"], name="critical_high_only")
    .map(lambda findings: sorted(findings, key=lambda f: f.severity.value), name="sort_by_severity")
    .with_retry(count=2)
)

prioritized = pipeline.run(scorecard.findings)
print(pipeline.audit_log())
```

### Caching

```python
from cyberscorecard import ScorecardCache

cache = ScorecardCache(max_size=100, ttl_seconds=86400)

@cache.memoize
def run_assessment(org_id):
    return assessor.assess(org_id, org_name, responses)

cache.save("scorecard_cache.pkl")
print(cache.stats())
```

### Score Trend & Regression Tracking

```python
from cyberscorecard import ScoreTrend, RegressionTracker

trend = ScoreTrend(window=6)
tracker = RegressionTracker()

for quarterly_scorecard in history:
    trend.record(quarterly_scorecard.overall_score)
    tracker.record(quarterly_scorecard)

print(trend.trend())       # "improving"
print(trend.volatility())  # 3.2
print(tracker.latest_regression())  # None if no regression
```

### Export Reports

```python
from cyberscorecard import ScorecardExporter

print(ScorecardExporter.to_json(scorecard))
print(ScorecardExporter.to_csv(scorecard))
print(ScorecardExporter.to_markdown(scorecard))
```

### Diff Between Assessments

```python
from cyberscorecard import diff_scorecards

diff = diff_scorecards(last_quarter, this_quarter)
print(diff.summary())  # {'added': 0, 'removed': 2, 'modified': 3, 'score_change': 12.5}
print(diff.to_json())
```

### Batch Assessment (Multi-Tenant)

```python
from cyberscorecard import batch_assess, abatch_assess

# Sync — assess multiple orgs
scorecards = batch_assess(
    org_ids=["ORG-1", "ORG-2", "ORG-3"],
    assess_fn=lambda org_id: assessor.assess(org_id, org_names[org_id], responses_map[org_id]),
    max_workers=4,
)

# Async
scorecards = await abatch_assess(org_ids, assess_fn, max_concurrency=8)
```

### Validation

```python
from cyberscorecard import ControlValidator, ControlRule

validator = ControlValidator()
validator.add_rule(ControlRule("evidence_required", True, "All implemented controls need evidence"))
validator.add_rule(ControlRule("required_framework", "CIS Controls v8"))

errors = validator.validate_batch(scorecard.controls)
```

### Streaming

```python
from cyberscorecard import stream_findings, findings_to_ndjson

for finding in stream_findings(scorecard.findings):
    send_to_dashboard(finding)

for line in findings_to_ndjson(scorecard.findings):
    output.write(line)
```

### Audit Log

```python
from cyberscorecard import AuditLog

log = AuditLog()
log.record("assessed", "ACME-001", detail="score=72.4")
log.record("finding_resolved", "ACME-001", detail="CIS-3.3")
```

## Changelog

### v1.2.2 (2026-04-10)
- Added Contributing and Author sections to README

### v1.2.1 (2026-04-10)
- Added Changelog section to README for release traceability

### v1.2.0
- Added `ZeroTrustScorecard` — zero-trust posture assessment across identity, device, network, and data layers
- Added `IncidentResponsePlaybookGenerator` — auto-generate CIS-aligned IR playbooks from scorecard findings
- Expanded SEO keywords for PyPI discoverability

### v1.0.1
- Advanced features: pipeline, caching, validation, diff/trend, streaming, audit log

### v1.0.0
- Initial release: CIS Controls v8 assessment, risk scoring, maturity scoring, remediation roadmap

## License

MIT

## Contributing

Contributions are welcome! Here's how to get started:

1. Fork the repository on [GitHub](https://github.com/maheshmakvana/cyberscorecard)
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes and add tests
4. Run the test suite: `pytest tests/ -v`
5. Submit a pull request

Please open an issue first for major changes to discuss the approach.

## Author

**Mahesh Makvana** — [GitHub](https://github.com/maheshmakvana) · [PyPI](https://pypi.org/user/maheshmakvana/)

MIT License
