"""Exceptions for cyberscorecard."""


class CyberscorecardError(Exception):
    """Base exception for cyberscorecard."""


class AssessmentError(CyberscorecardError):
    """Raised when security assessment fails."""


class ValidationError(CyberscorecardError):
    """Raised on invalid assessment data."""


class ReportError(CyberscorecardError):
    """Raised on report generation failure."""
