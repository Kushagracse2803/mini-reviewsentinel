"""
Runs every deterministic detector against a single file and aggregates the
results. This is the ONLY place that needs to know the full list of
detectors -- adding a new deterministic check later means adding one entry
to `_DETECTORS` here, not touching the pipeline.
"""

from __future__ import annotations

from app.models import Finding
from . import dangerous_eval, secrets, sql_injection

_DETECTORS = [sql_injection.analyze, secrets.analyze, dangerous_eval.analyze]


def analyze_file(filename: str, source: str) -> tuple[list[Finding], list[str]]:
    """Returns (findings, errors). A detector that fails to parse the file
    contributes an error string instead of raising -- one unparsable file
    must not take down analysis of every other file in the request
    (assignment Section 8, "analysis failure")."""
    findings: list[Finding] = []
    errors: list[str] = []
    for detector in _DETECTORS:
        try:
            file_findings, error = detector(filename, source)
        except Exception as exc:  # a detector bug must not crash the whole request
            errors.append(f"{detector.__module__} raised an unexpected error on {filename}: {exc}")
            continue
        findings.extend(file_findings)
        if error:
            errors.append(error)
    return findings, errors
