"""
Shared data shapes used across the whole app.

Every other module (static analysis, LLM review, the decision engine, the
agent loop, the API, the CLI) imports its Finding/Decision/Severity shapes
from here instead of defining its own. That's deliberate: if the shape of
a Finding ever changes, there is exactly ONE file to edit, and every module
that produces or consumes findings stays in sync automatically.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Decision(str, Enum):
    APPROVED = "APPROVED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    REJECTED = "REJECTED"


class Source(str, Enum):
    """Where a finding came from. Kept explicit so the decision engine can
    apply different trust levels to static vs. LLM findings (see
    decision_engine.py)."""

    STATIC = "static_analysis"
    LLM = "llm_review"


class Finding(BaseModel):
    file: str
    line: int = Field(ge=0, description="1-indexed line number, 0 if unknown")
    finding: str  # short title, e.g. "SQL Injection"
    severity: Severity
    evidence: str
    recommendation: str
    source: Source
    rule_id: Optional[str] = None  # e.g. "SQLI001" -- lets tests target one rule precisely


class FileInput(BaseModel):
    filename: str
    content: str


class ReviewRequest(BaseModel):
    request_id: str = Field(description="Client-supplied idempotency key")
    files: list[FileInput]


class LLMFinding(BaseModel):
    """What we ASK the LLM to return per finding. Deliberately narrower
    than Finding -- the LLM does not get to set its own `source` or
    `rule_id`; those are assigned by our code, never trusted from model
    output."""

    file: str
    line: int = 0
    finding: str
    severity: Severity
    evidence: str
    recommendation: str


class LLMReviewOutput(BaseModel):
    """The full JSON schema we require from the LLM. If the model's raw
    response doesn't fit this shape, pydantic raises ValidationError and
    llm_review.py treats that as a failed call -- never a crash, and never
    silently-accepted garbage."""

    risk_level: Severity
    findings: list[LLMFinding] = Field(default_factory=list)
    summary: str
    needs_more_context: bool = False
    context_request: Optional[str] = None


class ReviewResponse(BaseModel):
    request_id: str
    decision: Decision
    findings: list[Finding]
    static_summary: str
    llm_summary: str
    llm_available: bool
    conflict_detected: bool
    conflict_notes: list[str] = Field(default_factory=list)
    agent_iterations: int = 0
    cached: bool = False
