"""
Orchestrates one review end-to-end: static analysis -> prompt-injection
scan -> agentic LLM review -> decision engine -> ReviewResponse.

Both app/api.py (the HTTP service) and app/main.py (the CLI) call
`review_files()`, so there is exactly one place the pipeline is
assembled -- neither entrypoint re-implements the ordering, or the
idempotency logic below.

=== Repeated execution (assignment Section 8) ===

Requests are keyed by a client-supplied `request_id`. Two behaviours:

  - Same request_id + same file content  -> the cached ReviewResponse is
    returned with `cached=True`, and the pipeline (and any LLM calls) are
    NOT re-run. This is the "accidentally submitted twice" case.

  - Same request_id + DIFFERENT file content -> raises
    IdempotencyConflictError instead of silently returning the old
    result. A naive cache-by-id-only implementation would return a
    resultthat looks valid but describes the WRONG code -- worse than an
    error, because nothing signals that anything went wrong. This mirrors
    how real idempotency-key APIs (e.g. Stripe) treat key reuse with a
    different payload as a conflict, not a cache hit.

The store is an in-memory dict -- intentionally simple. See README "Known
limitations" for what that does and doesn't guarantee outside a single
process.
"""

from __future__ import annotations

import hashlib
from typing import Optional

from app.agent import run_agentic_review
from app.decision_engine import decide
from app.llm_review import LLMClient, LLMOutcome, OpenAIClient, settings
from app.models import Decision, FileInput, Finding, ReviewResponse, Source
from app.sanitize import detect_prompt_injection
from app.static_analysis import analyze_file


class IdempotencyConflictError(Exception):
    """Raised when a request_id is reused with different file content."""


_SEEN_REQUESTS: dict[str, tuple[str, ReviewResponse]] = {}

_DECISION_ORDER = {Decision.APPROVED: 0, Decision.REVIEW_REQUIRED: 1, Decision.REJECTED: 2}


def _combine(a: Decision, b: Decision) -> Decision:
    """Worst-of across files: a multi-file review can't be APPROVED if any
    single file in it was REJECTED or needs review."""
    return a if _DECISION_ORDER[a] >= _DECISION_ORDER[b] else b


def _content_hash(files: list[FileInput]) -> str:
    digest = hashlib.sha256()
    for f in sorted(files, key=lambda x: x.filename):
        digest.update(f.filename.encode())
        digest.update(b"\0")
        digest.update(f.content.encode())
        digest.update(b"\0")
    return digest.hexdigest()


def _default_client() -> LLMClient:
    if not settings.openai_api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is not set. Provide one in .env, or pass an explicit "
            "`client=` to review_files() (tests do this with FakeLLMClient)."
        )
    return OpenAIClient(settings.openai_api_key, settings.llm_model, settings.llm_timeout_seconds)


def review_files(
    request_id: str,
    files: list[FileInput],
    client: Optional[LLMClient] = None,
) -> ReviewResponse:
    content_hash = _content_hash(files)

    if request_id in _SEEN_REQUESTS:
        cached_hash, cached_response = _SEEN_REQUESTS[request_id]
        if cached_hash == content_hash:
            return cached_response.model_copy(update={"cached": True})
        raise IdempotencyConflictError(
            f"request_id {request_id!r} was already used for different file content. "
            "Use a new request_id for a genuinely new review."
        )

    all_findings: list[Finding] = []
    static_errors: list[str] = []
    llm_summaries: list[str] = []
    llm_available = True
    conflict_detected = False
    conflict_notes: list[str] = []
    total_iterations = 0
    overall_decision = Decision.APPROVED

    resolved_client = client
    if resolved_client is None:
        try:
            resolved_client = _default_client()
        except RuntimeError as exc:
            llm_available = False
            static_errors.append(str(exc))

    for file in files:
        injection_findings = detect_prompt_injection(file.filename, file.content)
        static_findings, errors = analyze_file(file.filename, file.content)
        static_findings = static_findings + injection_findings
        static_errors.extend(errors)
        all_findings.extend(static_findings)

        if resolved_client is not None:
            agent_result = run_agentic_review(file.filename, file.content, static_findings, resolved_client)
            total_iterations += agent_result.iterations
            outcome = agent_result.outcome
        else:
            outcome = LLMOutcome(status="unavailable", error="No LLM client configured.")

        if outcome.status != "ok" or outcome.data is None:
            llm_available = False
        else:
            llm_summaries.append(f"{file.filename}: {outcome.data.summary}")
            all_findings.extend(
                Finding(
                    file=f.file or file.filename,
                    line=f.line,
                    finding=f.finding,
                    severity=f.severity,
                    evidence=f.evidence,
                    recommendation=f.recommendation,
                    source=Source.LLM,
                )
                for f in outcome.data.findings
            )

        file_decision, file_conflict, file_notes = decide(static_findings, outcome)
        conflict_detected = conflict_detected or file_conflict
        conflict_notes.extend(f"{file.filename}: {n}" for n in file_notes)
        overall_decision = _combine(overall_decision, file_decision)

    response = ReviewResponse(
        request_id=request_id,
        decision=overall_decision,
        findings=all_findings,
        static_summary=(
            f"{len(all_findings)} total findings across {len(files)} file(s); "
            f"{len(static_errors)} analysis error(s)."
            + (f" Errors: {'; '.join(static_errors)}" if static_errors else "")
        ),
        llm_summary="; ".join(llm_summaries) if llm_summaries else "(no usable LLM output)",
        llm_available=llm_available,
        conflict_detected=conflict_detected,
        conflict_notes=conflict_notes,
        agent_iterations=total_iterations,
    )
    _SEEN_REQUESTS[request_id] = (content_hash, response)
    return response
