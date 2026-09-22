"""
The agentic re-evaluation loop (assignment Section 6).

Purposefully small: this is NOT a general-purpose autonomous agent. It
handles exactly one situation -- the LLM itself reports it doesn't have
enough context to be confident (`needs_more_context=True` in its
structured output) -- by gathering one extra, DETERMINISTIC piece of
context and asking the LLM to reconsider, up to a hard cap.

Why deterministic context-gathering, and not "ask another LLM to fetch
context"? Section 5 explicitly says "do not simply add another LLM and
ask it to decide" for conflicting evidence, and the same reasoning
applies here: every additional model call is another chance for prompt
injection or hallucination to creep in, with no new verifiable signal.
A cheap, inspectable, rule-based context step (e.g. "is this file under a
tests/ path?") is enough to resolve genuine ambiguity without adding
another black box.

Termination is guaranteed by a plain iteration counter checked BEFORE
each follow-up LLM call -- there is no code path that calls the LLM again
without first checking `iterations < max_iterations`, so this cannot loop
indefinitely regardless of what the LLM returns.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.llm_review import LLMClient, LLMOutcome, call_llm_review, settings
from app.models import Finding


def _gather_additional_context(filename: str, source: str, requested: Optional[str]) -> str:
    """Deterministic, rule-based context gathering. Deliberately simple --
    this is a lookup, not reasoning, and it is the only thing allowed to
    run between agent iterations."""
    notes = []
    normalized = filename.replace("\\", "/").lower()
    if "test" in normalized:
        notes.append(f"{filename} is located in a test/fixture path, not application code.")
    if requested:
        notes.append(
            f"LLM specifically asked: {requested!r} -- no automated source for this is "
            "available; a human should confirm."
        )
    if not notes:
        notes.append("No additional deterministic context was available for this request.")
    return " ".join(notes)


@dataclass
class AgentResult:
    outcome: LLMOutcome
    iterations: int


def run_agentic_review(
    filename: str,
    source: str,
    static_findings: list[Finding],
    client: LLMClient,
    max_iterations: Optional[int] = None,
) -> AgentResult:
    cap = settings.agent_max_iterations if max_iterations is None else max_iterations
    context_notes: list[str] = []
    iterations = 0

    outcome = call_llm_review(filename, source, static_findings, client, extra_context=context_notes)

    while (
        outcome.status == "ok"
        and outcome.data is not None
        and outcome.data.needs_more_context
        and iterations < cap
    ):
        iterations += 1
        context_notes.append(_gather_additional_context(filename, source, outcome.data.context_request))
        outcome = call_llm_review(filename, source, static_findings, client, extra_context=context_notes)

    return AgentResult(outcome=outcome, iterations=iterations)
