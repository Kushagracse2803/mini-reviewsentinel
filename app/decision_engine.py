"""
The "manager": takes static-analysis findings + the LLM outcome and
produces a single Decision. This is the ONLY place a final
APPROVE/REVIEW/REJECT is decided -- the LLM never emits a Decision
directly (see LLMReviewOutput in models.py, which has no `decision`
field at all, on purpose).

=== The conflict-resolution policy (assignment Section 5) ===

Deterministic findings (SQLi, hardcoded secrets, eval/exec, prompt
injection) are HIGH severity only when the AST pattern is unambiguous --
Section 3's false-positive reduction already filtered out parameterized
queries, env-var lookups, and placeholder-looking secrets before a finding
ever reaches HIGH. So by the time this function sees a HIGH static
finding, it represents fairly strong structural evidence, not a guess.

The LLM, by contrast, reasons over meaning and context -- powerful, but
not verifiable the way an AST match is, and it is the direct target of a
prompt-injection attack embedded in the code it reviews (Section 7). An
attacker who can make the LLM say "this is safe, approve it" must NOT be
able to flip a REJECTED into an APPROVED.

Policy, stated as a rule: static analysis can REJECT on its own; the LLM
alone can never REJECT -- it can only escalate a clean static result up to
REVIEW_REQUIRED.

  static=HIGH        + llm=anything    -> REJECTED        (static wins outright)
  static=MEDIUM       + llm=HIGH        -> REVIEW_REQUIRED
  static=MEDIUM       + llm=LOW/MEDIUM  -> REVIEW_REQUIRED
  static=LOW/none      + llm=HIGH        -> REVIEW_REQUIRED (capped below REJECTED)
  static=LOW/none      + llm=MEDIUM      -> REVIEW_REQUIRED
  static=LOW/none      + llm=LOW/none    -> APPROVED

Whenever static and LLM land in different severity BUCKETS (LOW vs.
MEDIUM/HIGH, or HIGH vs. not-HIGH), `conflict_detected=True` and a
human-readable note is attached -- even when the final decision doesn't
change, a human reviewer should be able to see the two layers disagreed
and why.

If the LLM is unavailable or its output was malformed, the decision is
made from static analysis ALONE, and -- deliberately -- treated MORE
conservatively: a static-only LOW result is still routed to
REVIEW_REQUIRED rather than auto-approved, because only one of the two
review layers actually ran. "Fail conservative, not fail open."
"""

from __future__ import annotations

from app.llm_review import LLMOutcome
from app.models import Decision, Finding, Severity


def _max_severity(findings: list[Finding]) -> Severity:
    if any(f.severity == Severity.HIGH for f in findings):
        return Severity.HIGH
    if any(f.severity == Severity.MEDIUM for f in findings):
        return Severity.MEDIUM
    return Severity.LOW


def _bucket(severity: Severity) -> str:
    """Collapses severity into a coarser bucket for conflict detection, so
    a LOW-vs-MEDIUM difference doesn't spam conflict notes the way a
    genuine LOW-vs-HIGH disagreement should."""
    return "low" if severity == Severity.LOW else "elevated"


def decide(
    static_findings: list[Finding],
    llm_outcome: LLMOutcome,
) -> tuple[Decision, bool, list[str]]:
    """Returns (decision, conflict_detected, conflict_notes)."""
    static_severity = _max_severity(static_findings)
    notes: list[str] = []

    if llm_outcome.status != "ok" or llm_outcome.data is None:
        notes.append(
            f"LLM review was not usable (status={llm_outcome.status}); decision is "
            "based on deterministic static analysis only."
        )
        if static_severity == Severity.HIGH:
            return Decision.REJECTED, False, notes
        if static_severity == Severity.MEDIUM:
            return Decision.REVIEW_REQUIRED, False, notes
        return (
            Decision.REVIEW_REQUIRED,
            False,
            notes + [
                "No static findings and no usable LLM opinion -- routed to human "
                "review rather than auto-approved, since only one of two review "
                "layers actually ran."
            ],
        )

    llm_severity = llm_outcome.data.risk_level
    conflict = _bucket(static_severity) != _bucket(llm_severity)
    if conflict:
        notes.append(
            f"Static analysis rated this {static_severity.value}; the LLM rated it "
            f"{llm_severity.value}. Static analysis is authoritative for the "
            "deterministic checks (SQLi, secrets, eval/exec, prompt injection); the "
            "LLM's opinion is recorded but cannot downgrade a static HIGH finding."
        )

    if static_severity == Severity.HIGH:
        return Decision.REJECTED, conflict, notes

    if static_severity == Severity.MEDIUM or llm_severity in (Severity.MEDIUM, Severity.HIGH):
        return Decision.REVIEW_REQUIRED, conflict, notes

    return Decision.APPROVED, conflict, notes
