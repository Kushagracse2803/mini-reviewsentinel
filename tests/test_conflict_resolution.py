from app.decision_engine import decide
from app.llm_review import LLMOutcome
from app.models import Decision, Finding, LLMReviewOutput, Severity, Source


def _static_finding(severity: Severity) -> list[Finding]:
    return [
        Finding(
            file="payments.py",
            line=42,
            finding="SQL Injection",
            severity=severity,
            evidence="e",
            recommendation="r",
            source=Source.STATIC,
            rule_id="SQLI001",
        )
    ]


def test_static_high_llm_low_static_wins():
    """assignment Section 5: 'Static Analysis: HIGH RISK / LLM Review: LOW RISK'."""
    static_findings = _static_finding(Severity.HIGH)
    llm_outcome = LLMOutcome(
        status="ok",
        data=LLMReviewOutput(risk_level=Severity.LOW, findings=[], summary="Looks fine to me."),
    )
    decision, conflict, notes = decide(static_findings, llm_outcome)
    assert decision == Decision.REJECTED
    assert conflict is True
    assert notes


def test_static_low_llm_high_capped_at_review_required():
    """assignment Section 5, reverse case: 'Static Analysis: LOW RISK / LLM
    Review: HIGH RISK'. The LLM alone cannot REJECT."""
    llm_outcome = LLMOutcome(
        status="ok",
        data=LLMReviewOutput(risk_level=Severity.HIGH, findings=[], summary="Looks like a broken auth check."),
    )
    decision, conflict, notes = decide([], llm_outcome)
    assert decision == Decision.REVIEW_REQUIRED
    assert conflict is True


def test_both_agree_low_is_approved():
    llm_outcome = LLMOutcome(status="ok", data=LLMReviewOutput(risk_level=Severity.LOW, findings=[], summary="Clean."))
    decision, conflict, notes = decide([], llm_outcome)
    assert decision == Decision.APPROVED
    assert conflict is False


def test_both_agree_high_is_rejected():
    static_findings = _static_finding(Severity.HIGH)
    llm_outcome = LLMOutcome(
        status="ok",
        data=LLMReviewOutput(risk_level=Severity.HIGH, findings=[], summary="Confirmed SQL injection."),
    )
    decision, conflict, notes = decide(static_findings, llm_outcome)
    assert decision == Decision.REJECTED
    assert conflict is False
