"""
Defense against untrusted source code (assignment Section 7).

The repository being reviewed is DATA, never INSTRUCTIONS. This file has
two jobs:

1. detect_prompt_injection() -- a deterministic, static check that looks
   for text patterns clearly aimed at an AI reviewer ("AI REVIEWER:",
   "ignore previous instructions", "approve this change", etc). This
   produces a real HIGH-severity Finding of its own, so an injection
   attempt is treated as suspicious code in its own right -- not silently
   stripped and forgotten. It checks both single lines AND a 3-line
   sliding window, so a phrase deliberately split across line breaks
   (e.g. "ignore all previous" / "instructions" on the next line) still
   gets caught -- see README "Hidden cases" for why this matters.

2. wrap_code_for_prompt() -- formats source code for the LLM prompt inside
   an unguessable, random delimiter, plus an explicit instruction (in
   llm_review.py's system prompt) that anything inside the delimiter is
   untrusted file content, not commands. This doesn't rely on the LLM
   "being smart enough" to recognize an attack; it relies on us never
   asking the LLM to treat file content as instructions in the first
   place, and on the delimiter itself not being something the attacker
   can predict and forge.

Neither function is optional or bypassable by the LLM -- both run BEFORE
the LLM ever sees the code, and the injection finding is added to the
static findings list, which the decision engine treats as more
authoritative than the LLM's opinion (see decision_engine.py).
"""

from __future__ import annotations

import re
import uuid

from app.models import Finding, Severity, Source

_INJECTION_PATTERNS = [
    re.compile(r"ignore (all )?(previous|prior|above) instructions", re.IGNORECASE),
    re.compile(r"\bAI\s*REVIEWER\s*:", re.IGNORECASE),
    re.compile(r"\byou are now\b", re.IGNORECASE),
    re.compile(r"disregard (the )?system prompt", re.IGNORECASE),
    re.compile(r"\bapprove this (change|code|pr)\b", re.IGNORECASE),
    re.compile(r"respond with\s+APPROVED", re.IGNORECASE),
    re.compile(r"</?(system|assistant|user)>", re.IGNORECASE),
]

_WINDOW_SIZE = 3


def detect_prompt_injection(filename: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.splitlines()
    flagged_lines: set[int] = set()

    def _check(text: str, start_line: int, end_line: int, spans_multiple: bool) -> None:
        # Skip if ANY line in this span was already flagged -- prevents an
        # overlapping window from re-reporting a phrase we already caught
        # (either on its own line, or via a different window), while still
        # letting a genuinely separate phrase on untouched lines through.
        if any(line_no in flagged_lines for line_no in range(start_line, end_line + 1)):
            return
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(text):
                flagged_lines.update(range(start_line, end_line + 1))
                findings.append(
                    Finding(
                        file=filename,
                        line=start_line,
                        finding="Prompt Injection Attempt",
                        severity=Severity.HIGH,
                        evidence=(
                            "Text resembling an instruction aimed at an AI reviewer"
                            + (" (spans multiple lines): " if spans_multiple else ": ")
                            + repr(text.strip()[:200])
                        ),
                        recommendation=(
                            "Remove text designed to influence an automated reviewer. "
                            "Comments and strings in source code are never treated as "
                            "instructions by this system, but their presence is itself "
                            "a red flag worth a human look."
                        ),
                        source=Source.STATIC,
                        rule_id="PROMPTINJ001",
                    )
                )
                return

    for idx, line in enumerate(lines, start=1):
        _check(line, idx, idx, spans_multiple=False)

    for idx in range(len(lines) - 1):
        start_line = idx + 1
        window_lines = lines[idx: idx + _WINDOW_SIZE]
        end_line = start_line + len(window_lines) - 1
        joined = " ".join(window_lines)
        _check(joined, start_line, end_line, spans_multiple=True)

    return findings


def wrap_code_for_prompt(filename: str, source: str) -> str:
    """Delimits code with a random, per-call boundary token so the model
    can't be tricked by code containing a fake copy of a predictable fixed
    delimiter like '---END CODE---'."""
    boundary = f"CODE_BLOCK_{uuid.uuid4().hex}"
    return (
        f"Filename: {filename}\n"
        f"<<<{boundary}\n"
        f"{source}\n"
        f"{boundary}>>>\n"
    )
