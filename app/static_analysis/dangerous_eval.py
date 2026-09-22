"""
Detector for eval()/exec() usage.

Every use of eval/exec is flagged -- deliberately more aggressive than the
SQL/secrets detectors, since there is close to no legitimate reason to ship
eval()/exec() in application code. Severity is still risk-graded, not
binary:

  - eval/exec on a fixed string literal (e.g. eval("1 + 1"))  -> MEDIUM
    (bad practice, but nothing external can influence what runs)
  - eval/exec on anything else (a variable, an f-string, a function
    argument, concatenation, input() ...)                      -> HIGH
    (the executed code can vary based on data outside this line --
    the actual arbitrary-code-execution risk)
"""

from __future__ import annotations

import ast

from app.models import Finding, Severity, Source

_DANGEROUS_FUNCS = {"eval", "exec"}


def analyze(filename: str, source: str) -> tuple[list[Finding], str | None]:
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        return [], f"Could not parse {filename} as Python: {exc}"

    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        if node.func.id not in _DANGEROUS_FUNCS:
            continue
        if not node.args:
            continue

        arg = node.args[0]
        is_pure_literal = isinstance(arg, ast.Constant) and isinstance(arg.value, str)
        severity = Severity.MEDIUM if is_pure_literal else Severity.HIGH

        findings.append(
            Finding(
                file=filename,
                line=node.lineno,
                finding=f"Dangerous use of {node.func.id}()",
                severity=severity,
                evidence=(
                    f"`{node.func.id}()` is called with a fixed string literal."
                    if is_pure_literal
                    else (
                        f"`{node.func.id}()` is called with a non-literal argument, "
                        "meaning the executed code can vary based on external input."
                    )
                ),
                recommendation=(
                    f"Avoid `{node.func.id}()` entirely. Use `ast.literal_eval()` for "
                    "parsing literal data, or an explicit parser/dispatch table for "
                    "anything more dynamic."
                ),
                source=Source.STATIC,
                rule_id="EVALEXEC001",
            )
        )

    return findings, None
