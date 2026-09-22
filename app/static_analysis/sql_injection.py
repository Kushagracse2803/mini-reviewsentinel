"""
Deterministic SQL-injection detector.

Approach: walk the AST (not regex) looking for calls that look like
`<something>.execute(...)` / `.executemany(...)` / `.executescript(...)`,
then classify the FIRST argument:

  - an f-string (ast.JoinedStr) with an interpolated value  -> dynamic
  - a string built with `+`                                  -> dynamic
  - a call to `.format(...)`                                 -> dynamic
  - `%` string formatting (`"..." % x`)                      -> dynamic
  - a plain string literal, whether inline or assigned to a
    variable earlier in the same file                        -> safe

We use the AST instead of regex because "is this string concatenation" is
a syntax question, not a text-pattern question -- regex would either miss
multi-line cases or misfire on string concatenation that has nothing to do
with a SQL call. AST also gives an exact line number for free, and lets us
resolve the common "build the query in a variable, execute it two lines
later" pattern shown in the assignment brief by tracing the variable back
to its last assignment before the call.

Scope/limitations (documented honestly, see README "Known limitations"):
this is a single-file, best-effort backward scan for the exact pattern in
the brief -- it is not full data-flow analysis. It will not trace a value
across function calls or across files, and an f-string that only
interpolates a module-level *constant* (not user input) is still flagged,
because proving a value can never be influenced by external input would
require real taint tracking, which is out of scope here. We deliberately
err toward over-flagging rather than trying to prove safety we can't
verify -- see README "Hidden cases" for a worked example.
"""

from __future__ import annotations

import ast

from app.models import Finding, Severity, Source

_EXECUTE_METHODS = {"execute", "executemany", "executescript"}


def _is_dynamic_sql_expr(node: ast.AST) -> bool:
    """True if `node` builds a string in a way that could inject untrusted
    data straight into SQL text (f-string, +, .format(), % formatting)."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(p, ast.FormattedValue) for p in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":
            return True
    return False


def _find_last_assignment(tree: ast.AST, name: str, before_line: int) -> ast.AST | None:
    """Best-effort: find the value assigned to `name` most recently before
    `before_line`. Not full data-flow analysis -- a linear scan is enough
    to handle the "assign then execute" pattern in the assignment brief."""
    candidates = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and getattr(node, "lineno", 0) < before_line:
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    candidates.append(node)
    if not candidates:
        return None
    candidates.sort(key=lambda n: n.lineno)
    return candidates[-1].value


def analyze(filename: str, source: str) -> tuple[list[Finding], str | None]:
    """Returns (findings, error). `error` is set (findings will be empty)
    if the file could not be parsed -- e.g. invalid Python syntax, or a
    different language entirely. Callers must handle this explicitly
    rather than assume every file yields findings (assignment Section 8,
    "analysis failure")."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        return [], f"Could not parse {filename} as Python: {exc}"

    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        if node.func.attr not in _EXECUTE_METHODS:
            continue
        if not node.args:
            continue

        first_arg = node.args[0]
        target_expr = first_arg
        resolved_via_variable = False

        if isinstance(first_arg, ast.Name):
            assigned = _find_last_assignment(tree, first_arg.id, node.lineno)
            if assigned is not None:
                target_expr = assigned
                resolved_via_variable = True

        if _is_dynamic_sql_expr(target_expr):
            evidence = (
                "Query text is built with an f-string/concatenation/`.format()`/`%` "
                "and passed directly to a SQL execute call"
                + (f" (via variable `{first_arg.id}`)" if resolved_via_variable else "")
                + ", allowing the interpolated value to change the SQL statement itself."
            )
            findings.append(
                Finding(
                    file=filename,
                    line=node.lineno,
                    finding="SQL Injection",
                    severity=Severity.HIGH,
                    evidence=evidence,
                    recommendation=(
                        "Use a parameterized query: pass SQL text as a plain string with "
                        "placeholders (e.g. `?` or `%s`) and supply values as a separate "
                        "argument, e.g. cursor.execute(\"SELECT * FROM t WHERE id = ?\", "
                        "(value,))."
                    ),
                    source=Source.STATIC,
                    rule_id="SQLI001",
                )
            )
        # else: a plain literal string (optionally with a params argument) --
        # this is the safe, parameterized pattern. No finding.

    return findings, None
