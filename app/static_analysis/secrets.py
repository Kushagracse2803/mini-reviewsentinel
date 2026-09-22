"""
Deterministic hardcoded-secret detector.

Two independent heuristics, carrying different confidence:

1. Pattern match on KNOWN secret formats (AWS access key ids, OpenAI-style
   `sk-...` keys, GitHub `ghp_...` tokens). Checked without caring about
   the variable name at all -- a leaked key is a leaked key regardless of
   what it's assigned to. -> HIGH severity, rule SECRET_PATTERN.

2. Variable-name heuristic: an assignment like `api_key = "<literal>"`
   where the name matches a secret-ish keyword (api_key, password, secret,
   token, access_key, private_key, auth_key). -> only MEDIUM severity,
   and only after false-positive filtering, because variable names lie
   constantly (assignment Section 3 warns about exactly this).

False-positive reduction for heuristic #2:
  - Skip if the right-hand side is not a plain string literal at all (e.g.
    `os.environ["API_KEY"]`, `os.getenv(...)`, `settings.api_key`, or a
    reference to another variable) -- that IS the correct pattern: reading
    a secret from config/env rather than hardcoding it.
  - Skip short values (< 8 chars) and common placeholder text ("changeme",
    "xxx", "your-api-key-here", "test", "password", ...) -- these are
    almost always examples/placeholders, not real secrets.
  - Skip values shaped like an ENV_VAR_NAME (`DB_PASSWORD`) -- a common
    false-positive is a variable that holds the *name* of an env var, not
    a credential value (see README "Hidden cases").
"""

from __future__ import annotations

import ast
import re

from app.models import Finding, Severity, Source

_SECRET_KEYWORDS = re.compile(
    r"(api[_-]?key|secret|password|passwd|token|access[_-]?key|private[_-]?key|auth[_-]?key)",
    re.IGNORECASE,
)

_PLACEHOLDER_VALUES = {
    "", "changeme", "change_me", "xxx", "xxxx", "yourapikeyhere",
    "your-api-key-here", "<password>", "<api_key>", "test", "password",
    "secret", "placeholder", "todo", "fixme", "example",
}

_HIGH_CONFIDENCE_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),      # AWS access key id
    re.compile(r"sk-[A-Za-z0-9]{20,}"),    # OpenAI-style secret key
    re.compile(r"ghp_[A-Za-z0-9]{36}"),    # GitHub personal access token
]

_ENV_VAR_NAME_RE = re.compile(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$")


def _looks_like_placeholder(value: str) -> bool:
    stripped = value.strip()
    return stripped.lower() in _PLACEHOLDER_VALUES or len(stripped) < 8


def _looks_like_env_var_name(value: str) -> bool:
    """Catches a common false positive: `db_password_env = "DB_PASSWORD"`
    -- the literal is the NAME of an env var, not a credential value."""
    return bool(_ENV_VAR_NAME_RE.match(value.strip()))


def analyze(filename: str, source: str) -> tuple[list[Finding], str | None]:
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as exc:
        return [], f"Could not parse {filename} as Python: {exc}"

    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if not targets:
            continue

        value_node = node.value
        literal_value = (
            value_node.value
            if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str)
            else None
        )

        if literal_value:
            for pattern in _HIGH_CONFIDENCE_PATTERNS:
                if pattern.fullmatch(literal_value.strip()) or pattern.search(literal_value):
                    key = (node.lineno, "SECRET_PATTERN")
                    if key not in seen:
                        seen.add(key)
                        findings.append(
                            Finding(
                                file=filename,
                                line=node.lineno,
                                finding="Hardcoded Secret",
                                severity=Severity.HIGH,
                                evidence=(
                                    f"Value assigned to `{targets[0]}` matches a known "
                                    "secret key format."
                                ),
                                recommendation=(
                                    "Load this value from an environment variable or a "
                                    "secrets manager instead of committing it to source."
                                ),
                                source=Source.STATIC,
                                rule_id="SECRET_PATTERN",
                            )
                        )
                    break

        if literal_value is None:
            continue
        if (node.lineno, "SECRET_PATTERN") in seen:
            continue  # already reported with higher confidence; don't double-report the same line
        if _looks_like_placeholder(literal_value) or _looks_like_env_var_name(literal_value):
            continue

        for name in targets:
            if not _SECRET_KEYWORDS.search(name):
                continue
            key = (node.lineno, "SECRET_KEYWORD")
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    file=filename,
                    line=node.lineno,
                    finding="Hardcoded Secret",
                    severity=Severity.MEDIUM,
                    evidence=(
                        f"Variable `{name}` looks like a credential and is assigned a "
                        "literal string."
                    ),
                    recommendation=(
                        "Load this value from an environment variable or a secrets "
                        "manager instead of hardcoding it."
                    ),
                    source=Source.STATIC,
                    rule_id="SECRET_KEYWORD",
                )
            )

    return findings, None
