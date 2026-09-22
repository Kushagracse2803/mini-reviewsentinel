"""
Thin CLI wrapper around the same pipeline the API uses:

    python -m app.main path/to/file_or_dir.py [more_files.py ...]

Uses `rich` for a readable table if it's installed; falls back to plain
print() if not, so the CLI never hard-fails over a cosmetic dependency.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path
from typing import Optional

from app.models import FileInput, ReviewResponse
from app.pipeline import IdempotencyConflictError, review_files


def _collect_files(paths: list[str]) -> list[FileInput]:
    files: list[FileInput] = []
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_dir():
            for py_file in sorted(path.rglob("*.py")):
                files.append(FileInput(filename=str(py_file), content=py_file.read_text()))
        elif path.is_file():
            files.append(FileInput(filename=str(path), content=path.read_text()))
        else:
            print(f"Skipping {raw_path}: not a file or directory", file=sys.stderr)
    return files


def _print_findings(response: ReviewResponse) -> None:
    try:
        from rich.console import Console
        from rich.table import Table

        table = Table(title=f"Mini ReviewSentinel -- {response.decision.value}")
        for col in ("File", "Line", "Finding", "Severity", "Source", "Recommendation"):
            table.add_column(col)
        for f in response.findings:
            table.add_row(f.file, str(f.line), f.finding, f.severity.value, f.source.value, f.recommendation)
        Console().print(table)
    except ImportError:
        for f in response.findings:
            print(f"{f.file}:{f.line}  [{f.severity.value}] {f.finding} ({f.source.value})")
            print(f"  Evidence: {f.evidence}")
            print(f"  Recommendation: {f.recommendation}\n")

    print(f"Overall decision: {response.decision.value}")
    if response.conflict_detected:
        print("Conflict between static analysis and LLM review:")
        for note in response.conflict_notes:
            print(f"  - {note}")
    if not response.llm_available:
        print(
            "Note: LLM review was unavailable or unusable for at least one file; "
            "decision falls back to static analysis for that file."
        )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Mini ReviewSentinel CLI")
    parser.add_argument("paths", nargs="+", help="Python file(s) or director(y/ies) to review")
    parser.add_argument("--request-id", default=None, help="Idempotency key; random if omitted")
    args = parser.parse_args(argv)

    files = _collect_files(args.paths)
    if not files:
        print("No Python files found.", file=sys.stderr)
        return 1

    request_id = args.request_id or str(uuid.uuid4())
    try:
        response = review_files(request_id, files)
    except IdempotencyConflictError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 3

    _print_findings(response)
    return 0 if response.decision.value != "REJECTED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
