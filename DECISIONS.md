# Design Decisions

## A. Static vs LLM disagreement

**Static = HIGH, LLM = LOW:** Static analysis wins outright. Decision is
`REJECTED` regardless of what the LLM says. Reasoning: by the time static
analysis reports HIGH, the false-positive-reduction pass (Section 3 of the
brief -- parameterized queries, env-var lookups, placeholder values are
all filtered out before a finding reaches HIGH) means we're looking at
fairly strong structural evidence, not a guess. The LLM is also the
literal target of a prompt-injection attack embedded in the code it's
reviewing (Section 7) -- an attacker who can make the LLM say "this is
safe" must not be able to flip a REJECTED into an APPROVED. Letting the
LLM override deterministic HIGH findings would make the injection attack
*work*.

**Static = LOW/none, LLM = HIGH:** Capped at `REVIEW_REQUIRED`, never
`REJECTED`. The LLM is good at spotting things static analysis structurally
cannot see (business logic, missing auth checks), but its claim has no
independent, deterministic corroboration. A false positive here is a
human spending five minutes confirming it's fine -- annoying, not
dangerous. A false REJECTED with no real issue is a much worse failure
mode for a review tool to normalize (it trains people to stop trusting
"REJECTED" and start rubber-stamping past it). So an LLM-only HIGH escalates
review, it doesn't unilaterally block.

Implementation: `app/decision_engine.py::decide()`.

## B. LLM failure

If the LLM API fails, times out, or isn't configured at all
(`OPENAI_API_KEY` unset), `call_llm_review()` retries transient failures
up to `LLM_MAX_RETRIES` times, then returns `LLMOutcome(status="unavailable")`
instead of raising. The decision engine treats this as "only one of two
review layers ran" and falls back to static-analysis-only, deliberately
**more conservative** than the normal path: a static-only LOW result is
still routed to `REVIEW_REQUIRED` rather than auto-approved, because we
lost a whole review layer and have no way to know what it would have
found. "Fail conservative, not fail open." This is exercised end-to-end
in `tests/test_api.py::test_review_without_llm_configured_falls_back_to_static_only`
with no API key or network access at all.

## C. LLM output validation

The LLM is asked (via the system prompt) to return one JSON object matching
a fixed schema. The raw response is validated against a Pydantic model
(`LLMReviewOutput`). If that fails, we try one recovery step -- extracting
a JSON object from markdown fences or surrounding prose, since models
sometimes wrap correct JSON in chatter despite instructions -- and
re-validate. If that also fails, the outcome is `status="malformed"`,
which the decision engine treats exactly like `"unavailable"` (static-only,
conservative fallback). The application code downstream of `llm_review.py`
never touches the LLM's raw text directly; it only ever sees a validated
`LLMReviewOutput` object or an explicit failure status. A response like
`"Here is my analysis..."` cannot cause an exception, a bad decision, or
a hang -- it's a two-line early return.

## D. Agent termination

`app/agent.py::run_agentic_review()` uses a plain iteration counter checked
*before* every follow-up LLM call: the while-loop condition includes
`iterations < cap`, and `cap` defaults to `AGENT_MAX_ITERATIONS` (2). There
is no code path that calls the LLM again without that check passing first,
so termination doesn't depend on the LLM ever cooperating -- even a model
that always returns `needs_more_context: true` forever stops after `cap`
follow-ups. Verified directly in
`tests/test_agent_retry_limit.py::test_agent_stops_at_max_iterations`,
which asserts the exact call count (`initial + cap`, never more).

We also deliberately kept the "gather more context" step **non-LLM** --
it's a small set of deterministic, rule-based lookups (e.g. "is this file
under a `tests/` path?"). The brief explicitly warns against resolving
disagreement by "simply adding another LLM and asking it to decide"; the
same logic applies to context-gathering -- another model call is another
chance for hallucination or injection, with no new verifiable signal.

## E. False positives

The hardest one is **the SQL-injection detector flagging an f-string with
a value we cannot prove is safe.** `query = f"SELECT * FROM {TABLE_NAME}"`
gets flagged HIGH exactly like `f"... WHERE id = {user_id}"`, even if
`TABLE_NAME` is a fixed module-level constant with no path to user input.
Telling these apart correctly requires real data-flow/taint analysis
(tracing every possible origin of a value across the whole program) --
well beyond what an AST pattern match can prove, and out of scope for this
assignment's time budget.

We handle it by choosing a side deliberately rather than accidentally: we
over-flag. A human dismissing an unnecessary HIGH finding costs a few
seconds; silently deciding an interpolated value is "probably fine" and
not flagging it is exactly how a real SQL injection ships. This is
documented in README "Known limitations" rather than hidden, and the
decision engine's static-wins policy means this kind of false positive
routes to `REJECTED` -- a human always sees it, it's never silently
swallowed.

## F. One trade-off

**The idempotency store is a plain in-memory `dict`, not a database or
distributed cache.** A production system handling concurrent requests
across multiple processes would need a shared store (Redis, a DB row with
a unique constraint on `request_id`) so "has this request_id been seen
before" is answered consistently no matter which process handles the
retry.

We chose the simpler in-memory version deliberately: this assignment runs
as a single process (CLI or a single `uvicorn` worker), so a dict already
correctly demonstrates the actual behaviour being tested -- detecting a
genuine duplicate request, and distinguishing it from an idempotency-key
collision with different content (see README "Hidden cases" #3). Building
real distributed-cache infrastructure for a single-process assignment
would be solving a problem we don't have yet, at the cost of time better
spent on the reasoning the brief says it's actually grading. The trade-off
is stated plainly rather than pretending the dict is production-ready.

---

## Actual test output (3+ tests, as required)

Captured directly from this implementation, `pytest -v`:

```
tests/test_sql_injection.py::test_fstring_sql_injection_detected PASSED
tests/test_sql_injection.py::test_parameterized_query_not_flagged PASSED
tests/test_sql_injection.py::test_direct_inline_concatenation_detected PASSED
tests/test_sql_injection.py::test_unparseable_file_reports_error_not_crash PASSED
tests/test_conflict_resolution.py::test_static_high_llm_low_static_wins PASSED
tests/test_conflict_resolution.py::test_static_low_llm_high_capped_at_review_required PASSED
tests/test_conflict_resolution.py::test_both_agree_low_is_approved PASSED
tests/test_conflict_resolution.py::test_both_agree_high_is_rejected PASSED
tests/test_agent_retry_limit.py::test_agent_stops_at_max_iterations PASSED
tests/test_agent_retry_limit.py::test_agent_stops_early_when_llm_becomes_confident PASSED

============================== 10 passed in 0.15s ==============================
```

Full suite: `29 passed` (see README Section 2 for how to reproduce).
