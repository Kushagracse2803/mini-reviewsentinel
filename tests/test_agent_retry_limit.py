import json

from app.agent import run_agentic_review
from app.llm_review import FakeLLMClient


def _needs_context_response() -> str:
    return json.dumps(
        {
            "risk_level": "MEDIUM",
            "findings": [],
            "summary": "Not sure yet.",
            "needs_more_context": True,
            "context_request": "Is this reachable from user input?",
        }
    )


class CountingFakeClient(FakeLLMClient):
    def __init__(self, response_text: str):
        super().__init__(response_text=response_text)
        self.calls = 0

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        self.calls += 1
        return super().complete(system_prompt, user_prompt)


def test_agent_stops_at_max_iterations():
    """assignment Section 6: 'must have a maximum number of
    iterations/retries and must not be capable of looping indefinitely.'"""
    client = CountingFakeClient(_needs_context_response())
    result = run_agentic_review("app.py", "eval(x)", [], client, max_iterations=2)

    assert result.iterations == 2
    assert client.calls == 3  # initial call + 2 follow-ups, never more
    assert result.outcome.status == "ok"
    assert result.outcome.data.needs_more_context is True
    # Still "unresolved" after hitting the cap -- and that's fine. The
    # DECISION layer (not the agent) is responsible for defaulting an
    # unresolved MEDIUM-risk case to REVIEW_REQUIRED rather than looping
    # forever trying to reach certainty.


def test_agent_stops_early_when_llm_becomes_confident():
    responses = iter(
        [
            _needs_context_response(),
            json.dumps(
                {
                    "risk_level": "LOW",
                    "findings": [],
                    "summary": "Confirmed safe.",
                    "needs_more_context": False,
                    "context_request": None,
                }
            ),
        ]
    )

    class SequencedClient:
        def complete(self, system_prompt: str, user_prompt: str) -> str:
            return next(responses)

    result = run_agentic_review("app.py", "eval(x)", [], SequencedClient(), max_iterations=5)
    assert result.iterations == 1
    assert result.outcome.data.needs_more_context is False
