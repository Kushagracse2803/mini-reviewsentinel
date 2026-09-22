import json

from app.llm_review import FakeLLMClient, call_llm_review


def test_malformed_llm_output_does_not_crash():
    """assignment Section 8: what if the model returns 'Here is my
    analysis...' instead of the expected JSON?"""
    client = FakeLLMClient(response_text="Sure! Here's my analysis of this code...")
    outcome = call_llm_review("app.py", "print(1)", [], client)
    assert outcome.status == "malformed"
    assert outcome.data is None


def test_llm_unavailable_is_handled_not_raised():
    """assignment Section 8: what if the LLM API fails or times out?"""
    client = FakeLLMClient(fail=True)
    outcome = call_llm_review("app.py", "print(1)", [], client, max_retries=1)
    assert outcome.status == "unavailable"
    assert outcome.data is None


def test_json_wrapped_in_markdown_fence_is_recovered():
    payload = json.dumps(
        {
            "risk_level": "LOW",
            "findings": [],
            "summary": "fine",
            "needs_more_context": False,
            "context_request": None,
        }
    )
    client = FakeLLMClient(response_text=f"```json\n{payload}\n```")
    outcome = call_llm_review("app.py", "print(1)", [], client)
    assert outcome.status == "ok"
    assert outcome.data.risk_level.value == "LOW"
