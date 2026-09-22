from fastapi.testclient import TestClient

from app.api import app

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_review_without_llm_configured_falls_back_to_static_only():
    """No OPENAI_API_KEY is set in this environment, so this exercises the
    'LLM unavailable' reliability path for real, through the actual HTTP
    layer -- no network access or API key required for this test to run."""
    payload = {
        "request_id": "api-test-no-llm",
        "files": [{"filename": "app.py", "content": "eval(x)\n"}],
    }
    resp = client.post("/review", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["llm_available"] is False
    assert any(f["finding"].startswith("Dangerous use of eval") for f in body["findings"])
    assert body["decision"] in ("REVIEW_REQUIRED", "REJECTED")


def test_empty_files_rejected_with_400():
    resp = client.post("/review", json={"request_id": "api-test-empty", "files": []})
    assert resp.status_code == 400
