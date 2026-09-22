"""
FastAPI service exposing the review pipeline over HTTP.

Routes are plain `def`, not `async def` -- every function this pipeline
calls (AST parsing, the OpenAI SDK, our own decision logic) is
synchronous. FastAPI runs `def` routes in a worker thread pool
automatically, so the server stays responsive under concurrent requests
without us writing async/await through static_analysis, llm_review,
decision_engine, and agent.py just to satisfy the web framework.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException

from app.models import ReviewRequest, ReviewResponse
from app.pipeline import IdempotencyConflictError, review_files

app = FastAPI(title="Mini ReviewSentinel")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/review", response_model=ReviewResponse)
def review(request: ReviewRequest) -> ReviewResponse:
    if not request.files:
        raise HTTPException(status_code=400, detail="No files provided.")
    try:
        return review_files(request.request_id, request.files)
    except IdempotencyConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
