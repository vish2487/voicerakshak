from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse

from app.fraud_detection import MAX_MESSAGE_LENGTH, assess_message

app = FastAPI(
    title="VoiceRakshak AI API",
    description="A minimal API for the VoiceRakshak AI application.",
    version="0.1.0",
)


@app.exception_handler(RequestValidationError)
async def sanitized_validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
    """Avoid reflecting submitted message content in validation responses."""
    details = [
        {"loc": error.get("loc", ()), "msg": error.get("msg", "Invalid request"), "type": error.get("type", "value_error")}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": details})


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    """Report that the API process is ready."""
    return {"status": "ok"}


class AssessmentRequest(BaseModel):
    message: str = Field(min_length=1, max_length=MAX_MESSAGE_LENGTH)
    source_type: Literal["call", "SMS", "WhatsApp", "other"] = "other"
    language: Literal["en-IN", "hi-IN", "mr-IN", "ta-IN"] = "en-IN"


class IndicatorResponse(BaseModel):
    code: str
    label: str
    explanation: str


class AssessmentResponse(BaseModel):
    risk_classification: Literal["high", "caution", "insufficient_information"]
    matched_indicators: list[IndicatorResponse]
    explanations: list[str]
    recommended_actions: list[str]
    clarifying_question: str | None
    safety_disclaimer: str


@app.post("/assess", response_model=AssessmentResponse, tags=["assessment"])
def assess(payload: AssessmentRequest) -> AssessmentResponse:
    """Assess text for a limited set of safety warning patterns.

    The request body is processed in memory and is never logged or persisted.
    """
    if not payload.message.strip():
        raise HTTPException(status_code=422, detail="message must not be blank")

    result = assess_message(payload.message, payload.language)
    return AssessmentResponse(
        risk_classification=result.risk_classification,
        matched_indicators=[indicator.__dict__ for indicator in result.matched_indicators],
        explanations=result.explanations,
        recommended_actions=result.recommended_actions,
        clarifying_question=result.clarifying_question,
        safety_disclaimer=result.safety_disclaimer,
    )
