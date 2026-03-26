from pydantic import BaseModel, Field
from typing import Optional


class ChatRequest(BaseModel):
    prompt: Optional[str] = None
    messages: Optional[list] = None
    system: Optional[str] = "You are a helpful assistant. /no_think"
    max_tokens: Optional[int] = 512
    temperature: Optional[float] = 0.7
    response_format: Optional[dict] = None


class ClassifyRequest(BaseModel):
    message: str


class GuardrailResult(BaseModel):
    passed: bool
    action: str = Field(description="One of: block, warn, log, pass")
    guardrail_name: str
    message: Optional[str] = None
    details: Optional[dict] = None
    latency_ms: float = 0.0


class PipelineResult(BaseModel):
    allowed: bool
    results: list[GuardrailResult] = Field(default_factory=list)
    total_latency_ms: float = 0.0


class ShieldResponse(BaseModel):
    """Wraps a gateway/LLM response with guardrail information."""

    text: Optional[str] = None
    usage: Optional[dict] = None
    inference_time_ms: Optional[float] = None
    guardrail_results: Optional[PipelineResult] = None
    blocked: bool = False
    block_reason: Optional[str] = None
