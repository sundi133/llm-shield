import json
from datetime import datetime

from fastapi import APIRouter, HTTPException

from core.models import ClassifyRequest
from core.llm_backend import llm_call

router = APIRouter()

UNSAFE_SCHEMA = {
    "type": "object",
    "properties": {
        "safe": {"type": "boolean"},
        "reason": {"type": "string"},
        "category": {"type": "string"},
    },
    "required": ["safe", "reason", "category"],
}


@router.post("/classify")
async def classify(request: ClassifyRequest):
    try:
        start = datetime.now()

        # Step 1: Quick safe/unsafe check with structured output
        safe_schema = {
            "type": "object",
            "properties": {
                "safe": {"type": "boolean"},
            },
            "required": ["safe"],
        }
        safe_check = llm_call(
            messages=[
                {"role": "system", "content": "You are a safety classifier. Determine if the message is safe. /no_think"},
                {"role": "user", "content": f"Is this message safe: {request.message}"},
            ],
            max_tokens=10,
            temperature=0,
            response_format=safe_schema,
        )
        result_text = safe_check["choices"][0]["message"]["content"]
        is_safe = json.loads(result_text).get("safe", False)
        step1_ms = (datetime.now() - start).total_seconds() * 1000

        if is_safe:
            return {
                "safe": True,
                "reason": None,
                "category": None,
                "inference_time_ms": round(step1_ms, 2),
            }

        # Step 2: Unsafe -- get structured details
        detail = llm_call(
            messages=[
                {"role": "system", "content": "You are a safety classifier. Classify the following message. /no_think"},
                {"role": "user", "content": f"Classify this message: {request.message}"},
            ],
            max_tokens=256,
            temperature=0,
            response_format=UNSAFE_SCHEMA,
        )
        detail_text = detail["choices"][0]["message"]["content"]
        result = json.loads(detail_text)
        total_ms = (datetime.now() - start).total_seconds() * 1000

        return {
            "safe": result.get("safe", False),
            "reason": result.get("reason"),
            "category": result.get("category"),
            "inference_time_ms": round(total_ms, 2),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
