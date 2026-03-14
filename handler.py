import subprocess
import requests
import time
import json
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

LLAMA_URL = "http://127.0.0.1:8000"
MODEL_PATH = "/models/Qwen3-8B-Q4_K_M.gguf"
DRAFT_MODEL_PATH = "/models/Qwen3-0.6B-Q4_K_M.gguf"

UNSAFE_SCHEMA = {
    "type": "object",
    "properties": {
        "safe": {"type": "boolean"},
        "reason": {"type": "string"},
        "category": {"type": "string"}
    },
    "required": ["safe", "reason", "category"]
}

app = FastAPI(title="LLM Shield")


class ChatRequest(BaseModel):
    prompt: Optional[str] = None
    messages: Optional[list] = None
    system: Optional[str] = "You are a helpful assistant. /no_think"
    max_tokens: Optional[int] = 512
    temperature: Optional[float] = 0.7
    response_format: Optional[dict] = None


class ClassifyRequest(BaseModel):
    message: str


def start_server():
    subprocess.Popen([
        "/app/llama-server",
        "-m", MODEL_PATH,
        "-md", DRAFT_MODEL_PATH,
        "-ngl", "99",
        "-ngld", "99",
        "-c", "8192",
        "--flash-attn", "auto",
        "--host", "0.0.0.0",
        "--port", "8000",
        "-np", "8",
        "--draft-max", "16",
        "--cache-type-k", "q8_0",
        "--cache-type-v", "q8_0",
        "--log-disable",
    ])
    for i in range(60):
        try:
            r = requests.get(f"{LLAMA_URL}/health", timeout=2)
            if r.json().get("status") == "ok":
                print("llama-server ready!")
                return
        except:
            pass
        time.sleep(2)
        print(f"Waiting... {i+1}/60")
    raise RuntimeError("Server failed to start")


def llm_call(messages, max_tokens=10, temperature=0, response_format=None):
    payload = {
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    if response_format:
        payload["response_format"] = {
            "type": "json_schema",
            "json_schema": {
                "name": "response",
                "strict": True,
                "schema": response_format,
            },
        }
    res = requests.post(
        f"{LLAMA_URL}/v1/chat/completions",
        json=payload,
        timeout=300
    )
    return res.json()


@app.get("/ping")
async def health_check():
    return {"status": "healthy"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.post("/classify")
async def classify(request: ClassifyRequest):
    try:
        start = datetime.now()

        # Step 1: Quick safe/unsafe check
        safe_check = llm_call(
            messages=[
                {"role": "system", "content": "You are a safety classifier. Answer only 'safe' or 'unsafe'. /no_think"},
                {"role": "user", "content": f"Is this message safe or unsafe: {request.message}"}
            ],
            max_tokens=5,
            temperature=0,
        )
        verdict = safe_check["choices"][0]["message"]["content"].strip().lower()
        step1_ms = (datetime.now() - start).total_seconds() * 1000

        if "safe" in verdict and "unsafe" not in verdict:
            return {
                "safe": True,
                "reason": None,
                "category": None,
                "inference_time_ms": round(step1_ms, 2),
            }

        # Step 2: Unsafe — get structured details
        step2_start = datetime.now()
        detail = llm_call(
            messages=[
                {"role": "system", "content": "You are a safety classifier. Classify the following message. /no_think"},
                {"role": "user", "content": f"Classify this message: {request.message}"}
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


@app.post("/v1/chat/completions")
async def chat_completions(request: ChatRequest):
    try:
        messages = request.messages or []

        if request.prompt and not messages:
            messages = [
                {"role": "system", "content": request.system},
                {"role": "user", "content": request.prompt}
            ]
        elif messages and not any(m["role"] == "system" for m in messages):
            messages.insert(0, {"role": "system", "content": request.system})

        start = datetime.now()

        payload = {
            "messages": messages,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }

        if request.response_format:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "response",
                    "strict": True,
                    "schema": request.response_format,
                },
            }

        res = requests.post(
            f"{LLAMA_URL}/v1/chat/completions",
            json=payload,
            timeout=300
        )
        data = res.json()

        elapsed_ms = (datetime.now() - start).total_seconds() * 1000

        return {
            "text": data["choices"][0]["message"]["content"],
            "usage": data.get("usage", {}),
            "inference_time_ms": round(elapsed_ms, 2),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.on_event("startup")
async def startup_event():
    start_server()


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "80"))
    print(f"Starting server on port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)
