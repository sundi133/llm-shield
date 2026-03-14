import subprocess
import requests
import time
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

LLAMA_URL = "http://127.0.0.1:8000"
MODEL_PATH = "/models/Qwen3-8B-Q4_K_M.gguf"
DRAFT_MODEL_PATH = "/models/Qwen3-0.6B-Q4_K_M.gguf"

app = FastAPI(title="LLM Shield")


class ChatRequest(BaseModel):
    prompt: Optional[str] = None
    messages: Optional[list] = None
    system: Optional[str] = "You are a helpful assistant. /no_think"
    max_tokens: Optional[int] = 512
    temperature: Optional[float] = 0.7


class ChatResponse(BaseModel):
    text: str
    usage: dict
    inference_time_ms: float


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


@app.get("/ping")
async def health_check():
    return {"status": "healthy"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


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

        res = requests.post(
            f"{LLAMA_URL}/v1/chat/completions",
            json={
                "messages": messages,
                "max_tokens": request.max_tokens,
                "temperature": request.temperature,
            },
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
