import runpod
import subprocess
import requests
import time

LLAMA_URL = "http://127.0.0.1:8000"
MODEL_PATH = "/runpod-volume/models/Qwen3-8B-Q4_K_M.gguf"
DRAFT_MODEL_PATH = "/runpod-volume/models/Qwen3-0.6B-Q4_K_M.gguf"

def start_server():
    subprocess.Popen([
        "/app/llama-server",
        "-m", MODEL_PATH,
        "-md", DRAFT_MODEL_PATH,
        "-ngl", "99",
        "-ngld", "99",
        "-c", "32768",
        "--flash-attn", "auto",
        "--host", "0.0.0.0",
        "--port", "8000",
        "-np", "4",
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

def handler(job):
    inp = job.get("input", {})
    prompt      = inp.get("prompt", "")
    messages    = inp.get("messages", [])
    system      = inp.get("system", "You are a helpful assistant. /no_think")
    max_tokens  = inp.get("max_tokens", 512)
    temperature = inp.get("temperature", 0.7)

    if prompt and not messages:
        messages = [
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt}
        ]
    elif messages and not any(m["role"] == "system" for m in messages):
        messages.insert(0, {"role": "system", "content": system})

    try:
        res = requests.post(
            f"{LLAMA_URL}/v1/chat/completions",
            json={
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
            },
            timeout=300
        )
        data = res.json()
        return {
            "text": data["choices"][0]["message"]["content"],
            "usage": data.get("usage", {})
        }
    except Exception as e:
        return {"error": str(e)}

start_server()
runpod.serverless.start({"handler": handler})
