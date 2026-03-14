import runpodSdk from "runpod-sdk";
import fetch from "node-fetch";
import { spawn } from "child_process";

const LLAMA_URL = "http://127.0.0.1:8000";
const MODEL_PATH = "/models/Qwen3-8B-Q4_K_M.gguf";
const DRAFT_MODEL_PATH = "/models/Qwen3-0.6B-Q4_K_M.gguf";

// ── Start llama-server ────────────────────────────────────────────
function startServer() {
  return new Promise((resolve, reject) => {
    const proc = spawn("/app/llama-server", [
      "-m",           MODEL_PATH,
      "-md",          DRAFT_MODEL_PATH,
      "-ngl",         "99",
      "-ngld",        "99",
      "-c",           "32768",
      "--flash-attn", "auto",
      "--host",       "0.0.0.0",
      "--port",       "8000",
      "-np",          "4",
      "--log-disable",
    ]);

    proc.stdout.on("data", (d) => console.log("[llama]", d.toString().trim()));
    proc.stderr.on("data", (d) => console.error("[llama]", d.toString().trim()));
    proc.on("exit", (code) => console.log("[llama] exited with code", code));

    console.log("Waiting for llama-server to be ready...");

    let attempts = 0;
    const interval = setInterval(async () => {
      attempts++;
      try {
        const res = await fetch(`${LLAMA_URL}/health`);
        const data = await res.json();
        if (data.status === "ok") {
          clearInterval(interval);
          console.log("llama-server is ready!");
          resolve();
        }
      } catch {
        // not ready yet
      }
      if (attempts >= 60) {
        clearInterval(interval);
        reject(new Error("llama-server failed to start"));
      }
    }, 2000);
  });
}

// ── RunPod Handler ────────────────────────────────────────────────
async function handler(job) {
  const input = job.input ?? {};

  const maxTokens   = input.max_tokens ?? 10;
  const temperature = input.temperature ?? 0;
  const stream      = input.stream ?? false;
  let   messages    = input.messages ?? [];

  // Build messages from prompt if no messages provided
  if (messages.length === 0 && input.prompt) {
    messages = [
      { role: "system", content: input.system ?? "You are a helpful assistant. /no_think" },
      { role: "user",   content: input.prompt },
    ];
  }

  const payload = {
    messages,
    max_tokens:  maxTokens,
    temperature,
    stream,
  };

  try {
    if (stream) {
      // ── Streaming ──────────────────────────────────────────────
      const res = await fetch(`${LLAMA_URL}/v1/chat/completions`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(payload),
      });

      async function* generate() {
        for await (const chunk of res.body) {
          const lines = chunk.toString().split("\n").filter(Boolean);
          for (const line of lines) {
            if (!line.startsWith("data: ")) continue;
            const data = line.slice(6);
            if (data === "[DONE]") return;
            try {
              const parsed = JSON.parse(data);
              const token  = parsed.choices?.[0]?.delta?.content ?? "";
              if (token) yield token;
            } catch { /* skip malformed chunks */ }
          }
        }
      }
      return generate();

    } else {
      // ── Non-streaming ──────────────────────────────────────────
      const res = await fetch(`${LLAMA_URL}/v1/chat/completions`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(payload),
      });

      const data = await res.json();
      return {
        text:  data.choices?.[0]?.message?.content ?? "",
        usage: data.usage ?? {},
        model: "Qwen3-8B-Q4_K_M + speculative Qwen3-0.6B",
      };
    }

  } catch (err) {
    return { error: err.message };
  }
}

// ── Boot ──────────────────────────────────────────────────────────
await startServer();

const runpod = runpodSdk(process.env.RUNPOD_API_KEY);
runpod.serverless.start({ handler });
