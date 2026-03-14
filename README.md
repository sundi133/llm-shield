# LLM Shield

Serverless Qwen3-8B inference on RunPod with speculative decoding via llama.cpp.

## Features

- **Qwen3-8B** with **Qwen3-0.6B** draft model for speculative decoding
- CUDA-accelerated via llama.cpp
- RunPod serverless handler with streaming and non-streaming support
- Node.js 20 runtime

## Project Structure

```
llm-shield/
├── Dockerfile        # CUDA 12.8 image, llama.cpp build, model download
├── handler.js        # RunPod serverless handler
├── package.json      # Node.js dependencies
├── .dockerignore     # Docker build excludes
└── LICENSE           # MIT License
```

## Quick Start

### Build & Push

```bash
docker build -t yourdockerhub/llm-shield:latest .
docker push yourdockerhub/llm-shield:latest
```

### Deploy on RunPod

1. Create a new Serverless Endpoint on [RunPod](https://runpod.io)
2. Use your pushed Docker image
3. Set `RUNPOD_API_KEY` as an environment variable

### Test

```bash
curl -X POST https://api.runpod.ai/v2/YOUR_ENDPOINT_ID/runsync \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "prompt": "What is quantum computing?",
      "max_tokens": 256,
      "temperature": 0.7
    }
  }'
```

## API

### Input Parameters

| Parameter     | Type    | Default                                  | Description                  |
|---------------|---------|------------------------------------------|------------------------------|
| `prompt`      | string  | `""`                                     | User prompt                  |
| `system`      | string  | `"You are a helpful assistant. /no_think"` | System message             |
| `max_tokens`  | number  | `512`                                    | Max tokens to generate       |
| `temperature` | number  | `0.7`                                    | Sampling temperature         |
| `stream`      | boolean | `false`                                  | Enable streaming response    |
| `messages`    | array   | `[]`                                     | Full chat messages array     |

### Response (non-streaming)

```json
{
  "text": "Quantum computing is...",
  "usage": { "prompt_tokens": 15, "completion_tokens": 128 },
  "model": "Qwen3-8B-Q4_K_M + speculative Qwen3-0.6B"
}
```

## License

[MIT](LICENSE)
