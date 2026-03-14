FROM ghcr.io/ggml-org/llama.cpp:server-cuda AS llama

FROM nvidia/cuda:12.8.0-runtime-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive

# Copy pre-built llama-server binary and libs
COPY --from=llama /llama-server /llama.cpp/build/bin/llama-server

# Install Node.js 20 + python3 (for model download)
RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    curl ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Download models
RUN pip3 install huggingface_hub && python3 -c "\
from huggingface_hub import hf_hub_download; \
hf_hub_download(repo_id='unsloth/Qwen3-8B-GGUF',   filename='Qwen3-8B-Q4_K_M.gguf',   local_dir='/models'); \
hf_hub_download(repo_id='unsloth/Qwen3-0.6B-GGUF', filename='Qwen3-0.6B-Q4_K_M.gguf', local_dir='/models'); \
print('Models downloaded!')"

# Install Node deps
WORKDIR /app
COPY package.json .
RUN npm install

COPY handler.js .

CMD ["node", "handler.js"]
