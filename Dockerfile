FROM ghcr.io/ggml-org/llama.cpp:server-cuda

ENV DEBIAN_FRONTEND=noninteractive
ENV LD_LIBRARY_PATH=/app/lib:/app:$LD_LIBRARY_PATH

# Find and register all shared libraries from the llama.cpp image
RUN find / -name "libmtmd.so*" -o -name "libllama.so*" -o -name "libggml*.so*" 2>/dev/null | head -20 \
    && find / -name "libmtmd.so*" 2>/dev/null -exec cp {} /usr/local/lib/ \; \
    && find / -name "libllama.so*" 2>/dev/null -exec cp -P {} /usr/local/lib/ \; \
    && find / -name "libggml*.so*" 2>/dev/null -exec cp -P {} /usr/local/lib/ \; \
    && ldconfig

# Install python3 + pip
RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Download models
RUN pip3 install --no-cache-dir huggingface_hub && python3 -c "\
from huggingface_hub import hf_hub_download; \
hf_hub_download(repo_id='unsloth/Qwen3-8B-GGUF',   filename='Qwen3-8B-Q4_K_M.gguf',   local_dir='/models'); \
hf_hub_download(repo_id='unsloth/Qwen3-0.6B-GGUF', filename='Qwen3-0.6B-Q4_K_M.gguf', local_dir='/models'); \
print('Models downloaded!')"

# Install Python deps
WORKDIR /runpod
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code
COPY handler.py .
COPY config/ config/
COPY core/ core/
COPY guardrails/ guardrails/
COPY api/ api/
COPY storage/ storage/
COPY static/ static/

# Override the default entrypoint (llama-server) so Python starts instead
ENTRYPOINT []
CMD ["python3", "handler.py"]
