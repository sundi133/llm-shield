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

# Install Python deps
WORKDIR /runpod
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY handler.py .

# Override the default entrypoint (llama-server) so Python starts instead
ENTRYPOINT []
CMD ["python3", "handler.py"]
