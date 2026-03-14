FROM ghcr.io/ggml-org/llama.cpp:server-cuda

ENV DEBIAN_FRONTEND=noninteractive
ENV LD_LIBRARY_PATH=/app/lib:/app:$LD_LIBRARY_PATH

# Install Node.js 20
RUN apt-get update && apt-get install -y \
    curl ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install Node deps
WORKDIR /runpod
COPY package.json .
RUN npm install

COPY handler.js .

# Override the default entrypoint (llama-server) so Node starts instead
ENTRYPOINT []
CMD ["node", "handler.js"]
