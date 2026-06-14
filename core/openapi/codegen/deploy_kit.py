"""Deploy-kit codegen: emit Dockerfile + platform manifests next to the server.

The generated MCP server serves Streamable HTTP when MCP_TRANSPORT=http, so it
runs as a plain container on any platform. This module emits the artifacts to
deploy that container to Docker, Compose, Cloud Run, Fly.io, Railway/Render
(Procfile), and Kubernetes — all 12-factor (env-driven), health-checked.
"""

from __future__ import annotations

import re


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9-]+", "-", (name or "mcp-server").lower()).strip("-")
    return s or "mcp-server"


_PY_DOCKERFILE = """FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV MCP_TRANSPORT=http \\
    PORT=8080 \\
    HOST=0.0.0.0
EXPOSE 8080
CMD ["python", "server.py"]
"""

_TS_DOCKERFILE = """FROM node:20-slim
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
RUN npx tsc
ENV MCP_TRANSPORT=http \\
    PORT=8080 \\
    HOST=0.0.0.0
EXPOSE 8080
CMD ["node", "dist/index.js"]
"""

_TSCONFIG = """{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ES2022",
    "moduleResolution": "bundler",
    "outDir": "dist",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  },
  "include": ["src/**/*.ts"]
}
"""

_DOCKERIGNORE = "node_modules\ndist\n__pycache__\n*.pyc\n.env\n.git\n"


def _compose(slug: str) -> str:
    return f"""services:
  {slug}:
    build: .
    ports:
      - "8080:8080"
    environment:
      MCP_TRANSPORT: http
      PORT: "8080"
      API_BASE_URL: ${{API_BASE_URL}}
      SHIELD_URL: ${{SHIELD_URL:-}}
      SHIELD_API_KEY: ${{SHIELD_API_KEY:-}}
      SHIELD_AGENT_KEY: ${{SHIELD_AGENT_KEY:-}}
      SHIELD_USER_ROLE: ${{SHIELD_USER_ROLE:-}}
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8080/health').status==200 else 1)"]
      interval: 30s
      timeout: 3s
      retries: 3
"""


def _fly_toml(slug: str) -> str:
    return f"""app = "{slug}"

[build]

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = true
  auto_start_machines = true

[env]
  MCP_TRANSPORT = "http"
  PORT = "8080"

[[http_service.checks]]
  method = "GET"
  path = "/health"
  interval = "30s"
  timeout = "3s"
"""


def _procfile(language: str) -> str:
    run = "node dist/index.js" if language == "typescript" else "python server.py"
    return f"web: MCP_TRANSPORT=http PORT=$PORT {run}\n"


def _cloudrun(slug: str) -> str:
    return f"""apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: {slug}
spec:
  template:
    spec:
      containers:
        - image: REPLACE_WITH_IMAGE
          ports:
            - containerPort: 8080
          env:
            - name: MCP_TRANSPORT
              value: "http"
            - name: PORT
              value: "8080"
            - name: API_BASE_URL
              value: REPLACE_WITH_API_BASE_URL
"""


def _k8s(slug: str) -> str:
    return f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {slug}
spec:
  replicas: 2
  selector:
    matchLabels:
      app: {slug}
  template:
    metadata:
      labels:
        app: {slug}
    spec:
      containers:
        - name: mcp
          image: REPLACE_WITH_IMAGE
          ports:
            - containerPort: 8080
          env:
            - name: MCP_TRANSPORT
              value: "http"
            - name: PORT
              value: "8080"
          readinessProbe:
            httpGet:
              path: /health
              port: 8080
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: {slug}
spec:
  selector:
    app: {slug}
  ports:
    - port: 80
      targetPort: 8080
"""


def _readme(slug: str, language: str) -> str:
    return f"""# Deploying {slug}

This MCP server serves Streamable HTTP when `MCP_TRANSPORT=http` (default in the
Dockerfile), so it runs as a plain container anywhere. Health: `GET /health`.

## Configure (env)
- `API_BASE_URL` — the upstream API base URL
- `SHIELD_URL`, `SHIELD_API_KEY`, `SHIELD_AGENT_KEY`, `SHIELD_USER_ROLE` — enable
  Shield enforcement (omit `SHIELD_URL` to run ungoverned)
- upstream auth creds per the spec's security schemes

## Run locally
    docker compose up --build      # http://localhost:8080/mcp
    # or: docker build -t {slug} . && docker run -p 8080:8080 -e API_BASE_URL=... {slug}

## Cloud Run
    gcloud run deploy {slug} --source . --port 8080
    # or apply cloudrun.service.yaml after pushing an image

## Fly.io
    fly launch --copy-config --now       # uses fly.toml

## Railway / Render / Heroku
    # uses Procfile; set env vars in the dashboard

## Kubernetes
    # edit image in k8s.yaml, then:
    kubectl apply -f k8s.yaml

## Desktop (stdio, no deploy)
    MCP_TRANSPORT=stdio {"node dist/index.js" if language == "typescript" else "python server.py"}
"""


def deploy_files(language: str, server_name: str = "mcp-server") -> dict:
    """Return {filename: content} deploy artifacts for the given language."""
    slug = _slug(server_name)
    files = {
        ".dockerignore": _DOCKERIGNORE,
        "docker-compose.yml": _compose(slug),
        "fly.toml": _fly_toml(slug),
        "Procfile": _procfile(language),
        "cloudrun.service.yaml": _cloudrun(slug),
        "k8s.yaml": _k8s(slug),
        "DEPLOY.md": _readme(slug, language),
    }
    if language == "typescript":
        files["Dockerfile"] = _TS_DOCKERFILE
        files["tsconfig.json"] = _TSCONFIG
    else:
        files["Dockerfile"] = _PY_DOCKERFILE
    return files
