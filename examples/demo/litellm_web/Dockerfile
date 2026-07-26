# Image for the LiteLLM demo UI.
#
# BUILD CONTEXT IS THIS FOLDER, not the repo root. That is deliberate: the
# repo-root .dockerignore excludes examples/, so a root-context build cannot
# copy these files at all (and `COPY requirements.txt` would silently match the
# repo-root requirements.txt — the whole Shield runtime — instead of ours).
#
# Build locally from this directory:
#     docker build -t shield-demo-ui .
#
# On Railway: set Root Directory to examples/demo/litellm_web and leave
# Dockerfile Path as Dockerfile (railway.json in this folder sets the rest).
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

# Railway injects PORT at runtime; app.py reads it and binds 0.0.0.0.
ENV PORT=8800
EXPOSE 8800
CMD ["python", "app.py"]
