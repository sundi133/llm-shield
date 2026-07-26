# Image for the LiteLLM demo UI.
#
# BUILD CONTEXT IS THE REPO ROOT, not this folder — so the COPY paths below are
# spelled out in full. Build it from the repo root:
#
#     docker build -f examples/demo/litellm_web/Dockerfile -t shield-demo-ui .
#
# On Railway: leave Root Directory EMPTY and set Dockerfile Path to
# examples/demo/litellm_web/Dockerfile. Do not set Root Directory to this
# folder — that changes the context and these paths stop resolving.
#
# The full paths also stop `COPY requirements.txt .` from silently picking up
# the repo-root requirements.txt (the whole Shield runtime) instead of ours.
FROM python:3.11-slim

WORKDIR /app
COPY examples/demo/litellm_web/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY examples/demo/litellm_web/app.py .

# Railway injects PORT at runtime; app.py reads it and binds 0.0.0.0.
ENV PORT=8800
EXPOSE 8800
CMD ["python", "app.py"]
