# Guarded MCP server — deployable image (Railway, Fly, Render, any container host).
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shield_guard.py server.py register.py ./

# The MCP endpoint is served at /mcp on $PORT. Host platforms inject $PORT.
EXPOSE 8000
CMD ["python", "server.py"]
