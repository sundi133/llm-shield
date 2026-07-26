# Standalone image for the LiteLLM demo UI. It copies only this directory, so it
# builds with this folder as the build context and depends on nothing else here.
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

# Railway injects PORT at runtime; app.py reads it and binds 0.0.0.0.
ENV PORT=8800
EXPOSE 8800
CMD ["python", "app.py"]
