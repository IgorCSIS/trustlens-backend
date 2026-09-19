# TrustLens backend: FastAPI, Slither, web3 and the AI triage pass.
FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends git curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-install a common solc so the first scans are fast; the analyzer installs
# other versions on demand at runtime.
RUN solc-select install 0.8.24 && solc-select use 0.8.24

COPY app ./app

ENV PORT=8000
EXPOSE 8000
# Hosts (Render/Railway/Fly) inject $PORT; default 8000 for local docker run.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
