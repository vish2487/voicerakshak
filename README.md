# VoiceRakshak AI

A mobile-first safety awareness interface with a FastAPI backend. The backend includes a deterministic text safety-pattern assessment endpoint; it does not verify callers or determine fraud with certainty. VoiceRakshak does not persist conversations or transcripts and needs no API keys. If you use browser speech recognition, the browser provider may process audio externally; the interface discloses this before use.

## Requirements

- Docker Engine with Docker Compose v2 (`docker compose`)
- For running tests outside Docker: Node.js 22.14.0 and Python 3.12

## Start the application

From the project root, run:

```sh
docker compose up --build
```

Open the application at <http://localhost:5173>. The backend health endpoint is <http://localhost:8000/health>; it returns `{"status":"ok"}`. The frontend requests `/api/health` through the Vite development-server proxy and displays whether the backend is connected.

## Text safety assessment API

`POST /assess` accepts a `message`, optional `source_type` (`call`, `SMS`, `WhatsApp`, or `other`; defaults to `other`), and optional `language` (`en-IN`, `hi-IN`, `mr-IN`, or `ta-IN`; defaults to `en-IN`). Detection and the explanatory response use the selected language. Through the Vite proxy, it is available at `/api/assess`.

```sh
curl -X POST http://localhost:8000/assess \
  -H 'Content-Type: application/json' \
  -d '{"message":"Transfer the money right now.","source_type":"call","language":"en-IN"}'
```

The response has exactly one classification: `high`, `caution`, or `insufficient_information`. It includes matched indicators, explanations, recommended actions, an optional clarifying question, and a safety disclaimer, localized to the selected language. Messages must be nonblank and no longer than 8,000 characters. The engine recognizes selected text patterns only. Assessment requests are processed in memory; message text is not stored or logged.

Stop the services with `Ctrl+C`. To stop and remove the containers later, run `docker compose down` from the project root.

The Docker images use pinned runtimes: `node:22.14.0-alpine3.21` and `python:3.12.9-slim-bookworm`. Application dependencies are pinned as exact versions, with a committed npm lockfile.

## Run tests

Frontend (from `frontend/`):

```sh
npm ci
npm test
npm run build
```

Backend (from `backend/`):

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest
```

## Configuration

Copy `.env.example` to `.env` if you want a local environment file. The app does not read secrets and works without environment variables or API keys.
