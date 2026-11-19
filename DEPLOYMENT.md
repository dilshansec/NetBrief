# Deployment

## Local development

Use README.md or start_windows.bat. The frontend is static HTML/CSS/JS served by FastAPI. There is no frontend build step. Set environment variables before starting Uvicorn; .env.example is a template, not automatically loaded.

## Container build (not executed in this session)

```sh
docker build -t netsentry .
docker run --rm -p 127.0.0.1:8000:8000 --memory=768m --cpus=1 netsentry
```

Dockerfile uses a non-root runtime user and one Uvicorn worker. Uploaded files are not mounted persistently. No public deployment has been performed.

## Hosting preparation

Use a Python/container-capable host supporting subprocesses. Serve frontend/backend from the same origin. A static-only host cannot run this backend. Do not split the frontend onto another origin without deliberately revisiting CORS and upload-origin policy.

Before public exposure: choose a provider and verify its current request-body, timeout, CPU, memory and process limits; set conservative matching application limits; add HTTPS, request body/time/concurrency controls at a reverse proxy; decide user authentication and retention requirements; run security and representative capture tests. No provider-specific compatibility or quota has been assumed or verified. Windows local success does not certify a Linux hosting environment.

Use a **single worker** with the current process-local cache. Health check: GET /api/health. Upload limit defaults to 10 MiB, packet limit 50,000, one concurrent analysis, timeout 45s. Linux CPU hard limit is 30 seconds and worker virtual memory default 512 MiB, so these may stop processing before the wall-clock timeout. Resource exhaustion returns a bounded analysis failure.

## GitHub preparation

Review changed files and test outputs. Keep .venv, logs, environment secrets and private captures excluded. Only sanitized/synthetic sample captures should be committed. Choose the intended software license before an open-source release; none has been added automatically.
