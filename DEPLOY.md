# Deploying the TrustLens backend

The backend is a Docker container (FastAPI + Slither + web3 + Claude). Any host
that runs a Dockerfile works: **Render**, **Railway**, and **Fly.io** are the
easiest. It needs outbound internet (Basescan, Base RPC, Anthropic) and about
512MB–1GB RAM (Slither is CPU/memory heavy).

## Environment variables (set these on the host)

| Var | Required | Notes |
|-----|----------|-------|
| `ANTHROPIC_API_KEY` | yes | for the AI report |
| `BASESCAN_API_KEY` | yes | fetch verified source (Etherscan V2 key, works for Base mainnet) |
| `ALLOWED_ORIGINS` | yes (prod) | your frontend origin, e.g. `https://trustlens.vercel.app` (comma-separated for several) |
| `FREE_BETA` | no | `1` (default) = AI reports free + rate-limited. Set `0` to require on-chain payment. |
| `AI_RATE_MAX` | no | free AI reports per IP per window (default 8) — your Claude-spend cap |
| `AI_RATE_WINDOW` | no | AI report window seconds (default 86400 = 1 day) |
| `SCAN_RATE_MAX` | no | free scans per IP per window (default 20) |
| `SCAN_RATE_WINDOW` | no | scan window seconds (default 60) |
| `PORT` | auto | injected by the host |

**Never** set `ALLOW_LOCAL_REPORT` in production (it exposes an ungated AI endpoint).

## Render (recommended, has a free tier)

1. Push this repo to GitHub.
2. Render → New → Web Service → connect the repo.
3. Runtime: **Docker**. Render auto-detects the `Dockerfile`.
4. Add the env vars above.
5. Deploy. Your URL is `https://<name>.onrender.com`.

## Railway / Fly.io

- **Railway:** New Project → Deploy from repo → it detects the Dockerfile → add env vars.
- **Fly.io:** `fly launch` (uses the Dockerfile) → `fly secrets set ANTHROPIC_API_KEY=... BASESCAN_API_KEY=... ALLOWED_ORIGINS=...` → `fly deploy`.

## Local docker test

```bash
docker build -t trustlens-backend .
docker run -p 8000:8000 \
  -e ANTHROPIC_API_KEY=... -e BASESCAN_API_KEY=... \
  -e ALLOWED_ORIGINS=http://localhost:5173 \
  trustlens-backend
```

## After deploy

Point the frontend at this URL by setting `VITE_API_BASE` in the web app (see
the web repo's DEPLOY.md), then rebuild/redeploy the frontend.
