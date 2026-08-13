# TrustLens — Backend (Scanner Engine)

The M2 scanner engine for **TrustLens**. Takes a Solidity contract (pasted source
or a verified on-chain address), runs **Slither** static analysis, and returns
normalized findings with a 0–100 risk score.

> **Status:** M2 core complete. `/scan/local` verified end-to-end (correctly
> flags reentrancy on a planted-bug sample). `/scan/address` implemented; needs
> an explorer API key to run.

## Layout

| File | Purpose |
|------|---------|
| `app/analyzer.py` | Runs Slither, normalizes detectors → findings, computes risk score. |
| `app/fetcher.py` | Pulls verified source for a deployed address (Etherscan V2 API, Base supported). |
| `app/main.py` | FastAPI app: `/health`, `/scan/local`, `/scan/address`. |
| `app/models.py` | Pydantic request/response models. |
| `samples/VulnerableBank.sol` | Deliberately vulnerable contract for testing the engine. |

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate           # PowerShell:  .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Slither needs a matching `solc`; the analyzer auto-installs/selects it via
`solc-select` based on the contract's `pragma`.

## Run

```bash
uvicorn app.main:app --reload --port 8000
```

Then:

```bash
# health
curl http://127.0.0.1:8000/health

# scan pasted source (no API key needed)
curl -X POST http://127.0.0.1:8000/scan/local \
  -H "content-type: application/json" \
  -d '{"filename":"VulnerableBank.sol","source":"<solidity here>"}'
```

## Scanning by address (needs API key)

1. `cp .env.example .env` and set `BASESCAN_API_KEY` (free at etherscan.io/myapikey —
   the V2 key works for Base).
2. Call `/scan/address` with `{"address":"0x...","chain":"base-sepolia"}`.

The contract must be **verified** on the explorer (that's why M1 step B verifies
`PaymentGate` — so we can scan it by address as a full-circle test).

## Risk score

Weighted by Slither impact: High=40, Medium=15, Low=4, Info=1 (capped at 100).
Verdict: CLEAN → CAUTION (>0) → RISKY (≥15) → DANGEROUS (≥40).

## Deep report (M2 + M3 AI triage)

The `/report/*` endpoints run the scanner, then feed the findings + source to
Claude (`app/ai.py`) for plain-English triage — which findings are real vs.
noise, with a human-calibrated risk score. This is the paid "deep scan" tier.

Needs `ANTHROPIC_API_KEY` in `.env`. The **server** holds the key; end users
never need one. Default model `claude-opus-5` (override with `TRUSTLENS_MODEL`).

```bash
# deep report on a verified contract
curl -X POST http://127.0.0.1:8000/report/address \
  -H "content-type: application/json" \
  -d '{"address":"0x93F3...","chain":"base-sepolia"}'
```

## Roadmap

- **M2 ✅** Slither engine + risk score + API
- **M3 ✅** LLM reasoning layer over findings → plain-English triaged report (`/report/*`)
- **M4** Next.js + wagmi frontend; verify on-chain payment (M1 `ScanPurchased`) before returning deep report
- **M5** Transaction-simulation layer (real honeypot / sellability check)
