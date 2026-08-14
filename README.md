# TrustLens — Backend (Scanner Engine)

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.13-3776AB?style=flat-square&labelColor=3E2230" />
  <img alt="FastAPI" src="https://img.shields.io/badge/FastAPI-Slither_+_web3-009688?style=flat-square&labelColor=3E2230" />
  <img alt="AI triage" src="https://img.shields.io/badge/AI-Claude_triage-FF4B5C?style=flat-square&labelColor=3E2230" />
  <img alt="Live on Base" src="https://img.shields.io/badge/live-Base_mainnet-0052FF?style=flat-square&labelColor=3E2230" />
</p>

The engine behind **TrustLens**, an AI smart-contract safety scanner. Give it a
verified contract address on Base; it fetches the source, follows any proxy to
the real implementation, runs **Slither** static analysis, then puts **Claude**
on top of the raw findings to say which flags are genuinely dangerous and which
are noise, with a plain-English fix for anything real.

The differentiator is the last step. Raw scanners stop at the findings and cry
wolf. TrustLens reads the code and does the triage.

### Part of TrustLens · the first tool in the [SafuLens](https://x.com/SafuLens) suite
- **[Live app](https://trustlens-web.niftyai.workers.dev)** — try it, no wallet or signup
- **[Frontend](https://github.com/IgorCSIS/trustlens-web)** — React + wagmi/viem
- **Backend** (this repo) — FastAPI + Slither + web3 + Claude
- **[Contracts](https://github.com/IgorCSIS/trustlens-contracts)** — Foundry `PaymentGate`

---

## What it does, end to end

```
address ─▶ resolve proxy ─▶ fetch verified source ─▶ Slither ─▶ risk score
                                                                    │
                                              Claude triage ◀───────┘
                                                    │
                          plain-English report: real vs false alarm + fixes
```

Two tiers from one pipeline:
- `POST /scan/address` — **free** rule-based scan (Slither findings + 0-100 risk score).
- `POST /report/address` — **AI deep report**: triage of each flag, an attack example and a copy-paste fix for the real ones, and a human-calibrated score.

## Engineering worth a look

- **Proxy-aware scanning (`app/proxy.py`).** Most scanners read the proxy shell and miss the real logic. TrustLens reads the EIP-1967, beacon, and legacy zeppelinos storage slots, follows the proxy to the implementation, and scans *that*. Live example: USDC's EIP-1967 slot is empty, so a naive scanner sees nothing; TrustLens resolves the legacy slot to the real FiatToken code and also flags that the upgrade admin is a single EOA.
- **Fail loud, never a reassuring shell.** If an implementation is unverified, unresolvable, or the on-chain read fails, the result is "COULD NOT ANALYZE", never a low-risk verdict on code we did not actually read. A false negative is the one thing a safety tool cannot ship.
- **Spoof-proof payment verification (`app/payments.py`).** The on-chain payment check requires the `ScanPurchased` event to be emitted *by* the PaymentGate contract, closing a hole where anyone could emit a matching event from their own contract.
- **Runs untrusted code safely.** Slither compiles attacker-supplied Solidity, so it runs behind a concurrency guard with a wall-clock timeout, and a global daily spend cap that fails closed protects the model budget.
- **Cheap and fast under load.** Results are cached by `(chain, address)`; proxies get a shorter TTL because they can be upgraded.

## Layout

| File | Purpose |
|------|---------|
| `app/main.py` | FastAPI app: `/scan/*`, `/report/*`, caching, rate limits, spend cap. |
| `app/proxy.py` | Resolve a proxy to its implementation via storage slots. |
| `app/rpc.py` | Shared Base RPC client. |
| `app/fetcher.py` | Pull verified source from the Etherscan V2 API (Base). |
| `app/analyzer.py` | Run Slither, normalize detectors to findings, compute the risk score. |
| `app/ai.py` | Claude triage: real vs false alarm, attack example, fix, calibrated score. |
| `app/payments.py` | On-chain payment + monthly-pass verification (dark during free beta). |
| `app/models.py` | Pydantic request/response models. |
| `tests/` | Proxy slot-derivation and false-negative regression tests. |

## Run locally

```bash
python -m venv .venv
.venv/Scripts/activate            # PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

```bash
# free scan of a verified contract on Base
curl -X POST http://127.0.0.1:8000/scan/address \
  -H "content-type: application/json" \
  -d '{"address":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913","chain":"base"}'
```

Scanning by address needs a free `BASESCAN_API_KEY` (the Etherscan V2 key works
for Base). The AI report needs `ANTHROPIC_API_KEY`. Both live in the server's
`.env`; end users never need a key. Default model is `claude-sonnet-5` (override
with `TRUSTLENS_MODEL`). Slither auto-installs a matching `solc` via `solc-select`.

## Configuration

| Env | Default | What it does |
|-----|---------|--------------|
| `BASESCAN_API_KEY` | — | Etherscan V2 key for fetching verified source |
| `ANTHROPIC_API_KEY` | — | Claude key for the AI report |
| `TRUSTLENS_MODEL` | `claude-sonnet-5` | Triage model |
| `FREE_BETA` | `1` | AI report free + rate-limited; `0` requires on-chain payment |
| `AI_GLOBAL_DAILY_MAX` | `200` | Global daily deep-report cap (fails closed) |
| `SLITHER_MAX_CONCURRENCY` / `SLITHER_TIMEOUT` | `1` / `150` | Slither containment |
| `CACHE_TTL` / `PROXY_CACHE_TTL` | `86400` / `3600` | Result cache lifetimes |

## A note on what this is

TrustLens is automated triage plus AI review. It is not a professional security
audit. It cannot see off-chain or economic risk, and every report says so. For
high-value contracts, get a real audit.

## License

[MIT](LICENSE)
