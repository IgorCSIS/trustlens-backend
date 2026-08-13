"""
TrustLens scanner API.

Endpoints:
  GET  /health          -> liveness
  POST /scan/local      -> M2: static-analysis only, pasted source (no API key)
  POST /scan/address    -> M2: static-analysis only, verified contract by address
  POST /report/local    -> M2+M3: static analysis + AI triage, pasted source
  POST /report/address  -> M2+M3: static analysis + AI triage, by address

M4 will call these from the Next.js frontend after verifying on-chain payment
(the PaymentGate `ScanPurchased` event from M1). The /report/* endpoints are the
paid "deep scan"; /scan/* is the free rule-based tier.
"""
from __future__ import annotations

import os
import shutil
import time
from collections import defaultdict

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import ai, analyzer, fetcher, payments
from .ai import AIReport
from .models import AddressScanRequest, LocalScanRequest, ReportRequest, ScanResult

load_dotenv()

app = FastAPI(title="TrustLens Scanner", version="0.4.0")

# CORS: in production set ALLOWED_ORIGINS to your deployed frontend origin(s),
# comma-separated. Falls back to any localhost port for local dev.
_origins = os.getenv("ALLOWED_ORIGINS", "").strip()
if _origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in _origins.split(",") if o.strip()],
        allow_methods=["*"], allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"http://(localhost|127\.0\.0\.1):\d+",
        allow_methods=["*"], allow_headers=["*"],
    )

# Free-beta mode: AI reports are free (no on-chain payment), just rate-limited.
# Set FREE_BETA=0 to require payment (once the payment contract is on mainnet + audited).
FREE_BETA = os.getenv("FREE_BETA", "1") == "1"


# --- Simple per-IP rate limiters --------------------------------------------
def _make_limiter(max_n: int, window: int, msg: str):
    hits: dict[str, list[float]] = defaultdict(list)

    def dep(request: Request) -> None:
        ip = request.client.host if request.client else "unknown"
        now = time.time()
        hits[ip] = [t for t in hits[ip] if t > now - window]
        if len(hits[ip]) >= max_n:
            raise HTTPException(status_code=429, detail=msg)
        hits[ip].append(now)

    return dep


# free scan: protect the CPU-heavy endpoint (per minute)
rate_limit = _make_limiter(
    int(os.getenv("SCAN_RATE_MAX", "20")), int(os.getenv("SCAN_RATE_WINDOW", "60")),
    "Too many scans, give it a moment.",
)
# AI report: daily per-IP cap so free-beta spend can't run away
ai_rate_limit = _make_limiter(
    int(os.getenv("AI_RATE_MAX", "8")), int(os.getenv("AI_RATE_WINDOW", "86400")),
    "You've hit today's free deep-report limit. Try again tomorrow, or scan away for free.",
)


class DeepReport(BaseModel):
    scan: ScanResult
    report: AIReport


@app.get("/")
def root() -> dict:
    return {
        "name": "TrustLens API",
        "status": "ok",
        "message": "The backend is running. This is an API, not a website.",
        "try": {"health": "/health", "interactive_docs": "/docs"},
    }


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "engine": "slither", "ai_model": ai.MODEL}


# --------------------------------------------------------------------------
# M2 — static analysis only (free tier)
# --------------------------------------------------------------------------

@app.post("/scan/local", response_model=ScanResult)
def scan_local(req: LocalScanRequest) -> ScanResult:
    try:
        return analyzer.analyze_source(req.source, filename=req.filename)
    except Exception as exc:  # noqa: BLE001 - surface engine errors to caller
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/scan/address", response_model=ScanResult, dependencies=[Depends(rate_limit)])
def scan_address(req: AddressScanRequest) -> ScanResult:
    """FREE tier — rule-based findings only, no payment, no AI cost."""
    scan, _ = _scan_address_core(req.address, req.chain)
    return scan


# --------------------------------------------------------------------------
# M2 + M3 — static analysis + AI triage (PAID "deep scan")
# --------------------------------------------------------------------------

@app.post("/report/address", response_model=DeepReport, dependencies=[Depends(ai_rate_limit)])
def report_address(req: ReportRequest) -> DeepReport:
    """AI deep report. Free during beta (rate-limited); paid once FREE_BETA=0."""
    if not FREE_BETA:
        # authorize with a per-scan payment OR an active monthly pass
        try:
            if req.pass_signature and req.pass_message:
                payments.verify_pass(req.address, req.pass_message, req.pass_signature, req.chain)
            elif req.tx_hash and req.payment_id:
                payments.verify_and_consume(req.tx_hash, req.address, req.payment_id, req.chain)
            else:
                raise payments.PaymentError("no payment or pass proof provided")
        except payments.PaymentError as exc:
            raise HTTPException(status_code=402, detail=str(exc)) from exc  # 402 Payment Required

    scan, source = _scan_address_core(req.address, req.chain)
    return DeepReport(scan=scan, report=_triage(scan, source))


@app.post("/report/local", response_model=DeepReport)
def report_local(req: LocalScanRequest) -> DeepReport:
    """DEV-ONLY — ungated AI report on pasted source. Disable/remove in prod."""
    if os.getenv("ALLOW_LOCAL_REPORT") != "1":
        raise HTTPException(status_code=403, detail="local report disabled (set ALLOW_LOCAL_REPORT=1 for dev)")
    try:
        scan = analyzer.analyze_source(req.source, filename=req.filename)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return DeepReport(scan=scan, report=_triage(scan, req.source))


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _scan_address_core(address: str, chain: str) -> tuple[ScanResult, str]:
    """Fetch + statically analyze a verified contract; return (scan, source)."""
    api_key = os.getenv("BASESCAN_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="BASESCAN_API_KEY not set on server")

    try:
        fetched = fetcher.fetch_sources(address, api_key, chain)
    except fetcher.SourceNotVerified as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"fetch failed: {exc}") from exc

    try:
        scan = analyzer.analyze_path(
            fetched.primary_file,
            target=address,
            solc_version=fetched.solc_version,
            remappings=fetched.remappings,
            root_dir=fetched.root_dir,
            filter_paths="lib",  # skip audited dependencies (OpenZeppelin, etc.)
        )
        try:
            with open(fetched.primary_file, encoding="utf-8") as fh:
                source = fh.read()
        except OSError:
            source = ""
        return scan, source
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=f"analysis failed: {exc}") from exc
    finally:
        # clean up the fetched source tree so temp dirs don't accumulate
        shutil.rmtree(fetched.root_dir, ignore_errors=True)


def _triage(scan: ScanResult, source: str) -> AIReport:
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise HTTPException(
            status_code=500,
            detail="ANTHROPIC_API_KEY not set on server (needed for the AI report)",
        )
    try:
        return ai.triage(scan, source)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"AI triage failed: {exc}") from exc
