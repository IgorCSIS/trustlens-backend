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
import threading
import time
from collections import defaultdict

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from . import ai, analyzer, fetcher, payments, proxy
from .ai import AIReport
from .models import (
    AddressScanRequest, Finding, LocalScanRequest, ProxyInfo, ReportRequest, ScanResult,
)

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


# --- Result cache -----------------------------------------------------------
# Scans are effectively deterministic for a given verified source, so cache by
# (chain, address): cuts Claude spend, kills repeat-scan latency, relieves the
# Basescan key, and lets a viral spike hit the cache instead of the model.
# In-process TTL cache; swap for Redis once there's more than one instance.
_CACHE_TTL = int(os.getenv("CACHE_TTL", "86400"))  # 24h; verified source rarely changes
# Proxies can be upgraded, which swaps the implementation without changing the
# address (the cache key). A shorter TTL bounds how long we might serve a verdict
# about code the admin has already replaced.
_PROXY_CACHE_TTL = int(os.getenv("PROXY_CACHE_TTL", "3600"))  # 1h
_scan_cache: dict[str, tuple[float, ScanResult]] = {}
_report_cache: dict[str, tuple[float, "DeepReport"]] = {}
_cache_lock = threading.Lock()


def _cache_key(address: str, chain: str) -> str:
    return f"{chain.lower()}:{address.lower()}"


def _effective_ttl(val) -> int:
    scan = val.scan if isinstance(val, DeepReport) else val
    if isinstance(scan, ScanResult) and scan.proxy and scan.proxy.is_proxy:
        return _PROXY_CACHE_TTL
    return _CACHE_TTL


def _cache_get(store: dict, key: str):
    with _cache_lock:
        hit = store.get(key)
        if hit is None:
            return None
        ts, val = hit
        if time.time() - ts > _effective_ttl(val):
            store.pop(key, None)
            return None
        return val


def _cache_put(store: dict, key: str, val) -> None:
    with _cache_lock:
        store[key] = (time.time(), val)


# --- Global AI spend cap (fails closed) -------------------------------------
# The per-IP limiter is bypassable by rotating IPs, so it is not a real ceiling
# on Claude spend. This global daily counter is: once the day's budget is spent,
# we stop calling the model instead of running up the bill. Reserved before the
# call and refunded if the call fails, so errors don't burn budget.
_AI_GLOBAL_DAILY_MAX = int(os.getenv("AI_GLOBAL_DAILY_MAX", "200"))
_ai_spend_lock = threading.Lock()
_ai_spend = {"day": "", "count": 0}


def _ai_budget_reserve() -> None:
    today = time.strftime("%Y-%m-%d", time.gmtime())
    with _ai_spend_lock:
        if _ai_spend["day"] != today:
            _ai_spend["day"], _ai_spend["count"] = today, 0
        if _ai_spend["count"] >= _AI_GLOBAL_DAILY_MAX:
            raise HTTPException(
                status_code=503,
                detail="TrustLens has hit today's free-beta deep-report capacity. "
                "Try again tomorrow, or keep using the free scan.",
            )
        _ai_spend["count"] += 1


def _ai_budget_refund() -> None:
    with _ai_spend_lock:
        if _ai_spend["count"] > 0:
            _ai_spend["count"] -= 1


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

@app.post("/scan/local", response_model=ScanResult, dependencies=[Depends(rate_limit)])
def scan_local(req: LocalScanRequest) -> ScanResult:
    """FREE tier on pasted source. Rate-limited: it runs Slither (CPU-heavy)."""
    try:
        return analyzer.analyze_source(req.source, filename=req.filename)
    except Exception as exc:  # noqa: BLE001 - surface engine errors to caller
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/scan/address", response_model=ScanResult, dependencies=[Depends(rate_limit)])
def scan_address(req: AddressScanRequest) -> ScanResult:
    """FREE tier — rule-based findings only, no payment, no AI cost."""
    key = _cache_key(req.address, req.chain)
    cached = _cache_get(_scan_cache, key)
    if cached is not None:
        return cached
    scan, _ = _scan_address_core(req.address, req.chain)
    if _cacheable(scan):
        _cache_put(_scan_cache, key, scan)
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

    # Payment/pass is verified above per caller; the cache only saves the compute.
    key = _cache_key(req.address, req.chain)
    cached = _cache_get(_report_cache, key)
    if cached is not None:
        return cached

    # Cache miss = a real Claude call. Reserve global budget first (fail closed),
    # refund if the scan or triage errors so failures don't burn the day's cap.
    _ai_budget_reserve()
    try:
        scan, source = _scan_address_core(req.address, req.chain)
    except Exception:
        _ai_budget_refund()
        raise

    if _degraded_scan(scan):
        # real logic not analyzed / state unconfirmed: no model call, honest report.
        # Refund is outside any try here so it cannot double-fire.
        _ai_budget_refund()
        report = DeepReport(scan=scan, report=_degraded_ai_report(scan))
    else:
        try:
            report = DeepReport(scan=scan, report=_triage(scan, source))
        except Exception:
            _ai_budget_refund()
            raise

    if _cacheable(scan):
        _cache_put(_report_cache, key, report)
        _cache_put(_scan_cache, key, scan)  # warm the free-scan cache too
    return report


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

def _proxy_admin_phrase(info: ProxyInfo) -> str:
    if info.admin is None:
        return ""
    who = "a contract (likely a multisig or timelock, verify its signers)" \
        if info.admin_is_contract else "a single externally-owned key (a centralization / rug vector)"
    return f" Upgrade control is held by {info.admin}, {who}."


def _proxy_standing_finding(info: ProxyInfo) -> Finding:
    """A visible trust flag on every proxy: the logic can be replaced after this
    scan. Kept Low so it does not inflate a clean implementation's score."""
    desc = (
        f"This address is an upgradeable {info.proxy_type or 'proxy'} contract. The code analyzed "
        f"is the current implementation at {info.implementation_address}; the admin can replace it, "
        f"so the deployed behavior can change after this scan." + _proxy_admin_phrase(info)
    )
    return Finding(check="upgradeable-proxy", impact="Low", confidence="High", description=desc, lines=[])


def _degraded_proxy_scan(info: ProxyInfo) -> ScanResult:
    """A result whose real running code could not be established: either a proxy
    whose implementation is not analyzable, OR on-chain state that could not be
    read (so we cannot even confirm whether the address is a proxy). Never a
    reassuring verdict: the limitation is the headline, not a footnote."""
    if info.note:
        detail = info.note
    elif info.implementation_address:
        detail = (f"This is a proxy. Its real logic at {info.implementation_address} could not be "
                  "analyzed, so what this contract actually does is unknown.")
    else:
        detail = "The code that actually runs at this address could not be confirmed."
    check = "proxy-state-unverified" if not info.state_read_ok else "proxy-implementation-unresolved"
    return ScanResult(
        target=info.proxy_address,
        risk_score=55,  # elevated / unknown band, never a comforting low number
        verdict="COULD NOT ANALYZE",
        summary={"High": 1},
        findings=[Finding(
            check=check, impact="High", confidence="High",
            description=detail + " Treat as unknown / unverified.",
            lines=[],
        )],
        proxy=info,
    )


def _degraded_scan(scan: ScanResult) -> bool:
    """True when the real running code was not analyzed, so the AI call must be
    skipped and the result must not be cached or presented as reassuring."""
    p = scan.proxy
    if p is None:
        return False
    if not p.state_read_ok:
        return True
    if p.is_proxy and not p.implementation_scanned:
        return True
    return False


def _cacheable(scan: ScanResult) -> bool:
    """Never cache a result we could not fully establish: a transient RPC blip
    must not pin a degraded verdict on an address for the cache lifetime."""
    return not _degraded_scan(scan)


def _degraded_ai_report(scan: ScanResult) -> AIReport:
    """Synthetic report for a degraded scan: no Claude call, honest scope."""
    info = scan.proxy
    lead = scan.findings[0].description if scan.findings else "The real running code could not be confirmed."
    limitations: list[str] = []
    if info and not info.state_read_ok:
        limitations.append(
            "On-chain proxy state could not be read, so we cannot confirm the code shown is what runs.")
    else:
        limitations.append("The proxy's real implementation code was not analyzed.")
    if info and info.note and info.note not in limitations:
        limitations.append(info.note)
    limitations.append("An upgradeable proxy's behavior can change after any scan.")
    return AIReport(
        headline=lead,
        adjusted_risk=scan.risk_score,
        verdict=scan.verdict,
        limitations=limitations,
        triaged=[],
        disclaimer=ai.DISCLAIMER,
    )


def _scan_address_core(address: str, chain: str) -> tuple[ScanResult, str]:
    """Resolve any proxy, then fetch + statically analyze the code that actually
    runs; return (scan, source). For a proxy we scan the implementation but keep
    the user's address as ScanResult.target."""
    api_key = os.getenv("BASESCAN_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="BASESCAN_API_KEY not set on server")

    # Follow the proxy to its implementation (never raises; degrades on RPC error).
    info = proxy.resolve(address, chain)

    # Could not read on-chain proxy state: we cannot assert this is NOT a proxy,
    # so we must not emit a raw score on the (possible) shell. Hard stop.
    if not info.state_read_ok:
        return _degraded_proxy_scan(info), ""

    cleanly_resolved = bool(
        info.is_proxy and info.implementation_address
        and info.scanned_address == info.implementation_address and not info.note
    )

    # Proxy detected but the real logic could not be reached: fail loud, never
    # scan the shell and call it clean.
    if info.is_proxy and not cleanly_resolved:
        return _degraded_proxy_scan(info), ""

    fetch_target = info.implementation_address if cleanly_resolved else address

    try:
        fetched = fetcher.fetch_sources(fetch_target, api_key, chain)
    except fetcher.SourceNotVerified as exc:
        if cleanly_resolved:
            # the implementation itself is unverified: unknown logic, not "clean"
            info.note = (f"The implementation at {fetch_target} is not verified on the explorer, "
                         "so the real logic could not be analyzed.")
            return _degraded_proxy_scan(info), ""
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"fetch failed: {exc}") from exc

    try:
        scan = analyzer.analyze_path(
            fetched.primary_file,
            target=address,  # keep the user's (proxy) address as the target
            solc_version=fetched.solc_version,
            remappings=fetched.remappings,
            root_dir=fetched.root_dir,
            filter_paths="lib",  # skip audited dependencies (OpenZeppelin, etc.)
        )
        if cleanly_resolved:
            info.implementation_scanned = True
            scan.proxy = info
            scan.findings.insert(0, _proxy_standing_finding(info))
            scan.summary["Low"] = scan.summary.get("Low", 0) + 1
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
