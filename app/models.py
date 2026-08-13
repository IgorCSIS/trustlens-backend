"""Pydantic models for the TrustLens scanner API."""
from __future__ import annotations

from pydantic import BaseModel, Field


class Finding(BaseModel):
    check: str = Field(..., description="Slither detector id, e.g. 'reentrancy-eth'")
    impact: str = Field(..., description="High | Medium | Low | Informational | Optimization")
    confidence: str = Field(..., description="High | Medium | Low")
    description: str
    lines: list[int] = Field(default_factory=list)


class ScanResult(BaseModel):
    target: str = Field(..., description="Address or filename that was scanned")
    engine: str = "slither"
    risk_score: int = Field(..., ge=0, le=100, description="0 (safe) .. 100 (dangerous)")
    verdict: str = Field(..., description="human label derived from risk_score")
    summary: dict[str, int] = Field(default_factory=dict, description="counts by impact")
    findings: list[Finding] = Field(default_factory=list)


class LocalScanRequest(BaseModel):
    """Scan Solidity source pasted directly (used for testing without an API key)."""
    filename: str = "Contract.sol"
    source: str


class AddressScanRequest(BaseModel):
    """Free basic scan of a verified contract by address."""
    address: str
    chain: str = "base-sepolia"


class ReportRequest(BaseModel):
    """Paid AI deep report. Authorize with EITHER a per-scan payment
    (tx_hash + payment_id) OR a monthly-pass signature (pass_message +
    pass_signature signed by `address`)."""
    address: str
    chain: str = "base-sepolia"
    # per-scan proof
    tx_hash: str | None = None
    payment_id: str | None = None
    # monthly-pass proof
    pass_message: str | None = None
    pass_signature: str | None = None
