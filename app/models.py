"""Pydantic models for the TrustLens scanner API."""
from __future__ import annotations

from pydantic import BaseModel, Field


class Finding(BaseModel):
    check: str = Field(..., description="Slither detector id, e.g. 'reentrancy-eth'")
    impact: str = Field(..., description="High | Medium | Low | Informational | Optimization")
    confidence: str = Field(..., description="High | Medium | Low")
    description: str
    lines: list[int] = Field(default_factory=list)


class ProxyInfo(BaseModel):
    """Set when the scanned address is a proxy. Lets the report show BOTH the
    address the user entered and the implementation that was actually analyzed."""
    is_proxy: bool = False
    proxy_type: str = ""              # eip1967 | eip1967-beacon | zeppelinos
    proxy_address: str = ""           # the address the user entered
    implementation_address: str | None = None
    scanned_address: str = ""         # the address Slither actually ran on
    implementation_scanned: bool = False  # True only if impl source was fetched + scanned
    admin: str | None = None          # who can upgrade (from the admin slot)
    admin_is_contract: bool | None = None  # True=likely multisig/timelock, False=EOA
    beacon: str | None = None
    state_read_ok: bool = True        # False if the on-chain proxy read failed
    note: str = ""                    # status / degradation message for the UI


class ScanResult(BaseModel):
    target: str = Field(..., description="Address or filename that was scanned")
    engine: str = "slither"
    risk_score: int = Field(..., ge=0, le=100, description="0 (safe) .. 100 (dangerous)")
    verdict: str = Field(..., description="human label derived from risk_score")
    summary: dict[str, int] = Field(default_factory=dict, description="counts by impact")
    findings: list[Finding] = Field(default_factory=list)
    proxy: ProxyInfo | None = None    # populated only for proxy contracts


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
