"""
Pydantic models for the TrustLens scanner API.

These are the wire contract: FastAPI parses requests into them and serializes
responses from them, and the frontend reads the field names directly. Fields
are therefore declared as public Pydantic fields rather than private
attributes behind properties. Pydantic already provides what the encapsulation
is for here, validating every value on construction and refusing anything that
does not fit the declared type, and renaming a field to _field would change
the JSON the frontend receives.

Every model does carry a __str__, so a model in a log line or a debugger reads
as a short summary instead of a wall of field values.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class Finding(BaseModel):
    """
    One issue reported by the static analyzer.

    Attributes:
        check (str): Slither detector id, e.g. 'reentrancy-eth'.
        impact (str): Severity label assigned by Slither.
        confidence (str): How sure Slither is that the finding is real.
        description (str): Slither's description of the issue.
        lines (list[int]): Source lines the finding points at.
    """

    check: str = Field(..., description="Slither detector id, e.g. 'reentrancy-eth'")
    impact: str = Field(..., description="High | Medium | Low | Informational | Optimization")
    confidence: str = Field(..., description="High | Medium | Low")
    description: str
    lines: list[int] = Field(default_factory=list)

    def __str__(self) -> str:
        """
        Return a readable representation of the finding.

        Returns:
            str: The detector id with its impact and confidence.
        """
        return f"Finding({self.check}, impact={self.impact}, confidence={self.confidence})"


class ProxyInfo(BaseModel):
    """
    Proxy details for a scanned address.

    Set when the scanned address is a proxy. Lets the report show BOTH the
    address the user entered and the implementation that was actually
    analyzed, which is the difference between "this contract is fine" and
    "the code this contract currently points at is fine".

    Attributes:
        is_proxy (bool): True when the address resolved to a proxy.
        proxy_type (str): eip1967 | eip1967-beacon | zeppelinos.
        proxy_address (str): The address the user entered.
        implementation_address (str | None): Implementation the proxy points at.
        scanned_address (str): The address Slither actually ran on.
        implementation_scanned (bool): True only if implementation source was
            fetched and scanned.
        admin (str | None): Who can upgrade, read from the admin slot.
        admin_is_contract (bool | None): True suggests a multisig or timelock,
            False an externally owned account.
        beacon (str | None): Beacon address for beacon proxies.
        state_read_ok (bool): False if the on-chain proxy read failed, which
            means nothing below it can be trusted.
        note (str): Status or degradation message for the UI.
    """

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

    def __str__(self) -> str:
        """
        Return a readable representation of the proxy details.

        Returns:
            str: Whether it is a proxy, its type, and whether state was read.
        """
        if not self.is_proxy:
            return "ProxyInfo(is_proxy=False)"
        return (
            f"ProxyInfo(type={self.proxy_type or 'unknown'}, "
            f"impl={self.implementation_address or 'unresolved'}, "
            f"impl_scanned={self.implementation_scanned}, "
            f"state_read_ok={self.state_read_ok})"
        )


class ScanResult(BaseModel):
    """
    Result of one static analysis run.

    Attributes:
        target (str): Address or filename that was scanned.
        engine (str): Analysis engine used.
        risk_score (int): 0 (safe) to 100 (dangerous).
        verdict (str): Human label derived from risk_score.
        summary (dict[str, int]): Finding counts by impact.
        findings (list[Finding]): The individual findings.
        proxy (ProxyInfo | None): Populated only for proxy contracts.
    """

    target: str = Field(..., description="Address or filename that was scanned")
    engine: str = "slither"
    risk_score: int = Field(..., ge=0, le=100, description="0 (safe) .. 100 (dangerous)")
    verdict: str = Field(..., description="human label derived from risk_score")
    summary: dict[str, int] = Field(default_factory=dict, description="counts by impact")
    findings: list[Finding] = Field(default_factory=list)
    proxy: ProxyInfo | None = None    # populated only for proxy contracts

    def __str__(self) -> str:
        """
        Return a readable representation of the scan result.

        Returns:
            str: Target, verdict, score, and finding count.
        """
        return (
            f"ScanResult(target={self.target}, verdict={self.verdict}, "
            f"risk={self.risk_score}, findings={len(self.findings)})"
        )


class LocalScanRequest(BaseModel):
    """
    Request to scan Solidity source pasted directly.

    Used for testing without an API key.

    Attributes:
        filename (str): Name to give the pasted source.
        source (str): The Solidity source text.
    """

    filename: str = "Contract.sol"
    source: str

    def __str__(self) -> str:
        """
        Return a readable representation of the request.

        The source itself is summarized by length rather than included, so a
        log line stays short and does not copy a whole contract.

        Returns:
            str: Filename and source length.
        """
        return f"LocalScanRequest(filename={self.filename}, source_chars={len(self.source)})"


class AddressScanRequest(BaseModel):
    """
    Request for a free basic scan of a verified contract by address.

    Attributes:
        address (str): Contract address to scan.
        chain (str): Chain the address lives on.
    """

    address: str
    chain: str = "base-sepolia"

    def __str__(self) -> str:
        """
        Return a readable representation of the request.

        Returns:
            str: Address and chain.
        """
        return f"AddressScanRequest(address={self.address}, chain={self.chain})"


class ReportRequest(BaseModel):
    """
    Request for a paid AI deep report.

    Authorize with EITHER a per-scan payment (tx_hash + payment_id) OR a
    monthly-pass signature (pass_message + pass_signature signed by address).

    Attributes:
        address (str): Contract address to report on.
        chain (str): Chain the address lives on.
        tx_hash (str | None): Per-scan payment transaction hash.
        payment_id (str | None): Per-scan payment identifier.
        pass_message (str | None): Message that was signed for a monthly pass.
        pass_signature (str | None): Signature over pass_message.
    """

    address: str
    chain: str = "base-sepolia"
    # per-scan proof
    tx_hash: str | None = None
    payment_id: str | None = None
    # monthly-pass proof
    pass_message: str | None = None
    pass_signature: str | None = None

    def __str__(self) -> str:
        """
        Return a readable representation of the request.

        Which proof was supplied is reported, but never the signature or
        transaction hash themselves, so payment proofs stay out of logs.

        Returns:
            str: Address, chain, and which kind of proof was provided.
        """
        if self.tx_hash and self.payment_id:
            proof = "per-scan"
        elif self.pass_message and self.pass_signature:
            proof = "monthly-pass"
        else:
            proof = "none"
        return f"ReportRequest(address={self.address}, chain={self.chain}, proof={proof})"
