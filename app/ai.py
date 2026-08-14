"""
AI reasoning layer (M3).

Takes the raw Slither findings from M2 plus the contract source, and asks Claude
to triage them: which findings are real and exploitable, which are noise, in
plain English a non-expert can act on. This is the TrustLens differentiator —
rule-based scanners stop at M2; we explain and rank.

Server-side only: the Anthropic API key lives in the backend .env, never on the
user's device. The scan fee (M1 PaymentGate) covers the per-call cost.
"""
from __future__ import annotations

import os

import anthropic
from pydantic import BaseModel, Field

from .models import ScanResult

# Default to Claude Sonnet (structured triage does not need Opus, and this cuts
# per-scan cost several-fold on a solo-founder budget). Override via env, e.g.
# TRUSTLENS_MODEL=claude-opus-5 for the hardest contracts.
MODEL = os.getenv("TRUSTLENS_MODEL", "claude-sonnet-5")

# Attached server-side to every report so no result is ever a naked verdict. A
# safety tool that says "safe" without limits is a liability; this makes the
# scope unavoidable regardless of what the model returns.
DISCLAIMER = (
    "Automated triage using static analysis and AI review. This is not a "
    "professional security audit. It cannot detect every vulnerability, cannot "
    "evaluate off-chain, economic, or governance risk, and cannot guarantee a "
    "contract is safe. Do not make financial decisions based on this report alone."
)

_SYSTEM = (
    "You are a senior smart-contract security auditor. You are given automated "
    "static-analysis findings (from Slither) for a Solidity contract, plus the "
    "contract source. Triage the findings: for each, decide whether it is a "
    "real, exploitable risk or low-value / a false positive, explain why in "
    "plain English a non-expert can follow, and give one concrete recommendation. "
    "Be honest and calibrated: most static-analysis findings on competently "
    "written contracts are low severity, and saying so is the correct answer. "
    "Never invent findings that were not provided to you. Judge only this contract.\n\n"
    "CRITICAL FRAMING: never GUARANTEE that a contract is safe, secure, or "
    "audited. You are reducing false alarms and surfacing real risk, not clearing "
    "a contract. The lowest-risk verdict is 'SAFE-ISH', which means low concern "
    "with caveats, never a guarantee. The headline reports what you found and what "
    "you could not check, never a promise of safety. Static analysis cannot see "
    "off-chain or economic risk, upgrade/admin powers beyond what the source "
    "shows, or anything in unverified code.\n\n"
    "Populate 'limitations' with 3-6 short, concrete things THIS analysis did not "
    "or could not check (e.g. off-chain oracle manipulation, tokenomics/economic "
    "rug design, admin-key trust, upgradeability, anything not in the provided "
    "source). This is mandatory.\n\n"
    "For any finding that is REAL (verdict critical / worth-fixing / minor — i.e. "
    "NOT a false positive), you must also produce three developer artifacts, all "
    "grounded in THIS contract's actual code:\n"
    "  - exploit_sketch: 2-4 sentences describing concretely how the issue is "
    "abused or goes wrong — a specific scenario with the actor and the outcome, "
    "not a generic definition. Make it credible and specific to this code.\n"
    "  - vulnerable_snippet: the exact offending Solidity line(s) copied from the "
    "source (a few lines max, enough to locate it).\n"
    "  - fixed_snippet: a drop-in corrected version of those same line(s) the dev "
    "can paste in to fix it. Keep it minimal and directly pasteable.\n"
    "For FALSE POSITIVES, set all three of these to an empty string \"\" — do not "
    "fabricate an exploit for something that is not a real risk."
)


class TriagedFinding(BaseModel):
    check: str = Field(..., description="Slither detector id this maps to")
    original_impact: str = Field(..., description="Slither's impact label")
    verdict: str = Field(
        ...,
        description="one of: critical | worth-fixing | minor | false-positive",
    )
    explanation: str = Field(..., description="plain-English why-it-matters (or doesn't)")
    recommendation: str = Field(..., description="one concrete action, or 'no action needed'")
    exploit_sketch: str = Field(
        ...,
        description="REAL findings: concrete attack/failure scenario. Empty '' for false positives.",
    )
    vulnerable_snippet: str = Field(
        ...,
        description="REAL findings: the offending Solidity line(s). Empty '' for false positives.",
    )
    fixed_snippet: str = Field(
        ...,
        description="REAL findings: drop-in corrected replacement code. Empty '' for false positives.",
    )


class AIReport(BaseModel):
    headline: str = Field(..., description="one-sentence bottom line; reports what was found, never a guarantee of safety")
    adjusted_risk: int = Field(..., ge=0, le=100, description="human-calibrated 0..100 risk")
    verdict: str = Field(..., description="SAFE-ISH | CAUTION | RISKY | DANGEROUS (SAFE-ISH = low concern with caveats, never a guarantee)")
    limitations: list[str] = Field(
        default_factory=list,
        description="what this analysis did NOT or could not check (mandatory, 3-6 items)",
    )
    triaged: list[TriagedFinding] = Field(default_factory=list)
    disclaimer: str = Field(default="", description="set server-side; scope + not-an-audit notice")


def triage(scan: ScanResult, source: str, max_source_chars: int = 24_000) -> AIReport:
    """Run the LLM triage over a ScanResult + source; return a structured report."""
    findings_block = "\n".join(
        f"- [{f.impact}/{f.confidence}] {f.check} (lines {f.lines})\n    {f.description}"
        for f in scan.findings
    ) or "(no findings reported by the static analyzer)"

    src = source[:max_source_chars]
    truncated = " (truncated)" if len(source) > max_source_chars else ""

    proxy_ctx = ""
    p = getattr(scan, "proxy", None)
    if p and p.is_proxy:
        proxy_ctx = (
            f"\nPROXY CONTEXT: {scan.target} is a {p.proxy_type or 'proxy'} contract. The source below "
            f"is its current implementation at {p.implementation_address}, which an admin can replace, "
            f"so the deployed behavior can change after this scan. Reflect the upgradeability and the "
            f"admin/centralization risk in the headline and limitations. {p.note}\n"
        )
    elif p and not p.state_read_ok:
        proxy_ctx = (
            f"\nPROXY CONTEXT: on-chain proxy state for {scan.target} could not be read ({p.note}), "
            f"so we cannot confirm the source below is the code that actually runs. Note this as a "
            f"prominent limitation.\n"
        )

    user = (
        f"Contract: {scan.target}\n"
        f"Static-analysis verdict: {scan.verdict} (raw score {scan.risk_score}/100)\n"
        f"{proxy_ctx}\n"
        f"FINDINGS:\n{findings_block}\n\n"
        f"SOURCE{truncated}:\n```solidity\n{src}\n```\n\n"
        "Produce the triaged report."
    )

    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY / ant profile
    # thinking disabled keeps latency + cost predictable for a per-scan product and
    # avoids max_tokens contention; structured output is guaranteed to match AIReport.
    # System prompt is marked cacheable so it is not re-billed on every scan.
    response = client.messages.parse(
        model=MODEL,
        max_tokens=12000,  # room for exploit sketches + fix snippets
        thinking={"type": "disabled"},
        system=[{"type": "text", "text": _SYSTEM, "cache_control": {"type": "ephemeral"}}],
        messages=[{"role": "user", "content": user}],
        output_format=AIReport,
    )
    report = response.parsed_output
    # Attach the scope notice server-side so every report carries it, regardless
    # of what the model returned. Never ship a naked verdict.
    report.disclaimer = DISCLAIMER
    return report
