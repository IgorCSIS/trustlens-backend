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

# Default to Claude Opus 5; override via env for cost tuning (e.g. claude-sonnet-5).
MODEL = os.getenv("TRUSTLENS_MODEL", "claude-opus-5")

_SYSTEM = (
    "You are a senior smart-contract security auditor. You are given automated "
    "static-analysis findings (from Slither) for a Solidity contract, plus the "
    "contract source. Triage the findings: for each, decide whether it is a "
    "real, exploitable risk or low-value / a false positive, explain why in "
    "plain English a non-expert can follow, and give one concrete recommendation. "
    "Be honest and calibrated: most static-analysis findings on competently "
    "written contracts are low severity, and saying so is the correct answer. "
    "Never invent findings that were not provided to you. Judge only this contract.\n\n"
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
    headline: str = Field(..., description="one-sentence bottom line for the user")
    adjusted_risk: int = Field(..., ge=0, le=100, description="human-calibrated 0..100 risk")
    verdict: str = Field(..., description="SAFE-ISH | CAUTION | RISKY | DANGEROUS")
    triaged: list[TriagedFinding] = Field(default_factory=list)


def triage(scan: ScanResult, source: str, max_source_chars: int = 24_000) -> AIReport:
    """Run the LLM triage over a ScanResult + source; return a structured report."""
    findings_block = "\n".join(
        f"- [{f.impact}/{f.confidence}] {f.check} (lines {f.lines})\n    {f.description}"
        for f in scan.findings
    ) or "(no findings reported by the static analyzer)"

    src = source[:max_source_chars]
    truncated = " (truncated)" if len(source) > max_source_chars else ""

    user = (
        f"Contract: {scan.target}\n"
        f"Static-analysis verdict: {scan.verdict} (raw score {scan.risk_score}/100)\n\n"
        f"FINDINGS:\n{findings_block}\n\n"
        f"SOURCE{truncated}:\n```solidity\n{src}\n```\n\n"
        "Produce the triaged report."
    )

    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY / ant profile
    # thinking disabled keeps latency + cost predictable for a per-scan product and
    # avoids max_tokens contention; structured output is guaranteed to match AIReport.
    response = client.messages.parse(
        model=MODEL,
        max_tokens=12000,  # room for exploit sketches + fix snippets
        thinking={"type": "disabled"},
        system=_SYSTEM,
        messages=[{"role": "user", "content": user}],
        output_format=AIReport,
    )
    return response.parsed_output
