"""
Static-analysis engine: runs Slither on Solidity source and normalizes the
output into a TrustLens ScanResult (findings + risk score).

This is the M2 core. M3 will layer an LLM on top of these findings to produce a
plain-English report; for now we return the structured detector output.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile

from .models import Finding, ScanResult

# Weight each Slither impact level toward an overall 0..100 risk score.
_IMPACT_WEIGHT = {
    "High": 40,
    "Medium": 15,
    "Low": 4,
    "Informational": 1,
    "Optimization": 0,
}


def _detect_pragma(source: str, default: str = "0.8.24") -> str:
    """Best-effort solc version from a `pragma solidity` line."""
    m = re.search(r"pragma\s+solidity\s+[^0-9]*([0-9]+\.[0-9]+\.[0-9]+)", source)
    return m.group(1) if m else default


def _ensure_solc(version: str) -> None:
    """Install + select the requested solc via solc-select (idempotent)."""
    subprocess.run(
        ["solc-select", "install", version],
        capture_output=True, text=True, check=False,
    )
    subprocess.run(
        ["solc-select", "use", version],
        capture_output=True, text=True, check=False,
    )


def _score(summary: dict[str, int]) -> tuple[int, str]:
    raw = sum(_IMPACT_WEIGHT.get(k, 0) * v for k, v in summary.items())
    score = min(raw, 100)
    if score >= 40:
        verdict = "DANGEROUS"
    elif score >= 15:
        verdict = "RISKY"
    elif score > 0:
        verdict = "CAUTION"
    else:
        verdict = "CLEAN"
    return score, verdict


def _normalize(raw: dict, target: str) -> ScanResult:
    detectors = (raw.get("results") or {}).get("detectors") or []
    findings: list[Finding] = []
    summary: dict[str, int] = {}

    for d in detectors:
        impact = d.get("impact", "Informational")
        summary[impact] = summary.get(impact, 0) + 1

        lines: list[int] = []
        for el in d.get("elements", []):
            sm = el.get("source_mapping") or {}
            for ln in sm.get("lines", []) or []:
                if ln not in lines:
                    lines.append(ln)

        findings.append(
            Finding(
                check=d.get("check", "unknown"),
                impact=impact,
                confidence=d.get("confidence", "Medium"),
                description=(d.get("description") or "").strip(),
                lines=sorted(lines),
            )
        )

    # Sort most severe first.
    order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3, "Optimization": 4}
    findings.sort(key=lambda f: order.get(f.impact, 9))

    score, verdict = _score(summary)
    return ScanResult(
        target=target,
        risk_score=score,
        verdict=verdict,
        summary=summary,
        findings=findings,
    )


def analyze_source(source: str, filename: str = "Contract.sol") -> ScanResult:
    """Run Slither on a single Solidity source string; return a ScanResult."""
    version = _detect_pragma(source)
    _ensure_solc(version)

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, filename)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(source)
        return analyze_path(path, target=filename)


def analyze_path(
    sol_path: str,
    target: str | None = None,
    solc_version: str | None = None,
    remappings: list[str] | None = None,
    root_dir: str | None = None,
    filter_paths: str | None = None,
) -> ScanResult:
    """Run Slither on a .sol file (optionally inside a multi-file project).

    Two Windows-specific workarounds:
      * ``--json -`` (stdout) is unreliable, so we write the report to a temp
        file and read it back.
      * crytic-compile chokes on absolute temp paths, so we run Slither with its
        cwd set to the project root and pass a *relative* target.
    Slither exits non-zero when it finds issues, so success is keyed on the JSON
    file existing, not the return code.

    :param remappings:   solc remappings (e.g. from a verified standard-json)
    :param root_dir:     compilation root; remappings + target are relative to it
    :param filter_paths: comma-separated path fragments to exclude from findings
                         (e.g. "lib" to skip audited dependencies)
    """
    if solc_version:
        _ensure_solc(solc_version)

    abspath = os.path.abspath(sol_path)
    target = target or os.path.basename(abspath)

    if root_dir:
        work_dir = os.path.abspath(root_dir)
        slither_target = os.path.relpath(abspath, work_dir).replace("\\", "/")
    elif os.path.isdir(abspath):
        work_dir = abspath
        slither_target = "."
    else:
        work_dir = os.path.dirname(abspath)
        slither_target = os.path.basename(abspath)

    with tempfile.TemporaryDirectory() as tmp:
        json_out = os.path.join(tmp, "slither.json")
        cmd = ["slither", slither_target, "--json", json_out]
        if remappings:
            cmd += ["--solc-remaps", " ".join(remappings)]
        if filter_paths:
            cmd += ["--filter-paths", filter_paths]

        proc = subprocess.run(
            cmd, cwd=work_dir, capture_output=True, text=True, check=False
        )

        if not os.path.exists(json_out):
            raise RuntimeError(
                f"Slither produced no report.\nstderr:\n{proc.stderr[-1500:]}"
            )

        with open(json_out, encoding="utf-8") as fh:
            raw = json.load(fh)

    return _normalize(raw, target)
