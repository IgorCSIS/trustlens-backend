"""
Fetch verified Solidity source for a deployed contract from an Etherscan-family
explorer (Basescan for Base). Uses the Etherscan V2 unified API so one key works
across chains.

We always explode the verified source into real files on disk (preserving the
project's relative paths) and reconstruct its remappings. This avoids
crytic-compile's Windows bug with standard-json inputs, and lets Slither compile
multi-file projects (e.g. contracts importing OpenZeppelin) correctly.

Handles all three Etherscan `SourceCode` shapes:
  1. `{{...}}` standard-json-input (multi-file, with remappings/settings)
  2. `{...}` plain multi-file dict
  3. plain flattened source string
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass, field

import requests

_V2_ENDPOINT = "https://api.etherscan.io/v2/api"
_CHAIN_IDS = {
    "base-sepolia": 84532,
    "base": 8453,
    "ethereum": 1,
    "sepolia": 11155111,
}


class SourceNotVerified(Exception):
    pass


@dataclass
class FetchedSource:
    primary_file: str            # abs path to the main contract .sol
    root_dir: str                # dir that is the compilation root (slither cwd)
    solc_version: str            # e.g. "0.8.24"
    contract_name: str
    remappings: list[str] = field(default_factory=list)


def _parse_solc_version(compiler_version: str, source: str) -> str:
    m = re.search(r"(\d+\.\d+\.\d+)", compiler_version or "")
    if m:
        return m.group(1)
    m = re.search(r"pragma\s+solidity\s+[^0-9]*(\d+\.\d+\.\d+)", source)
    return m.group(1) if m else "0.8.24"


def fetch_sources(address: str, api_key: str, chain: str = "base-sepolia") -> FetchedSource:
    chain_id = _CHAIN_IDS.get(chain)
    if chain_id is None:
        raise ValueError(f"Unsupported chain '{chain}'. Known: {list(_CHAIN_IDS)}")

    resp = requests.get(
        _V2_ENDPOINT,
        params={
            "chainid": chain_id,
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": api_key,
        },
        timeout=30,
    )
    resp.raise_for_status()
    payload = resp.json()

    result = payload.get("result")
    if not result or not isinstance(result, list):
        raise RuntimeError(f"Unexpected explorer response: {payload}")

    entry = result[0]
    source_code = entry.get("SourceCode") or ""
    if not source_code:
        raise SourceNotVerified(
            f"No verified source for {address} on {chain}. Verify it first."
        )

    name = entry.get("ContractName") or "Contract"
    solc_version = _parse_solc_version(entry.get("CompilerVersion", ""), source_code)
    root = tempfile.mkdtemp(prefix="trustlens_src_")

    files, remappings = _materialize(source_code, root, fallback_name=f"{name}.sol")
    primary = _pick_primary(files, name)

    return FetchedSource(
        primary_file=primary,
        root_dir=root,
        solc_version=solc_version,
        contract_name=name,
        remappings=remappings,
    )


def _materialize(source_code: str, root: str, fallback_name: str) -> tuple[list[str], list[str]]:
    """Write source(s) to disk under `root`. Return (written_files, remappings)."""
    text = source_code.strip()
    obj = None

    if text.startswith("{{") and text.endswith("}}"):
        obj = json.loads(text[1:-1])
    elif text.startswith("{"):
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            obj = None

    written: list[str] = []
    remappings: list[str] = []

    if isinstance(obj, dict) and "sources" in obj:  # standard-json-input
        remappings = list((obj.get("settings") or {}).get("remappings") or [])
        for rel_path, entry in obj["sources"].items():
            written.append(_write_file(root, rel_path, entry.get("content", "")))
    elif isinstance(obj, dict):  # plain {path: {content}} or {path: source}
        for rel_path, val in obj.items():
            content = val.get("content", "") if isinstance(val, dict) else str(val)
            written.append(_write_file(root, rel_path, content))
    else:  # flattened single file
        written.append(_write_file(root, fallback_name, source_code))

    return written, remappings


def _pick_primary(files: list[str], contract_name: str) -> str:
    """Choose the file that defines the target contract."""
    target = f"{contract_name}.sol".lower()

    # 1) exact filename match, preferring files NOT under a lib/ dependency dir
    matches = [f for f in files if os.path.basename(f).lower() == target]
    non_lib = [f for f in matches if "/lib/" not in f.replace("\\", "/") + "/"]
    if non_lib:
        return non_lib[0]
    if matches:
        return matches[0]

    # 2) content search for the contract definition
    pat = re.compile(rf"\b(?:abstract\s+)?contract\s+{re.escape(contract_name)}\b")
    for f in files:
        try:
            with open(f, encoding="utf-8") as fh:
                if pat.search(fh.read()):
                    return f
        except OSError:
            continue

    # 3) fallback: first file
    return files[0]


def _write_file(root: str, rel_path: str, content: str) -> str:
    rel_path = rel_path.replace("\\", "/").lstrip("/")
    safe = os.path.normpath(os.path.join(root, rel_path))
    if not safe.startswith(os.path.normpath(root)):
        safe = os.path.join(root, os.path.basename(rel_path))
    os.makedirs(os.path.dirname(safe), exist_ok=True)
    with open(safe, "w", encoding="utf-8") as fh:
        fh.write(content)
    return safe
