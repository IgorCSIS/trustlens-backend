"""
Shared Base RPC helper.

Both payments.py (payment/pass verification) and proxy.py (proxy resolution)
need a web3 client for the same chains, so the chain->URL map and the client
factory live here to avoid a cross-module dependency between them.
"""
from __future__ import annotations

from web3 import Web3

RPCS = {
    "base-sepolia": "https://sepolia.base.org",
    "base": "https://mainnet.base.org",
}


class UnsupportedChain(Exception):
    """Raised when a chain has no configured RPC endpoint."""


def w3(chain: str, timeout: int = 20) -> Web3:
    rpc = RPCS.get(chain)
    if not rpc:
        raise UnsupportedChain(f"unsupported chain '{chain}'")
    return Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": timeout}))
