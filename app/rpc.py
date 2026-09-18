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

from .errors import TrustLensError


class UnsupportedChain(TrustLensError):
    """
    Raised when a chain has no configured RPC endpoint.

    The caller named a chain this deployment does not serve, so this is a
    400: the request itself is wrong, not the service.
    """

    @property
    def http_status(self) -> int:
        """
        Get the HTTP status this error maps to.

        Returns:
            int: 400, bad request.
        """
        return 400

    @property
    def user_message(self) -> str:
        """
        Get the caller-facing message.

        Returns:
            str: The detail, or a default explanation when none was given.
        """
        return self.detail or "That chain is not supported."


def w3(chain: str, timeout: int = 20) -> Web3:
    """
    Build a Web3 client for a chain.

    Parameters:
        chain (str): Chain identifier, e.g. "base".
        timeout (int): Request timeout in seconds.

    Returns:
        Web3: Client pointed at that chain's configured RPC endpoint.

    Raises:
        UnsupportedChain: If the chain has no configured endpoint.
    """
    endpoint = RPCS.get(chain)
    if not endpoint:
        raise UnsupportedChain(f"unsupported chain '{chain}'")
    return Web3(Web3.HTTPProvider(endpoint, request_kwargs={"timeout": timeout}))
