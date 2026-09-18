"""
Proxy resolution: follow a proxy contract to the implementation that actually
holds its logic, so the scanner reads the real code instead of the proxy shell.

Why this exists: scanning a proxy address (e.g. USDC's FiatTokenProxy) and
stopping there is a false negative. The proxy shell is a few lines of
delegatecall; the code that runs lives at the implementation address stored in a
well-known storage slot. USDC on Base leaves the modern EIP-1967 slot empty and
stores its implementation in the legacy zeppelinos slot, so we must check both.

Slot values below were verified live against Base USDC
(0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913): its EIP-1967 slot reads empty and
the zeppelinos slot resolves to the FiatToken logic. Note the derivation
difference: EIP-1967 slots are keccak(label) - 1; the legacy zeppelinos slots are
the raw keccak with NO subtraction. Getting that wrong reintroduces the exact
false negative this feature removes.

resolve() NEVER raises into the caller: an RPC hiccup must degrade a scan, never
turn it into a 500.
"""
from __future__ import annotations

from web3 import Web3

from . import rpc
from .models import ProxyInfo

# --- storage slots (hardcoded; do not recompute at runtime) -----------------
_EIP1967_IMPL = 0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC
_EIP1967_ADMIN = 0xB53127684A568B3173AE13B9F8A6016E243E63B6E8EE1178D6A717850B5D6103
_EIP1967_BEACON = 0xA3F0AD74E5423AEBFD80D3EF4346578335A9A72AEAEE59FF6CB3582B35133D50
# legacy OpenZeppelin/zeppelinos (raw keccak, no minus-1). USDC uses these.
_ZOS_IMPL = 0x7050C9E0F4CA769C69BD3A8EF740BC37934F8E2C036E5A723FD8EE048ED3F8C3
_ZOS_ADMIN = 0x10D6A54A4754C8869D6886B5F5D7FBFA5B4522237EA5C60D11BC4E7A1FF9390B

_IMPL_SELECTOR = "0x5c60da1b"  # implementation()


def _addr_from_word(word: bytes) -> str | None:
    """Extract the right-aligned 20-byte address from a 32-byte storage word."""
    b = bytes(word).rjust(32, b"\x00")[-32:]
    if int.from_bytes(b, "big") == 0:
        return None
    return Web3.to_checksum_address("0x" + b.hex()[-40:])


def _read_addr_slot(w3: Web3, address: str, slot: int) -> str | None:
    """
    Read one storage slot and interpret it as an address.

    Parameters:
        w3 (Web3): Connected client for the target chain.
        address (str): Contract whose storage is read.
        slot (int): Storage slot number.

    Returns:
        str | None: The address held in the slot, or None if the slot is empty.
    """
    return _addr_from_word(w3.eth.get_storage_at(address, slot))


def _has_code(w3: Web3, address: str) -> bool:
    """
    Report whether an address has contract code deployed at it.

    Used to tell a contract admin (multisig or timelock) from a plain
    externally owned account. An unreadable query is treated as "no", which
    is the cautious answer: it never upgrades the report's confidence.

    Parameters:
        w3 (Web3): Connected client for the target chain.
        address (str): Address to check.

    Returns:
        bool: True if code is deployed at address, False otherwise or on error.
    """
    try:
        return len(bytes(w3.eth.get_code(Web3.to_checksum_address(address)))) > 0
    except Exception:  # noqa: BLE001 - treat an unreadable code query as "unknown/no"
        return False


def _beacon_impl(w3: Web3, beacon: str) -> str | None:
    """
    Ask a beacon contract which implementation it currently points at.

    Parameters:
        w3 (Web3): Connected client for the target chain.
        beacon (str): Beacon contract address.

    Returns:
        str | None: The implementation address, or None if the call reverted
            or the address is not a beacon.
    """
    try:
        res = w3.eth.call({"to": Web3.to_checksum_address(beacon), "data": _IMPL_SELECTOR})
    except Exception:  # noqa: BLE001 - beacon.implementation() reverted / not a beacon
        return None
    return _addr_from_word(res)


def _single_hop(w3: Web3, address: str) -> dict | None:
    """One level of proxy resolution. Returns {impl, ptype, admin_slot, beacon}
    for the first pattern with a non-zero slot, or None if `address` is not a
    proxy via any known pattern."""
    impl = _read_addr_slot(w3, address, _EIP1967_IMPL)
    if impl:
        return {"impl": impl, "ptype": "eip1967", "admin_slot": _EIP1967_ADMIN, "beacon": None}

    beacon = _read_addr_slot(w3, address, _EIP1967_BEACON)
    if beacon and _has_code(w3, beacon):
        return {"impl": _beacon_impl(w3, beacon), "ptype": "eip1967-beacon", "admin_slot": None, "beacon": beacon}

    impl = _read_addr_slot(w3, address, _ZOS_IMPL)
    if impl:
        return {"impl": impl, "ptype": "zeppelinos", "admin_slot": _ZOS_ADMIN, "beacon": None}

    return None


def resolve(address: str, chain: str) -> ProxyInfo:
    """Resolve a proxy to its implementation. Always returns a ProxyInfo; never
    raises. is_proxy=False means "scan the address as-is" (the common case)."""
    try:
        addr = Web3.to_checksum_address(address)
    except Exception:  # noqa: BLE001
        return ProxyInfo(proxy_address=address, scanned_address=address, note="")

    info = ProxyInfo(proxy_address=addr, scanned_address=addr)

    try:
        w3 = rpc.w3(chain)
    except Exception:  # noqa: BLE001 - no RPC for this chain: cannot verify proxy state
        info.state_read_ok = False
        info.note = ("Could not read on-chain proxy state (no RPC for this chain), "
                     "so we cannot confirm whether the shown code is what runs.")
        return info

    try:
        hop = _single_hop(w3, addr)
        if hop is None:
            return info  # not a recognized proxy; is_proxy stays False

        info.is_proxy = True
        info.proxy_type = hop["ptype"]
        info.beacon = hop["beacon"]
        impl = hop["impl"]
        info.implementation_address = impl

        # admin / upgrade-control surface
        if hop["admin_slot"] is not None:
            admin = _read_addr_slot(w3, addr, hop["admin_slot"])
            if admin:
                info.admin = admin
                info.admin_is_contract = _has_code(w3, admin)

        # self-reference is not a real delegation
        if impl and impl.lower() == addr.lower():
            info.note = "Proxy implementation slot points back at the proxy itself; treated as no delegation."
            return info

        # one extra hop if the implementation is itself a proxy (rare, bounded)
        if impl and _has_code(w3, impl):
            inner = _single_hop(w3, impl)
            if inner is not None:
                nxt = inner["impl"]
                if nxt and _has_code(w3, nxt) and _single_hop(w3, nxt) is None:
                    impl = nxt
                    info.implementation_address = impl
                else:
                    info.implementation_address = nxt or impl
                    info.note = ("Nested proxy: the final implementation could not be reached "
                                 "within the resolution depth, so the real logic was not analyzed.")
                    return info

        if not impl or not _has_code(w3, impl):
            info.note = ("This is a proxy, but its implementation has no code on-chain, "
                         "so the real logic could not be analyzed.")
            return info

        # clean resolution: this impl is the address we will fetch + scan
        info.implementation_address = impl
        info.scanned_address = impl
        return info

    except Exception as exc:  # noqa: BLE001 - any read failure: degrade, do not raise
        info.state_read_ok = False
        info.note = f"Could not read on-chain proxy state: {str(exc)[:120]}"
        return info
