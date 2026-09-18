"""
Locks the proxy storage-slot constants against their canonical derivations.

The whole proxy-aware feature hinges on one subtlety: EIP-1967 slots are
keccak256(label) - 1, but the legacy OpenZeppelin/zeppelinos slots are the RAW
keccak with NO subtraction. USDC uses the legacy slots, so getting this wrong
silently reintroduces the exact false negative the feature removes. This test is
pure (no network) so it can't go flaky.
"""
from web3 import Web3

from app import proxy


def _keccak_int(label: str) -> int:
    """
    Hash a label and read the digest as a big-endian integer.

    Storage slots are specified as hashes of a label, sometimes minus one, so
    comparing them as integers is the direct way to assert the constants.

    Parameters:
        label (str): The slot label to hash.

    Returns:
        int: The keccak digest as an integer.
    """
    return int.from_bytes(Web3.keccak(text=label), "big")


def test_eip1967_slots_are_hash_minus_one() -> None:
    """EIP-1967 slots are keccak(label) minus one, per the standard."""
    assert proxy._EIP1967_IMPL == _keccak_int("eip1967.proxy.implementation") - 1
    assert proxy._EIP1967_ADMIN == _keccak_int("eip1967.proxy.admin") - 1
    assert proxy._EIP1967_BEACON == _keccak_int("eip1967.proxy.beacon") - 1


def test_zeppelinos_slots_are_raw_hash_no_minus_one() -> None:
    """The older ZeppelinOS layout uses the raw hash, with no minus one."""
    # The USDC path. No "- 1" here on purpose.
    assert proxy._ZOS_IMPL == _keccak_int("org.zeppelinos.proxy.implementation")
    assert proxy._ZOS_ADMIN == _keccak_int("org.zeppelinos.proxy.admin")


def test_impl_selector_is_implementation() -> None:
    """The beacon selector must be implementation(), not something adjacent."""
    assert proxy._IMPL_SELECTOR == "0x" + Web3.keccak(text="implementation()")[:4].hex()


def test_slots_all_distinct() -> None:
    """Two slots colliding would make one proxy type read another's storage."""
    slots = [
        proxy._EIP1967_IMPL, proxy._EIP1967_ADMIN, proxy._EIP1967_BEACON,
        proxy._ZOS_IMPL, proxy._ZOS_ADMIN,
    ]
    assert len(set(slots)) == 5


def test_addr_from_word_extracts_low_20_bytes() -> None:
    """An address occupies the low 20 bytes of a 32-byte storage word."""
    word = bytes.fromhex("000000000000000000000000" + "2Ce6311ddAE708829bc0784C967b7d77D19FD779")
    assert proxy._addr_from_word(word) == Web3.to_checksum_address("0x2Ce6311ddAE708829bc0784C967b7d77D19FD779")
    assert proxy._addr_from_word(b"\x00" * 32) is None  # zero word = slot unset
