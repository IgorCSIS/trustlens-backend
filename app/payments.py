"""
On-chain payment verification for the paid AI report.

The freemium split:
  - /scan/*   → free basic (rule-based) scan, no payment, no AI cost
  - /report/* → paid AI deep report; caller must prove they paid via the
                PaymentGate contract on-chain.

Flow: the frontend calls PaymentGate.purchaseScan(target) paying scanPrice, then
sends us the tx hash + paymentId. We fetch the receipt, confirm a matching
ScanPurchased event, and consume the paymentId so it can't be reused (anti-replay).
"""
from __future__ import annotations

import os
import re
import sqlite3
import threading
import time

from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3
from web3.logs import DISCARD

from . import rpc

PAYMENT_GATE = Web3.to_checksum_address("0x93F37c9af6b4dB4c51DD3CD1a742a4D9AdC878Ca")

_EVENT_ABI = [
    {
        "type": "event",
        "name": "ScanPurchased",
        "anonymous": False,
        "inputs": [
            {"name": "paymentId", "type": "uint256", "indexed": True},
            {"name": "payer", "type": "address", "indexed": True},
            {"name": "target", "type": "address", "indexed": True},
            {"name": "amount", "type": "uint256", "indexed": False},
            {"name": "timestamp", "type": "uint256", "indexed": False},
        ],
    },
    {
        "type": "function",
        "name": "hasActivePass",
        "stateMutability": "view",
        "inputs": [{"name": "user", "type": "address"}],
        "outputs": [{"name": "", "type": "bool"}],
    },
]

# How stale a signed pass-access message may be (replay window).
_PASS_MAX_AGE = 600  # seconds

_DB = os.path.join(os.path.dirname(__file__), "..", "payments.db")
_lock = threading.Lock()

from .errors import TrustLensError


class PaymentError(TrustLensError):
    """
    Raised when a payment cannot be verified or was already used.

    The caller supplied proof that did not check out, so this is a 402:
    the request is well-formed but payment is still outstanding.
    """

    @property
    def http_status(self) -> int:
        """
        Get the HTTP status this error maps to.

        Returns:
            int: 402, payment required.
        """
        return 402

    @property
    def user_message(self) -> str:
        """
        Get the caller-facing message.

        Returns:
            str: The detail, or a default explanation when none was given.
        """
        return self.detail or "Payment could not be verified."


def _w3(chain: str) -> Web3:
    """
    Get a Web3 client for a chain, as a payment-layer error on failure.

    Wraps the RPC layer's UnsupportedChain in PaymentError so a caller
    verifying a payment sees one error type rather than two.

    Parameters:
        chain (str): Chain identifier.

    Returns:
        Web3: Connected client for the chain.

    Raises:
        PaymentError: If the chain has no configured RPC endpoint.
    """
    try:
        return rpc.w3(chain)
    except rpc.UnsupportedChain as exc:
        raise PaymentError(str(exc)) from exc


def find_payment(tx_hash: str, target: str, payment_id: str, chain: str) -> dict:
    """Verify the tx contains a ScanPurchased event matching target + paymentId.

    Returns the event args on success; raises PaymentError otherwise. Does NOT
    consume the paymentId (see verify_and_consume for the anti-replay step).
    """
    w3 = _w3(chain)
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
    except Exception as exc:  # noqa: BLE001
        raise PaymentError(f"payment transaction not found: {exc}") from exc

    if receipt["status"] != 1:
        raise PaymentError("payment transaction reverted")

    contract = w3.eth.contract(address=PAYMENT_GATE, abi=_EVENT_ABI)
    events = contract.events.ScanPurchased().process_receipt(receipt, errors=DISCARD)

    want_target = Web3.to_checksum_address(target)
    for ev in events:
        # SECURITY: the event must be emitted BY the PaymentGate contract.
        # process_receipt decodes any log with a matching signature, so without
        # this check an attacker could emit a fake ScanPurchased from their own
        # contract and get a free report. Reject anything not from PaymentGate.
        if Web3.to_checksum_address(ev["address"]) != PAYMENT_GATE:
            continue
        args = ev["args"]
        if str(args["paymentId"]) == str(payment_id) and args["target"] == want_target:
            return dict(args)

    raise PaymentError(
        "no matching payment in that transaction "
        "(paymentId / target / contract mismatch)"
    )


def verify_and_consume(tx_hash: str, target: str, payment_id: str, chain: str) -> dict:
    """Verify a payment and mark its paymentId used. Raises on reuse."""
    args = find_payment(tx_hash, target, payment_id, chain)

    with _lock:
        con = sqlite3.connect(_DB)
        try:
            con.execute(
                "CREATE TABLE IF NOT EXISTS used_payments("
                "payment_id TEXT PRIMARY KEY, target TEXT, tx_hash TEXT, chain TEXT)"
            )
            try:
                con.execute(
                    "INSERT INTO used_payments VALUES (?,?,?,?)",
                    (str(payment_id), target.lower(), tx_hash, chain),
                )
                con.commit()
            except sqlite3.IntegrityError as exc:
                raise PaymentError("this payment has already been used") from exc
        finally:
            con.close()

    return {"payer": args["payer"], "amount": int(args["amount"])}


def verify_pass(address: str, message: str, signature: str, chain: str) -> dict:
    """Verify a monthly-pass holder: check the signature proves ownership of
    `address`, that the message is fresh, and that the address holds an active
    pass on-chain. Raises PaymentError otherwise."""
    try:
        recovered = Account.recover_message(encode_defunct(text=message), signature=signature)
    except Exception as exc:  # noqa: BLE001
        raise PaymentError(f"bad signature: {exc}") from exc

    if recovered.lower() != address.lower():
        raise PaymentError("signature does not match the claimed address")

    # freshness — the signed message must carry a recent `issued: <unix>`
    m = re.search(r"issued:\s*(\d+)", message)
    if not m:
        raise PaymentError("missing issued timestamp in signed message")
    age = time.time() - int(m.group(1))
    if age > _PASS_MAX_AGE or age < -_PASS_MAX_AGE:
        raise PaymentError("signed message expired, please sign again")

    w3 = _w3(chain)
    contract = w3.eth.contract(address=PAYMENT_GATE, abi=_EVENT_ABI)
    try:
        active = contract.functions.hasActivePass(Web3.to_checksum_address(recovered)).call()
    except Exception as exc:  # noqa: BLE001
        raise PaymentError(f"could not read pass status: {exc}") from exc

    if not active:
        raise PaymentError("no active monthly pass for this wallet")

    return {"holder": recovered}
