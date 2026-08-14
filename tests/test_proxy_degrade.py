"""
Regression tests for the proxy false-negative guards. A proxy (or a possible
proxy) whose real code could not be analyzed must NEVER yield a reassuring
verdict, and must never be cached. These stub proxy.resolve() so they need no
network and return before any fetch/Slither call.
"""
import os

os.environ.setdefault("BASESCAN_API_KEY", "dummy-for-test")

from app import main, proxy  # noqa: E402
from app.models import ProxyInfo  # noqa: E402

_ADDR = "0x" + "11" * 20


def _stub(**kw):
    def fake(address, chain):
        return ProxyInfo(proxy_address=address, scanned_address=address, **kw)
    return fake


def _with_resolve(stub, fn):
    orig = proxy.resolve
    main.proxy.resolve = stub
    try:
        return fn()
    finally:
        main.proxy.resolve = orig


def test_unreadable_state_never_reassures():
    """RPC read failed on a possible proxy: hard stop, not a shell scan."""
    scan, source = _with_resolve(
        _stub(state_read_ok=False, note="RPC down"),
        lambda: main._scan_address_core(_ADDR, "base"),
    )
    assert scan.verdict == "COULD NOT ANALYZE"
    assert scan.risk_score >= 55
    assert source == ""
    assert scan.proxy is not None and scan.proxy.state_read_ok is False
    assert main._degraded_scan(scan) is True
    assert main._cacheable(scan) is False


def test_proxy_with_unresolved_impl_never_reassures():
    """is_proxy True but implementation not analyzable: degraded."""
    scan, _ = _with_resolve(
        _stub(is_proxy=True, note="implementation unverified"),
        lambda: main._scan_address_core(_ADDR, "base"),
    )
    assert scan.verdict == "COULD NOT ANALYZE"
    assert main._degraded_scan(scan) is True
    assert main._cacheable(scan) is False


def test_degraded_ai_report_has_no_reassuring_verdict():
    scan, _ = _with_resolve(
        _stub(state_read_ok=False, note="RPC down"),
        lambda: main._scan_address_core(_ADDR, "base"),
    )
    rep = main._degraded_ai_report(scan)
    assert rep.verdict == "COULD NOT ANALYZE"
    assert rep.adjusted_risk >= 55
    assert rep.triaged == []
    assert rep.limitations  # non-empty scope
    assert rep.disclaimer


def test_non_proxy_is_not_degraded_and_is_cacheable():
    """A clean non-proxy scan (proxy=None) must stay a normal cacheable result."""
    from app.models import ScanResult
    clean = ScanResult(target=_ADDR, risk_score=8, verdict="SAFE-ISH", summary={}, findings=[])
    assert main._degraded_scan(clean) is False
    assert main._cacheable(clean) is True


def test_free_scan_endpoint_degrades_and_does_not_cache():
    """The most exposed surface: the FREE /scan/address path must return COULD
    NOT ANALYZE on unreadable state and must not cache it."""
    from app.models import AddressScanRequest
    key = main._cache_key(_ADDR, "base")
    main._scan_cache.pop(key, None)
    res = _with_resolve(
        _stub(state_read_ok=False, note="RPC down"),
        lambda: main.scan_address(AddressScanRequest(address=_ADDR, chain="base")),
    )
    assert res.verdict == "COULD NOT ANALYZE"
    assert key not in main._scan_cache  # a transient blip must not poison the cache
