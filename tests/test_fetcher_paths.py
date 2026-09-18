"""
Regression tests for source-file path containment.

The paths written to disk come from the block explorer, which relays whatever
the contract author put in their source map. They are untrusted input and must
never place a file outside the temporary compilation root.
"""

from __future__ import annotations

import os
import tempfile

from app.fetcher import _write_file


def test_plain_relative_path_lands_inside_root() -> None:
    """The ordinary case still writes where it says it will."""
    with tempfile.TemporaryDirectory() as root:
        written = _write_file(root, "contracts/Token.sol", "// code")
        assert written == os.path.join(os.path.normpath(root), "contracts", "Token.sol")
        assert os.path.isfile(written)


def test_parent_traversal_is_contained() -> None:
    """A ../.. path must not escape the root."""
    with tempfile.TemporaryDirectory() as root:
        written = _write_file(root, "../../etc/evil.sol", "// hostile")
        assert written.startswith(os.path.normpath(root) + os.sep)
        assert os.path.basename(written) == "evil.sol"


def test_sibling_prefix_directory_is_contained() -> None:
    """
    The case the previous guard let through.

    It tested safe.startswith(root), so from a root of /tmp/ab the path
    ../abc/evil.sol normalized to /tmp/abc/evil.sol, which shares the prefix
    but is a different directory. The guard now requires a separator after
    the root, so a sibling whose name merely starts with the root is caught.
    """
    with tempfile.TemporaryDirectory() as parent:
        root = os.path.join(parent, "ab")
        os.makedirs(root)
        sibling = os.path.join(parent, "abc")

        written = _write_file(root, "../abc/evil.sol", "// hostile")

        assert written.startswith(os.path.normpath(root) + os.sep)
        assert not os.path.exists(sibling), "file escaped into the sibling directory"


def test_absolute_path_is_contained() -> None:
    """A leading slash must not turn into an absolute write."""
    with tempfile.TemporaryDirectory() as root:
        written = _write_file(root, "/etc/passwd.sol", "// hostile")
        assert written.startswith(os.path.normpath(root) + os.sep)


def test_windows_separators_are_normalized_and_contained() -> None:
    """Backslash separators are normalized and still contained."""
    with tempfile.TemporaryDirectory() as root:
        written = _write_file(root, r"..\..\evil.sol", "// hostile")
        assert written.startswith(os.path.normpath(root) + os.sep)
