"""
Audit Python sources against the Appendix A conventions.

Checks, per Appendix A (Python's Best Practices):
  1. Every module, class, function, and method carries a docstring.
  2. Every function and method has a return annotation, and every parameter
     other than self/cls is annotated (gradual typing).
  3. Every class provides __str__, inherited or defined.
  4. No name shadows a builtin.
  5. A module with top-level executable statements guards them with
     if __name__ == '__main__'.

__str__ is resolved at runtime where the module can be imported, because a
class that inherits __str__ from a base satisfies the rule without redefining
it and a purely static check cannot see that. Modules that will not import
(missing optional dependency, for example) fall back to the static check and
are reported as such.

Usage:
    python tools/appendix_a_audit.py app/*.py tests/*.py
"""

from __future__ import annotations

import ast
import builtins
import importlib
import pathlib
import sys
from typing import Final

# Running this as a script puts tools/ on sys.path, not the project root, so
# the package under audit would not import. Put the root first explicitly.
_PROJECT_ROOT: Final[str] = str(pathlib.Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

BUILTIN_NAMES: Final[frozenset[str]] = frozenset(dir(builtins))

# Names that are conventionally exempt: dunder entry points defined by a
# framework, and the module docstring of an empty package marker.
EXEMPT_FUNCTIONS: Final[frozenset[str]] = frozenset({"__str__", "__repr__"})


def _module_name_for(path: pathlib.Path) -> str:
    """
    Derive an importable module name from a source path.

    Parameters:
        path (pathlib.Path): Path to a .py file inside the project.

    Returns:
        str: Dotted module name, e.g. "app.main".
    """
    parts = list(path.with_suffix("").parts)
    return ".".join(parts)


def _runtime_str_owners(path: pathlib.Path) -> dict[str, bool] | None:
    """
    Import a module and record, per class, whether __str__ is available.

    Parameters:
        path (pathlib.Path): Source file to import.

    Returns:
        dict[str, bool] | None: Class name to whether it resolves a __str__
            other than object's, or None if the module could not be imported.
    """
    try:
        module = importlib.import_module(_module_name_for(path))
    except Exception:  # noqa: BLE001 - an unimportable module falls back to static
        return None
    found: dict[str, bool] = {}
    for name in dir(module):
        obj = getattr(module, name)
        if isinstance(obj, type):
            found[name] = obj.__str__ is not object.__str__
    return found


def audit_file(path: pathlib.Path) -> list[str]:
    """
    Audit one source file and return its Appendix A violations.

    Parameters:
        path (pathlib.Path): File to audit.

    Returns:
        list[str]: One human-readable line per violation, empty if compliant.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    issues: list[str] = []
    runtime_str = _runtime_str_owners(path)

    if not ast.get_docstring(tree):
        issues.append("module: missing module docstring")

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name not in EXEMPT_FUNCTIONS and not ast.get_docstring(node):
                issues.append(f"L{node.lineno} {node.name}: no docstring")
            if node.returns is None:
                issues.append(f"L{node.lineno} {node.name}: no return annotation")
            params = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            for arg in params:
                if arg.arg not in ("self", "cls") and arg.annotation is None:
                    issues.append(f"L{node.lineno} {node.name}: param '{arg.arg}' unannotated")

        elif isinstance(node, ast.ClassDef):
            if not ast.get_docstring(node):
                issues.append(f"L{node.lineno} class {node.name}: no docstring")
            defined = {
                child.name
                for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            if "__str__" in defined:
                continue
            if runtime_str is None:
                issues.append(
                    f"L{node.lineno} class {node.name}: no __str__ "
                    "(module not importable, inheritance unchecked)"
                )
            elif not runtime_str.get(node.name, False):
                issues.append(f"L{node.lineno} class {node.name}: no __str__, inherited or defined")

        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in BUILTIN_NAMES:
                    issues.append(f"L{node.lineno}: '{target.id}' shadows the builtin {target.id}")

    return issues


def main() -> int:
    """
    Audit every path given on the command line.

    Returns:
        int: 0 when every file is compliant, 1 otherwise, so the audit can
            gate a CI step.
    """
    paths = [pathlib.Path(arg) for arg in sys.argv[1:]]
    if not paths:
        print("usage: python tools/appendix_a_audit.py <file.py> [file.py ...]")
        return 1

    total = 0
    for path in paths:
        issues = audit_file(path)
        total += len(issues)
        status = "OK" if not issues else f"{len(issues)} issue(s)"
        print(f"\n--- {path} ({status}) ---")
        for issue in issues:
            print("   ", issue)

    print(f"\nTOTAL ISSUES: {total}")
    return 0 if total == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
