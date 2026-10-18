"""Regression tests: requirements.txt must be installable and pinned.

Defects in the original AI-Vuln-Scanner/requirements.txt:

  re           NOT ON PyPI -- `pip install -r requirements.txt` aborts with
               "ERROR: Could not find a version that satisfies the requirement
               re (from versions: none)". It is also a standard library module.
  python3-nmap Not importable by this project at all: vulnscanner.py drives the
               nmap binary through subprocess and parses its XML output, it
               never imports an nmap binding.
  ipaddress    Standard library. The PyPI package is a Python 2 backport that
               shadows the stdlib module.
  beautifulsoup4 / openai / aiohttp
               Never imported. The module docstring states the AI providers are
               called over plain HTTP ("OpenAI (HTTP, no openai SDK
               dependency)").
  everything   Unpinned, so a fresh install silently picks up whatever is
               newest on the day it runs.

Fails on the original requirements.txt, passes on the patched one.
"""
import ast
import pathlib
import re as _re
import sys
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
REQ = ROOT / "requirements.txt"
SRC = ROOT / "vulnscanner.py"

# import name -> distribution name
IMPORT_TO_DIST = {
    "dotenv": "python-dotenv",
}


def _requirement_lines():
    out = []
    for raw in REQ.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def _dist_names():
    names = set()
    for line in _requirement_lines():
        name = _re.split(r"[<>=!~\[\s;]", line, maxsplit=1)[0].strip().lower()
        if name:
            names.add(name)
    return names


@pytest.mark.parametrize(
    "banned, why",
    [
        ("re", "standard library and not on PyPI: install aborts"),
        ("ipaddress", "standard library; the PyPI backport shadows it"),
        ("python3-nmap", "not importable by this project; nmap is used via subprocess"),
        ("beautifulsoup4", "never imported"),
        ("openai", "never imported; providers are called over plain HTTP"),
        ("aiohttp", "never imported"),
    ],
)
def test_no_stdlib_or_unused_distributions(banned, why):
    assert banned not in _dist_names(), f"{banned} must not be a dependency ({why})"


def test_every_requirement_is_version_pinned():
    unpinned = [ln for ln in _requirement_lines() if not _re.search(r"[<>=!~]", ln)]
    assert not unpinned, f"unpinned requirements make installs non-reproducible: {unpinned}"


def test_nmap_is_documented_as_a_system_requirement():
    """The nmap binary is a real prerequisite and must be stated, not faked."""
    text = REQ.read_text(encoding="utf-8")
    assert "nmap" in text.lower()
    assert "PATH" in text, "document that the nmap binary must be on PATH"


def _top_level_imports():
    tree = ast.parse(SRC.read_text(encoding="utf-8"))
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                modules.add(node.module.split(".")[0])
    return modules


def test_every_third_party_import_is_declared():
    stdlib = sys.stdlib_module_names
    third_party = {m for m in _top_level_imports() if m not in stdlib}
    declared = _dist_names()
    missing = {
        m for m in third_party
        if IMPORT_TO_DIST.get(m, m.lower()) not in declared
    }
    assert not missing, f"imported but not declared in requirements.txt: {sorted(missing)}"


def test_no_declared_dependency_is_left_unused():
    """Catches the reverse error: pinning packages the project never imports."""
    # Transitive pins kept deliberately from the Snyk hardening comments.
    allowed_transitive = {"idna", "zipp"}
    imported_dists = {
        IMPORT_TO_DIST.get(m, m.lower()) for m in _top_level_imports()
    }
    unused = _dist_names() - imported_dists - allowed_transitive
    assert not unused, f"declared but never imported: {sorted(unused)}"


@pytest.mark.parametrize("line", _requirement_lines(), ids=lambda s: s)
def test_pinned_version_exists_on_pypi(line):
    """This is what actually failed: a requirement with no matching version."""
    m = _re.match(r"\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)\s*$", line)
    if not m:
        pytest.skip(f"not a strict pin: {line}")
    name, version = m.group(1), m.group(2)
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url, timeout=30) as resp:
        assert resp.status == 200