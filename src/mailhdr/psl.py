"""Public Suffix List lookups, for DMARC's "organizational domain".

The list itself (Mozilla, MPL-2.0) ships inside the package, and ``list_version()`` says which
snapshot it is. The matching follows the algorithm on publicsuffix.org and is checked against the
project's own test file in ``tests/data/test_psl.txt``.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources


def _idna(label: str) -> str:
    try:
        return label.encode("idna").decode("ascii")
    except UnicodeError:
        return label


def _normalise(domain: str) -> list[str] | None:
    domain = domain.strip().rstrip(".").lower()
    if not domain or domain.startswith("."):
        return None
    labels = [_idna(label) for label in domain.split(".")]
    if any(not label for label in labels):
        return None
    return labels


@lru_cache(maxsize=1)
def _rules() -> tuple[frozenset[str], frozenset[str], frozenset[str], str]:
    text = resources.files("mailhdr").joinpath("data/public_suffix_list.dat").read_text("utf-8")
    plain: set[str] = set()
    wild: set[str] = set()
    exceptions: set[str] = set()
    version = "unknown"
    for line in text.splitlines():
        if line.startswith("// VERSION:"):
            version = line.split(":", 1)[1].strip()
        line = line.split()[0] if line.strip() and not line.startswith("//") else ""
        if not line:
            continue
        if line.startswith("!"):
            exceptions.add(".".join(_idna(p) for p in line[1:].split(".")))
        elif line.startswith("*."):
            wild.add(".".join(_idna(p) for p in line[2:].split(".")))
        else:
            plain.add(".".join(_idna(p) for p in line.split(".")))
    return frozenset(plain), frozenset(wild), frozenset(exceptions), version


def list_version() -> str:
    return _rules()[3]


def public_suffix(domain: str) -> str | None:
    labels = _normalise(domain)
    if labels is None:
        return None
    plain, wild, exceptions, _ = _rules()
    best = 1  # the implicit "*" rule: every TLD is a suffix
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        n = len(labels) - i
        if candidate in exceptions:
            return ".".join(labels[i + 1 :])  # an exception rule means one label less
        if candidate in plain:
            best = max(best, n)
        parent = ".".join(labels[i + 1 :])
        if i + 1 < len(labels) and parent in wild:
            best = max(best, n)
    return ".".join(labels[len(labels) - best :])


def organizational_domain(domain: str) -> str | None:
    """The registrable domain (suffix plus one label), or None if ``domain`` is itself a suffix."""
    labels = _normalise(domain)
    suffix = public_suffix(domain)
    if labels is None or suffix is None:
        return None
    n = len(suffix.split("."))
    if len(labels) <= n:
        return None
    return ".".join(labels[len(labels) - n - 1 :])
