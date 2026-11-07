"""The Public Suffix List matcher against the list's own conformance file."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from mailhdr import psl

CASES = re.findall(
    r"(?m)^checkPublicSuffix\((null|'[^']*'),\s*(null|'[^']*')\)",
    Path(__file__).with_name("data").joinpath("test_psl.txt").read_text(encoding="utf-8"),
)


def _given(text: str) -> str | None:
    return None if text == "null" else text.strip("'")


def _expected(text: str) -> str | None:
    """The file spells answers in Unicode and lower case; mailhdr answers in ASCII (punycode)."""
    value = _given(text)
    return None if value is None else ".".join(psl._idna(label) for label in value.split("."))


def test_there_are_cases():
    assert len(CASES) > 60


@pytest.mark.parametrize(("given", "expected"), [(_given(a), _expected(b)) for a, b in CASES])
def test_publicsuffix_conformance(given, expected):  # type: ignore[no-untyped-def]
    got = psl.organizational_domain(given) if given is not None else None
    assert got == expected


def test_versions_and_private_section():
    assert re.match(r"\d{4}-\d{2}-\d{2}", psl.list_version())
    assert psl.organizational_domain("a.b.example.co.uk") == "example.co.uk"
    assert psl.organizational_domain("co.uk") is None
    assert psl.public_suffix("x.y.unknowntld") == "unknowntld"
    assert psl.organizational_domain("mail.example.com.") == "example.com"
    assert psl.organizational_domain("a..b.com") is None


def test_idn_domains():
    assert psl.organizational_domain("www.食狮.中国") == psl.organizational_domain(
        "www.xn--85x722f.xn--fiqs8s"
    )
