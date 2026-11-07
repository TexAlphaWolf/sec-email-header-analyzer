"""End to end on the sample messages in examples/, plus one test per kind of finding."""

from __future__ import annotations

from pathlib import Path

import pytest

from mailhdr.analyze import analyze
from mailhdr.dnsio import StaticResolver
from mailhdr.lookalike import load_brands

EX = Path(__file__).resolve().parent.parent / "examples"
ZONE = StaticResolver.from_file(EX / "zone.json")
BRANDS = load_brands(EX / "brands.txt")


def run(name: str):  # type: ignore[no-untyped-def]
    return analyze(
        (EX / name).read_bytes(), StaticResolver.from_file(EX / "zone.json"), brands=BRANDS
    )


def codes(a) -> set[str]:  # type: ignore[no-untyped-def]
    return {f.code for f in a.findings}


def test_legitimate_message_is_clean():
    a = run("01-legitimate.eml")
    assert a.risk == "low" and a.findings == []
    assert (
        [d.result for d in a.dkim] == ["pass"]
        and a.spf.result == "pass"
        and a.dmarc.result == "pass"
    )
    assert (
        a.spf_inputs["ip"] == "192.0.2.25" and a.chain.origin is None
    ) or a.chain.origin.from_ip == "192.0.2.25"
    assert a.summary["subject"] == "Your October statement"


def test_spoofed_sender():
    a = run("02-spoofed-sender.eml")
    assert a.risk == "high" and {"dmarc-fail", "no-dkim", "return-path-differs"} <= codes(a)
    assert a.dmarc.disposition == "reject"


def test_lookalike_domain_passes_authentication_but_is_flagged():
    a = run("03-lookalike-domain.eml")
    assert a.dmarc.result == "pass" and a.spf.result == "pass" and a.dkim[0].passed
    assert {"from-typosquat", "reply-to-differs", "display-name-brand"} <= codes(a)
    assert a.risk == "high"


def test_forged_authentication_results():
    a = run("04-forged-auth-results.eml")
    claimed = [f for f in a.findings if f.code == "claimed-pass"]
    assert len(claimed) == 2 and a.risk == "high"


def test_altered_message_fails_dkim_only():
    a = run("05-altered-in-transit.eml")
    assert a.dkim[0].result == "fail" and "body hash" in a.dkim[0].reason
    assert a.dmarc.result == "pass" and a.risk == "medium"


def test_display_name_with_another_address():
    a = run("06-display-name-trick.eml")
    assert "display-name-address" in codes(a) and a.risk == "high"


def test_offline_mode_checks_nothing_but_still_reads_the_headers():
    a = analyze((EX / "03-lookalike-domain.eml").read_bytes(), None, brands=BRANDS)
    assert a.offline and a.dkim == [] and a.spf is None and a.dmarc is None
    assert "offline" in codes(a) and "from-typosquat" in codes(a)


def test_explicit_ip_helo_and_mailfrom_override():
    data = (EX / "02-spoofed-sender.eml").read_bytes()
    a = analyze(
        data,
        StaticResolver.from_file(EX / "zone.json"),
        ip="192.0.2.77",
        mailfrom="x@acmebank.example",
        helo="mail.acmebank.example",
        brands=BRANDS,
    )
    assert a.spf.result == "pass" and a.spf_inputs["ip_source"] == "given with --ip"


def message(headers: str) -> bytes:
    return (headers + "\r\nbody\r\n").encode()


@pytest.mark.parametrize(
    ("headers", "code"),
    [
        ("To: a@b.example\r\n", "no-from"),
        ("From: a@b.example\r\nFrom: c@d.example\r\n", "multiple-from"),
        ("From: a@b.example, c@d.example\r\n", "multiple-from-addresses"),
        ("From: a@b.example\r\n", "no-date"),
        (
            "From: a@b.example\r\nDate: Fri, 06 Nov 2026 10:00:00 +0000\r\nDate: Fri, 06 Nov 2026 10:00:00 +0000\r\n",
            "multiple-date",
        ),
        ("From: a@b.example\r\nDate: not a date\r\n", "date-bad"),
        ("From: a@b.example\r\nDate: Fri, 06 Nov 2030 10:00:00 +0000\r\n", "date-future"),
        ("From: a@b.example\r\n", "no-received"),
        ("From: a@b.example\r\nReply-To: z@other.example\r\n", "reply-to-differs"),
        ("From: a@mail.b.example\r\nReply-To: z@b.example\r\n", "reply-to-subdomain"),
        ("From: a@b.example\r\nReturn-Path: <x@other.example>\r\n", "return-path-differs"),
        ("From: a@b.example\r\n", "no-return-path"),
        (
            "From: a@b.example\r\nReceived: from x (x [10.0.0.1]) by y; Fri, 06 Nov 2026 10:00:00 +0000\r\n",
            "private-origin",
        ),
    ],
)
def test_individual_findings(headers, code):  # type: ignore[no-untyped-def]
    a = analyze(message(headers), None, now=1_794_000_000)
    assert code in codes(a), [f.code for f in a.findings]


def test_clean_minimal_message_has_no_findings_except_offline_notes():
    a = analyze(
        message(
            "From: a@b.example\r\nDate: Fri, 06 Nov 2026 10:00:00 +0000\r\nMessage-ID: <1@b.example>\r\nReceived: from x ([198.51.100.1]) by y; Fri, 06 Nov 2026 10:00:00 +0000\r\nReturn-Path: <a@b.example>\r\n"
        ),
        None,
        now=1_794_000_000,
    )
    assert {f.severity for f in a.findings} <= {"info"}


def test_dns_trouble_is_reported_as_low_not_as_a_verdict():
    zone = StaticResolver(
        {"_dmarc.acmebank.example": {"TXT": ["!temp"]}, "acmebank.example": {"TXT": ["!temp"]}}
    )
    a = analyze((EX / "01-legitimate.eml").read_bytes(), zone, brands=BRANDS)
    assert a.dmarc.result == "temperror" and a.spf.result == "temperror"
    assert {"dmarc-temperror", "spf-temperror"} <= codes(a)
    assert {f.severity for f in a.findings} <= {"low", "info"}  # trouble with DNS is never "high"
