from __future__ import annotations

import pytest

from mailhdr.dkim import DkimResult
from mailhdr.dmarc import aligned, evaluate, parse_policy
from mailhdr.dnsio import StaticResolver
from mailhdr.spf import SpfResult


def dk(domain: str, result: str = "pass") -> DkimResult:
    return DkimResult(result, domain=domain)


def z(**records: str) -> StaticResolver:
    return StaticResolver(
        {f"_dmarc.{k.replace('_', '.')}": {"TXT": [v]} for k, v in records.items()}
    )


def ev(zone, from_domain="example.com", dkims=(), spf=None, spf_domain=""):  # type: ignore[no-untyped-def]
    return evaluate(zone, from_domain, list(dkims), spf, spf_domain)


def test_pass_by_aligned_dkim():
    r = ev(z(example_com="v=DMARC1; p=reject"), dkims=[dk("example.com")])
    assert r.result == "pass" and r.dkim_aligned == "example.com" and r.disposition == ""


def test_pass_by_aligned_spf_only():
    r = ev(
        z(example_com="v=DMARC1; p=reject"), spf=SpfResult("pass"), spf_domain="mail.example.com"
    )
    assert r.result == "pass" and r.spf_aligned == "mail.example.com"


def test_fail_reports_policy_and_why():
    r = ev(
        z(example_com="v=DMARC1; p=reject"),
        dkims=[dk("evil.net")],
        spf=SpfResult("pass"),
        spf_domain="evil.net",
    )
    assert r.result == "fail" and r.disposition == "reject" and "another domain" in r.reason


def test_strict_alignment():
    zone = z(example_com="v=DMARC1; p=reject; adkim=s; aspf=s")
    assert ev(zone, dkims=[dk("mail.example.com")]).result == "fail"
    assert ev(zone, dkims=[dk("example.com")]).result == "pass"
    assert ev(zone, spf=SpfResult("pass"), spf_domain="mail.example.com").result == "fail"


def test_failed_dkim_does_not_count():
    r = ev(z(example_com="v=DMARC1; p=reject"), dkims=[dk("example.com", "fail")])
    assert r.result == "fail"


def test_org_domain_fallback_and_sp():
    zone = z(example_com="v=DMARC1; p=reject; sp=quarantine")
    r = ev(zone, from_domain="news.example.com", dkims=[dk("evil.net")])
    assert (
        r.found_at == "example.com"
        and r.applied_policy == "quarantine"
        and r.disposition == "quarantine"
    )
    assert ev(zone, from_domain="example.com", dkims=[dk("evil.net")]).disposition == "reject"


def test_subdomain_record_beats_org_record():
    zone = z(example_com="v=DMARC1; p=reject", news_example_com="v=DMARC1; p=none")
    r = ev(zone, from_domain="news.example.com", dkims=[dk("evil.net")])
    assert r.found_at == "news.example.com" and r.disposition == "none"


def test_no_record_and_dns_failure():
    assert ev(StaticResolver({})).result == "none"
    r = ev(StaticResolver({"_dmarc.example.com": {"TXT": ["!temp"]}}))
    assert r.result == "temperror"


@pytest.mark.parametrize(
    "text",
    [
        "v=DMARC1; p=bogus",
        "v=DMARC2; p=none",
        "p=none; v=DMARC1",
        "v=DMARC1; p=none; pct=200",
        "v=DMARC1; p=none; adkim=x",
        "v=DMARC1",
        "v=DMARC1; sp=nope; p=none",
        "v=DMARC1; p=none; p=reject",
    ],
)
def test_unusable_records_are_ignored(text):  # type: ignore[no-untyped-def]
    r = ev(z(example_com=text), dkims=[dk("example.com")])
    assert r.result == "none"


def test_two_records_are_ignored():
    zone = StaticResolver(
        {"_dmarc.example.com": {"TXT": ["v=DMARC1; p=none", "v=DMARC1; p=reject"]}}
    )
    r = ev(zone)
    assert r.result == "none" and r.warnings


def test_rua_alone_means_monitoring():
    assert parse_policy("v=DMARC1; rua=mailto:a@example.com").p == "none"


def test_warnings():
    r = ev(z(example_com="v=DMARC1; p=none"), dkims=[dk("evil.net")])
    assert any("p=none" in w for w in r.warnings)
    r = ev(z(example_com="v=DMARC1; p=reject; pct=25"), dkims=[dk("evil.net")])
    assert any("25%" in w for w in r.warnings)


def test_alignment_helper():
    assert aligned("a.example.com", "b.example.com", "r")
    assert not aligned("a.example.com", "b.example.com", "s")
    assert not aligned("a.co.uk", "b.co.uk", "r")  # co.uk is a public suffix, not one organisation
    assert not aligned("co.uk", "co.uk", "r") and aligned("co.uk", "co.uk", "s")
