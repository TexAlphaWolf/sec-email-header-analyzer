"""SPF rules from RFC 7208, one behaviour per test, all offline."""

from __future__ import annotations

import ipaddress

import pytest

from mailhdr.dnsio import StaticResolver
from mailhdr.spf import _Ctx, check_host, expand_macros, valid_domain


def spf(
    zone: dict,
    ip: str = "192.0.2.10",
    sender: str = "bob@example.com",
    helo: str = "mail.example.com",
):  # type: ignore[no-untyped-def]
    return check_host(StaticResolver(zone), ip, sender, helo, now=1_700_000_000)


def rec(*terms: str) -> dict:
    return {"TXT": ["v=spf1 " + " ".join(terms)]}


@pytest.mark.parametrize(
    ("terms", "expected"),
    [
        (["ip4:192.0.2.0/24", "-all"], "pass"),
        (["ip4:198.51.100.0/24", "-all"], "fail"),
        (["ip4:198.51.100.0/24", "~all"], "softfail"),
        (["ip4:198.51.100.0/24", "?all"], "neutral"),
        (["ip4:198.51.100.0/24"], "neutral"),
        (["-ip4:192.0.2.10", "+all"], "fail"),
        (["ip4:192.0.2.10"], "pass"),
        (["ip4:192.0.2.0/33"], "permerror"),
        (["ip4:2001:db8::/32"], "permerror"),
        (["ip6:192.0.2.0/24"], "permerror"),
        (["ip4:192.0.2.0/24", "bogus:x", "-all"], "permerror"),
        (["-all", "ip4:192.0.2.10"], "fail"),
    ],
)
def test_basic_mechanisms(terms, expected):  # type: ignore[no-untyped-def]
    assert spf({"example.com": rec(*terms)}).result == expected


def test_no_record_and_unknown_domain():
    assert spf({"example.com": {"TXT": ["hello"]}}).result == "none"
    assert spf({}).result == "none"
    assert spf({"example.com": {"A": ["192.0.2.1"]}}).result == "none"
    assert spf({"example.com": {"TXT": ["!temp"]}}).result == "temperror"


def test_two_records_is_permerror():
    zone = {"example.com": {"TXT": ["v=spf1 -all", "v=spf1 +all"]}}
    assert spf(zone).result == "permerror"


def test_version_must_be_exact():
    assert spf({"example.com": {"TXT": ["v=spf10 +all"]}}).result == "none"
    assert spf({"example.com": {"TXT": ["V=SPF1 -all"]}}).result == "fail"


def test_a_and_mx():
    zone = {
        "example.com": rec("a", "mx/24", "-all"),
        "mail.example.org": {"A": ["198.51.100.7"]},
    }
    zone["example.com"]["A"] = ["192.0.2.10"]
    zone["example.com"]["MX"] = ["10 mail.example.org"]
    assert spf(zone).result == "pass"
    assert spf(zone, ip="198.51.100.200").result == "pass"  # inside the /24
    assert spf(zone, ip="203.0.113.1").result == "fail"


def test_a_with_cidr_and_other_domain():
    zone = {
        "example.com": rec("a:other.example.net/28", "-all"),
        "other.example.net": {"A": ["192.0.2.0"]},
    }
    assert spf(zone).result == "pass"
    assert spf(zone, ip="192.0.2.16").result == "fail"


def test_ipv6_client_uses_aaaa_only():
    zone = {"example.com": {"TXT": ["v=spf1 a -all"], "A": ["192.0.2.10"], "AAAA": ["2001:db8::5"]}}
    assert spf(zone, ip="2001:db8::5").result == "pass"
    assert spf(zone, ip="2001:db8::6").result == "fail"
    zone2 = {"example.com": rec("ip6:2001:db8::/32", "-all")}
    assert spf(zone2, ip="2001:db8:1::1").result == "pass"
    assert spf(zone2, ip="192.0.2.1").result == "fail"


def test_ipv4_mapped_ipv6_is_treated_as_ipv4():
    zone = {"example.com": rec("ip4:192.0.2.0/24", "-all")}
    assert spf(zone, ip="::ffff:192.0.2.10").result == "pass"


def test_include_semantics():
    zone = {
        "example.com": rec("include:_spf.example.net", "-all"),
        "_spf.example.net": rec("ip4:192.0.2.0/24", "-all"),
    }
    assert spf(zone).result == "pass"
    # a fail inside the include is "no match", not a fail of the whole record
    zone2 = {
        "example.com": rec("include:b.example.net", "ip4:192.0.2.10", "-all"),
        "b.example.net": rec("-all"),
    }
    assert spf(zone2).result == "pass"
    # include of a domain without SPF is a permerror
    assert spf({"example.com": rec("include:nope.example.net", "-all")}).result == "permerror"
    # a temp error inside propagates
    zone3 = {
        "example.com": rec("include:t.example.net", "-all"),
        "t.example.net": {"TXT": ["!temp"]},
    }
    assert spf(zone3).result == "temperror"


def test_include_inherits_the_qualifier():
    zone = {
        "example.com": rec("~include:s.example.net", "-all"),
        "s.example.net": rec("ip4:192.0.2.0/24"),
    }
    assert spf(zone).result == "softfail"


def test_redirect():
    zone = {
        "example.com": rec("redirect=_spf.example.net"),
        "_spf.example.net": rec("ip4:192.0.2.0/24", "-all"),
    }
    assert spf(zone).result == "pass"
    assert spf(zone, ip="203.0.113.1").result == "fail"
    # an 'all' makes redirect irrelevant
    zone2 = {
        "example.com": rec("-all", "redirect=_spf.example.net"),
        "_spf.example.net": rec("+all"),
    }
    assert spf(zone2).result == "fail"
    assert spf({"example.com": rec("redirect=nowhere.example.net")}).result == "permerror"


def test_exists_and_macros():
    zone = {
        "example.com": rec("exists:%{i}._ip.%{d}", "-all"),
        "192.0.2.10._ip.example.com": {"A": ["127.0.0.2"]},
    }
    assert spf(zone).result == "pass"
    assert spf(zone, ip="192.0.2.11").result == "fail"


def test_lookup_limit_is_exactly_ten():
    ok = {"example.com": rec(*[f"include:i{n}.example.net" for n in range(10)], "-all")}
    bad = {"example.com": rec(*[f"include:i{n}.example.net" for n in range(11)], "-all")}
    for z in (ok, bad):
        for n in range(11):
            z[f"i{n}.example.net"] = rec("-all")
    assert spf(ok).result == "fail" and spf(ok).lookups == 10
    assert spf(bad).result == "permerror" and "10" in spf(bad).reason


def test_void_lookup_limit():
    zone = {"example.com": rec("a:x1.example.net", "a:x2.example.net", "a:x3.example.net", "-all")}
    res = spf(zone)
    assert res.result == "permerror" and "found nothing" in res.reason
    two = {"example.com": rec("a:x1.example.net", "a:x2.example.net", "-all")}
    assert spf(two).result == "fail"


def test_loop_is_stopped():
    zone = {"example.com": rec("include:example.com", "-all")}
    assert spf(zone).result == "permerror"


def test_mx_with_too_many_hosts():
    zone = {"example.com": rec("mx", "-all")}
    zone["example.com"]["MX"] = [f"10 m{n}.example.net" for n in range(11)]
    assert spf(zone).result == "permerror"


def test_ptr():
    zone = {
        "example.com": rec("ptr", "-all"),
        "10.2.0.192.in-addr.arpa": {"PTR": ["mail.example.com"]},
        "mail.example.com": {"A": ["192.0.2.10"]},
    }
    assert spf(zone).result == "pass"
    forged = dict(zone)
    forged["10.2.0.192.in-addr.arpa"] = {"PTR": ["mail.example.com"]}
    forged["mail.example.com"] = {"A": ["203.0.113.9"]}  # forward lookup does not confirm
    assert spf(forged).result == "fail"
    other = dict(zone)
    other["10.2.0.192.in-addr.arpa"] = {"PTR": ["mail.attacker.net"]}
    other["mail.attacker.net"] = {"A": ["192.0.2.10"]}  # confirmed, but not under example.com
    assert spf(other).result == "fail"


def test_fail_explanation():
    zone = {
        "example.com": rec("-all", "exp=why.example.com"),
        "why.example.com": {"TXT": ["%{i} may not send as %{o}"]},
    }
    res = spf(zone, ip="203.0.113.5")
    assert res.result == "fail" and res.explanation == "203.0.113.5 may not send as example.com"


def test_empty_sender_uses_helo():
    zone = {"mail.example.com": rec("ip4:192.0.2.10", "-all")}
    assert check_host(StaticResolver(zone), "192.0.2.10", "", "mail.example.com").result == "pass"


def test_invalid_inputs():
    assert check_host(StaticResolver({}), "not-an-ip", "a@example.com").result == "permerror"
    assert spf({}, sender="a@localhost").result == "none"
    assert (
        not valid_domain("a..b") and not valid_domain("-a.com") and valid_domain("_spf.example.com")
    )


# --- macros: the table from RFC 7208 section 7.4
@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("%{s}", "strong-bad@email.example.com"),
        ("%{o}", "email.example.com"),
        ("%{d}", "email.example.com"),
        ("%{d4}", "email.example.com"),
        ("%{d3}", "email.example.com"),
        ("%{d2}", "example.com"),
        ("%{d1}", "com"),
        ("%{dr}", "com.example.email"),
        ("%{d2r}", "example.email"),
        ("%{l}", "strong-bad"),
        ("%{l-}", "strong.bad"),
        ("%{lr}", "strong-bad"),
        ("%{lr-}", "bad.strong"),
        ("%{l1r-}", "strong"),
        ("%{ir}.%{v}._spf.%{d2}", "3.2.0.192.in-addr._spf.example.com"),
        ("%{lr-}.lp._spf.%{d2}", "bad.strong.lp._spf.example.com"),
        ("%%", "%"),
        ("a%_b", "a b"),
        ("%-", "%20"),
    ],
)
def test_rfc7208_macro_examples(spec, expected):  # type: ignore[no-untyped-def]
    ctx = _Ctx(
        StaticResolver({}),
        ipaddress.ip_address("192.0.2.3"),
        "strong-bad@email.example.com",
        "mx.example.org",
    )
    assert expand_macros(spec, "email.example.com", ctx) == expected


def test_ipv6_macro_and_uppercase_escape():
    ctx = _Ctx(
        StaticResolver({}), ipaddress.ip_address("2001:db8::cb01"), "a b@email.example.com", "h"
    )
    assert expand_macros("%{ir}.%{v}._spf.%{d2}", "email.example.com", ctx).startswith(
        "1.0.b.c.0.0.0.0"
    )
    assert expand_macros("%{L}", "x.com", ctx) == "a%20b"


def test_self_include_after_a_match_is_not_reached():
    # RFC 7208 4.6: terms run left to right and stop at the first match.
    zone = {"example.com": rec("ip4:192.0.2.0/24", "include:example.com", "-all")}
    assert spf(zone).result == "pass"
    assert spf(zone, ip="203.0.113.1").result == "permerror"  # reached: the loop is an error


@pytest.mark.parametrize(
    "terms",
    [
        ["all:x"],
        ["include"],
        ["include:"],
        ["exists"],
        ["exists:"],
        ["ip4"],
        ["ip4:not-an-ip"],
        ["a/33"],
        ["a//129"],
        ["mx/99"],
        ["redirect="],
        ["exp="],
        ["redirect=a.example.net", "redirect=b.example.net"],
        ["exp=a.example.net", "exp=b.example.net"],
        ["a:%{z}.example.net"],
        ["a:%{d0}.example.net"],
        ["a:%x"],
        ["!!!"],
        ["+"],
        ["a:%{c}.example.net"],  # %{c} is only allowed in an explanation
    ],
)
def test_syntax_errors_are_permerror(terms):  # type: ignore[no-untyped-def]
    assert spf({"example.com": rec(*terms, "-all")}).result == "permerror"


def test_syntax_error_wins_even_after_a_match():
    zone = {"example.com": rec("ip4:192.0.2.10", "bogus")}
    assert spf(zone).result == "permerror"


def test_unknown_modifiers_are_ignored():
    zone = {"example.com": rec("foo=bar", "ip4:192.0.2.10", "-all")}
    assert spf(zone).result == "pass"


def test_dns_trouble_in_mechanisms():
    for term in ("a:t.example.net", "mx:t.example.net", "exists:t.example.net"):
        zone = {
            "example.com": rec(term, "-all"),
            "t.example.net": {"A": ["!temp"], "MX": ["!temp"]},
        }
        assert spf(zone).result == "temperror", term


def test_exists_and_a_with_nothing_found_count_as_void():
    zone = {
        "example.com": rec("exists:x.example.net", "a:y.example.net", "mx:z.example.net", "-all")
    }
    assert spf(zone).result == "permerror"  # three void lookups


def test_ptr_with_temp_error_and_macro_p():
    zone = {
        "example.com": rec("exists:%{p}.example.net", "ptr:example.com", "-all"),
        "10.2.0.192.in-addr.arpa": {"PTR": ["!temp"]},
    }
    assert spf(zone).result == "fail"


def test_explanation_is_ignored_when_unusable():
    base = rec("-all", "exp=why.example.com")
    for txt in ([], ["a", "b"], ["!temp"]):
        zone = {
            "example.com": base,
            "why.example.com": {"TXT": txt} if txt else {"A": ["192.0.2.1"]},
        }
        res = spf(zone, ip="203.0.113.5")
        assert res.result == "fail" and res.explanation == ""


def test_a_mechanism_ignores_addresses_of_the_other_family_and_bad_text():
    zone = {"example.com": {"TXT": ["v=spf1 a -all"], "A": ["not-an-ip", "192.0.2.10"]}}
    assert spf(zone).result == "pass"
    zone6 = {
        "example.com": {"TXT": ["v=spf1 a:h.example.net -all"]},
        "h.example.net": {"AAAA": ["192.0.2.10", "zzz"]},
    }
    assert spf(zone6, ip="2001:db8::1").result == "fail"


def test_trace_is_filled_in():
    res = spf(
        {
            "example.com": rec("include:_s.example.net", "-all"),
            "_s.example.net": rec("ip4:192.0.2.0/24", "-all"),
        }
    )
    assert res.result == "pass" and res.record.startswith("v=spf1 include:")
    assert any("_s.example.net" in line for line in res.trace)
