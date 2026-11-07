"""Random SPF zones evaluated by mailhdr and by pyspf, which must agree on the result word.

pyspf is a separate implementation (by other authors, from RFC 4408 days), so agreement on
hundreds of random zones is evidence the rules were read the same way. Where they differ on
purpose the case is listed in ``KNOWN_DIFFERENCES`` with the reason.
"""

from __future__ import annotations

import ipaddress
import random

import pytest
import spf as pyspf

from mailhdr.dnsio import StaticResolver
from mailhdr.spf import check_host

IPS = ["192.0.2.10", "192.0.2.77", "198.51.100.5", "203.0.113.200", "2001:db8::10", "2001:db8:1::5"]
NAMES = [
    "example.com",
    "a.example.net",
    "b.example.net",
    "c.example.net",
    "mx.example.net",
    "gone.example.net",
]
ADDR = ["192.0.2.10", "198.51.100.5", "192.0.2.64", "2001:db8::10"]


# One place where the two differ on purpose. pyspf refuses a record that includes its own domain
# up front ("trivial recursion"), even when an earlier term would already have matched. RFC 7208
# section 4.6 evaluates terms left to right and stops at the first match, so mailhdr only objects
# when evaluation really reaches the self-include. tests/test_spf.py pins that behaviour.
def has_self_include(zone: dict[str, dict[str, list[str]]]) -> bool:
    return any(f"include:{name}" in " ".join(recs.get("TXT", [])) for name, recs in zone.items())


def random_zone(rng: random.Random) -> dict[str, dict[str, list[str]]]:
    zone: dict[str, dict[str, list[str]]] = {}
    for name in NAMES[:-1]:
        records: dict[str, list[str]] = {}
        terms = []
        for _ in range(rng.randint(0, 5)):
            kind = rng.choice(
                ["ip4", "ip6", "a", "mx", "include", "exists", "a:", "mx:", "-ip4", "~ip4"]
            )
            if kind in ("ip4", "-ip4", "~ip4"):
                net = ipaddress.ip_network(
                    f"{rng.choice(ADDR[:3])}/{rng.choice([24, 28, 32])}", strict=False
                )
                terms.append(f"{kind}:{net}")
            elif kind == "ip6":
                terms.append(f"ip6:2001:db8::/{rng.choice([32, 64, 128])}")
            elif kind in ("a", "mx"):
                terms.append(kind + rng.choice(["", "/24", "//64"]))
            elif kind in ("a:", "mx:"):
                terms.append(kind + rng.choice(NAMES) + rng.choice(["", "/24"]))
            elif kind == "include":
                terms.append(rng.choice(["", "+", "~", "?"]) + "include:" + rng.choice(NAMES))
            else:
                terms.append("exists:" + rng.choice(NAMES))
        end = rng.choice(["-all", "~all", "?all", "", "redirect=" + rng.choice(NAMES), "+all"])
        records["TXT"] = ["v=spf1 " + " ".join([*terms, end]).strip()]
        if rng.random() < 0.7:
            records["A"] = [rng.choice(ADDR[:3])]
        if rng.random() < 0.4:
            records["AAAA"] = ["2001:db8::10"]
        if rng.random() < 0.5:
            records["MX"] = [
                f"{10 * (i + 1)} {rng.choice(NAMES)}" for i in range(rng.randint(1, 3))
            ]
        zone[name] = records
    if rng.random() < 0.3:
        zone["a.example.net"]["TXT"] = ["!temp"]
    return zone


def run_pyspf(zone, ip, sender, monkeypatch):  # type: ignore[no-untyped-def]
    resolver = StaticResolver(zone)

    def lookup(name, qtype, strict=True, timeout=20):  # type: ignore[no-untyped-def]
        from mailhdr.dnsio import DnsError

        name = name.rstrip(".").lower()
        try:
            if qtype == "TXT" or qtype == "SPF":
                if qtype == "SPF":
                    return []
                return [((name, "TXT"), (t.encode(),)) for t in resolver.txt(name)]
            if qtype == "A":
                return [((name, "A"), a) for a in resolver.a(name)]
            if qtype == "AAAA":
                return [((name, "AAAA"), a) for a in resolver.aaaa(name)]
            if qtype == "MX":
                return [((name, "MX"), (p, h)) for p, h in resolver.mx(name)]
            if qtype == "PTR":
                return []
        except DnsError as exc:
            if exc.kind == "temp":
                raise pyspf.TempError("simulated") from exc
        return []

    monkeypatch.setattr(pyspf, "DNSLookup", lookup)
    result, _text = pyspf.check2(ip, sender, "mx.example.net", timeout=5)
    return result


@pytest.mark.parametrize("seed", range(200))
def test_agrees_with_pyspf(seed, monkeypatch):  # type: ignore[no-untyped-def]
    rng = random.Random(seed)
    zone = random_zone(rng)
    if has_self_include(zone):
        pytest.skip("self-include: known, documented difference")
    disagreements = []
    for ip in IPS:
        sender = f"user@{rng.choice(NAMES[:-1])}"
        mine = check_host(StaticResolver(zone), ip, sender, "mx.example.net", now=0).result
        theirs = run_pyspf(zone, ip, sender, monkeypatch)
        if mine != theirs:
            disagreements.append((ip, sender, mine, theirs))
    assert not disagreements, f"zone={zone}\n{disagreements}"
