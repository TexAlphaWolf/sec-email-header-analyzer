"""Check mailhdr against the real Internet's DNS. Needs network access; run it where DNS works.

    pip install -e ".[dev]" && python tools/live_check.py

What it does, for a list of well-known domains:
  spf    evaluates SPF for several IP addresses with mailhdr and with pyspf, both asking real DNS
  dmarc  fetches each DMARC record and compares the policy mailhdr reads with a plain regex on the
         raw TXT answer
  dkim   downloads published DKIM keys and compares the RSA modulus mailhdr extracts with the
         one the ``cryptography`` package extracts from the same bytes

Real records change, so a difference is retried once before it counts. Prints JSON, then OK or FAILED.
"""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import contextlib

import dns.resolver
import spf as pyspf
from cryptography.hazmat.primitives import serialization

from mailhdr import psl
from mailhdr.dkim import parse_key_record, rsa_public_numbers
from mailhdr.dmarc import parse_policy
from mailhdr.dnsio import DnsError, DnsPythonResolver
from mailhdr.spf import check_host

DOMAINS = [
    "google.com",
    "gmail.com",
    "microsoft.com",
    "outlook.com",
    "github.com",
    "amazon.com",
    "apple.com",
    "paypal.com",
    "facebook.com",
    "linkedin.com",
    "cloudflare.com",
    "ietf.org",
    "mozilla.org",
    "wikipedia.org",
    "ubuntu.com",
    "debian.org",
    "poste.it",
    "unicredit.it",
    "intesasanpaolo.com",
    "aruba.it",
    "libero.it",
    "mailchimp.com",
    "salesforce.com",
    "dropbox.com",
    "netflix.com",
]
FIXED_IPS = ["8.8.8.8", "192.0.2.1", "2001:4860:4860::8888"]
DKIM_CANDIDATES = [
    "20230601._domainkey.gmail.com",
    "20221208._domainkey.gmail.com",
    "20210112._domainkey.gmail.com",
    "20161025._domainkey.gmail.com",
    "selector1._domainkey.microsoft.com",
    "google._domainkey.ietf.org",
    "s1._domainkey.sendgrid.net",
    "k1._domainkey.mailchimp.com",
]


def mx_ips(domain: str) -> list[str]:
    ips: list[str] = []
    try:
        for mx in dns.resolver.resolve(domain, "MX", lifetime=5):
            for rtype in ("A", "AAAA"):
                with contextlib.suppress(Exception):
                    ips += [
                        r.address for r in dns.resolver.resolve(str(mx.exchange), rtype, lifetime=5)
                    ][:1]
            if len(ips) >= 3:
                break
    except Exception:
        pass
    return ips[:3]


def pyspf_result(ip: str, sender: str) -> tuple[str, str]:
    """(result word, pyspf's own explanation), so a difference can be understood from the log."""
    try:
        word, text = pyspf.check2(ip, sender, "mx." + sender.split("@")[1], timeout=10)
        return word, str(text)[:160]
    except Exception as exc:
        return f"error:{type(exc).__name__}", str(exc)[:160]


def live_spf() -> dict:
    resolver = DnsPythonResolver(timeout=8)
    compared = agree = with_record = 0
    words: dict[str, int] = {}
    diffs = []
    lookups = []
    for domain in DOMAINS:
        try:
            if not any(t.lower().startswith("v=spf1") for t in resolver.txt(domain)):
                continue
        except DnsError:
            continue
        with_record += 1
        for ip in mx_ips(domain) + FIXED_IPS:
            sender = f"user@{domain}"
            for attempt in (1, 2):
                mine = check_host(resolver, ip, sender, "mx." + domain)
                theirs, theirs_text = pyspf_result(ip, sender)
                if mine.result == theirs or attempt == 2:
                    break
                time.sleep(1)
            compared += 1
            words[mine.result] = words.get(mine.result, 0) + 1
            lookups.append(mine.lookups)
            if mine.result == theirs:
                agree += 1
            else:
                diffs.append(
                    {
                        "domain": domain,
                        "ip": ip,
                        "mine": mine.result,
                        "theirs": theirs,
                        "why": mine.reason[:120],
                        "theirs_text": theirs_text,
                    }
                )
    return {
        "domains_with_spf": with_record,
        "evaluations": compared,
        "agree": agree,
        "differences": diffs,
        "result_words": dict(sorted(words.items())),
        "max_dns_lookups_seen": max(lookups, default=0),
    }


def live_dmarc() -> dict:
    resolver = DnsPythonResolver(timeout=8)
    parsed = agree = 0
    rows = []
    for domain in DOMAINS:
        try:
            texts = [
                t
                for t in resolver.txt(f"_dmarc.{domain}")
                if t.lower().lstrip().startswith("v=dmarc1")
            ]
        except DnsError:
            continue
        if len(texts) != 1:
            continue
        m = re.search(r"(?i)(?:^|;)\s*p\s*=\s*(\w+)", texts[0])
        try:
            policy = parse_policy(texts[0])
        except ValueError as exc:
            rows.append({"domain": domain, "error": str(exc), "raw": texts[0][:100]})
            continue
        parsed += 1
        same = m is not None and m.group(1).lower() == policy.p
        agree += same
        rows.append(
            {
                "domain": domain,
                "p": policy.p,
                "sp": policy.sp,
                "pct": policy.pct,
                "agrees_with_regex": same,
            }
        )
    return {"records_parsed": parsed, "agree_with_regex": agree, "rows": rows}


def live_dkim() -> dict:
    resolver = DnsPythonResolver(timeout=8)
    found = same = 0
    rows = []
    for name in DKIM_CANDIDATES:
        try:
            texts = resolver.txt(name)
        except DnsError:
            continue
        for text in texts:
            if "p=" not in text:
                continue
            try:
                record = parse_key_record(text)
            except Exception as exc:
                rows.append({"name": name, "error": str(exc)[:100]})
                continue
            if record.revoked or record.key_type != "rsa":
                rows.append({"name": name, "kind": record.key_type, "revoked": record.revoked})
                continue
            found += 1
            n, e = rsa_public_numbers(record.public)
            key = serialization.load_der_public_key(record.public)
            ok = key.public_numbers().n == n and key.public_numbers().e == e
            same += ok
            rows.append({"name": name, "bits": n.bit_length(), "e": e, "same_as_cryptography": ok})
    return {"keys_parsed": found, "same_modulus_as_cryptography": same, "rows": rows}


def main() -> int:
    try:
        DnsPythonResolver(timeout=5).txt("example.com")
    except DnsError as exc:
        print(json.dumps({"error": f"DNS does not work from here: {exc}"}))
        print("FAILED")
        return 1
    result = {
        "public_suffix_list": psl.list_version(),
        "spf": live_spf(),
        "dmarc": live_dmarc(),
        "dkim": live_dkim(),
    }
    print(json.dumps(result, indent=2))
    s, d, k = result["spf"], result["dmarc"], result["dkim"]
    ok = (
        s["domains_with_spf"] >= 15
        and s["evaluations"] >= 50
        and not s["differences"]
        and d["records_parsed"] >= 8
        and d["agree_with_regex"] == d["records_parsed"]
        and k["keys_parsed"] >= 1
        and k["same_modulus_as_cryptography"] == k["keys_parsed"]
    )
    print("OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
