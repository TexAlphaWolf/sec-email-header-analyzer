"""DMARC (RFC 7489): find the policy, check alignment, say what the domain asked receivers to do."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from mailhdr import psl
from mailhdr.dkim import DkimResult, parse_tags
from mailhdr.dnsio import DnsError, Resolver
from mailhdr.spf import SpfResult


@dataclass
class DmarcPolicy:
    p: str = "none"
    sp: str | None = None
    adkim: str = "r"
    aspf: str = "r"
    pct: int = 100
    rua: list[str] = field(default_factory=list)
    ruf: list[str] = field(default_factory=list)
    raw: str = ""


@dataclass
class DmarcResult:
    result: str  # pass | fail | none | temperror | permerror
    reason: str = ""
    from_domain: str = ""
    found_at: str = ""
    policy: DmarcPolicy | None = None
    applied_policy: str = ""  # the p/sp that governs this message
    disposition: str = ""  # none | quarantine | reject: what the domain asks for on failure
    dkim_aligned: str = ""  # the d= that aligned, if any
    spf_aligned: str = ""  # the domain SPF passed for and that aligned, if any
    warnings: list[str] = field(default_factory=list)


def parse_policy(text: str) -> DmarcPolicy:
    """Parse a record. Raises ValueError if it is not a usable DMARC record (RFC 7489 6.3)."""
    parts = [p for p in text.split(";") if p.strip()]
    if not parts or parts[0].strip().replace(" ", "") != "v=DMARC1":
        raise ValueError("record does not start with v=DMARC1")
    try:
        tags = parse_tags(";".join(parts[1:]))
    except Exception as exc:
        raise ValueError(str(exc)) from exc
    pol = DmarcPolicy(raw=text.strip())
    allowed = ("none", "quarantine", "reject")
    if "p" in tags:
        if tags["p"].lower() not in allowed:
            raise ValueError(f"p={tags['p'][:20]} is not none, quarantine or reject")
        pol.p = tags["p"].lower()
    elif "rua" not in tags:
        raise ValueError("no p= tag and no rua= to fall back on")
    if "sp" in tags:
        if tags["sp"].lower() not in allowed:
            raise ValueError(f"sp={tags['sp'][:20]} is not none, quarantine or reject")
        pol.sp = tags["sp"].lower()
    for key in ("adkim", "aspf"):
        if key in tags:
            if tags[key].lower() not in ("r", "s"):
                raise ValueError(f"{key}={tags[key][:10]} is not r or s")
            setattr(pol, key, tags[key].lower())
    if "pct" in tags:
        if not re.fullmatch(r"\d{1,3}", tags["pct"]) or int(tags["pct"]) > 100:
            raise ValueError(f"pct={tags['pct'][:10]} is not 0..100")
        pol.pct = int(tags["pct"])
    pol.rua = [u.strip() for u in tags.get("rua", "").split(",") if u.strip()]
    pol.ruf = [u.strip() for u in tags.get("ruf", "").split(",") if u.strip()]
    return pol


def _lookup(resolver: Resolver, name: str) -> tuple[DmarcPolicy | None, str]:
    """(policy, '') or (None, reason). Raises DnsError(temp) on a temporary failure."""
    try:
        texts = resolver.txt(f"_dmarc.{name}")
    except DnsError as exc:
        if exc.kind == "temp":
            raise
        return None, "no record"
    records = [t for t in texts if re.match(r"(?i)^\s*v\s*=\s*DMARC1\s*(;|$)", t)]
    if not records:
        return None, "no record"
    if len(records) > 1:
        return None, "more than one DMARC record: all ignored (RFC 7489 6.6.3)"
    try:
        return parse_policy(records[0]), ""
    except ValueError as exc:
        return None, f"unusable record ({exc})"


def aligned(a: str, b: str, mode: str) -> bool:
    a, b = a.lower().rstrip("."), b.lower().rstrip(".")
    if mode == "s":
        return a == b
    org_a, org_b = psl.organizational_domain(a), psl.organizational_domain(b)
    return org_a is not None and org_a == org_b


def evaluate(
    resolver: Resolver,
    from_domain: str,
    dkim_results: list[DkimResult],
    spf: SpfResult | None,
    spf_domain: str,
) -> DmarcResult:
    """``spf_domain`` is the domain SPF was checked for (MAIL FROM, or HELO when that was empty)."""
    from_domain = from_domain.lower().rstrip(".")
    out = DmarcResult("none", from_domain=from_domain)
    org = psl.organizational_domain(from_domain)
    try:
        policy, why = _lookup(resolver, from_domain)
        found_at = from_domain
        if policy is None and org and org != from_domain and "no record" in why:
            policy, why = _lookup(resolver, org)
            found_at = org
    except DnsError:
        out.result, out.reason = "temperror", "DNS failure looking up the DMARC record"
        return out
    if policy is None:
        out.reason = why if why != "no record" else f"no DMARC record for {from_domain}"
        if "unusable" in why or "more than one" in why:
            out.warnings.append(why)
        return out
    out.policy, out.found_at = policy, found_at

    for res in dkim_results:
        if res.passed and aligned(res.domain, from_domain, policy.adkim):
            out.dkim_aligned = res.domain
            break
    if (
        spf is not None
        and spf.result == "pass"
        and spf_domain
        and aligned(spf_domain, from_domain, policy.aspf)
    ):
        out.spf_aligned = spf_domain

    subdomain = found_at != from_domain
    out.applied_policy = policy.sp if (subdomain and policy.sp) else policy.p
    if out.dkim_aligned or out.spf_aligned:
        out.result = "pass"
        out.reason = "aligned " + " and ".join(
            n for n, v in (("DKIM", out.dkim_aligned), ("SPF", out.spf_aligned)) if v
        )
    else:
        out.result = "fail"
        out.disposition = out.applied_policy
        out.reason = "no aligned DKIM or SPF pass"
        if any(r.passed for r in dkim_results):
            out.reason += " (a DKIM signature passed but for another domain)"
        elif spf is not None and spf.result == "pass":
            out.reason += " (SPF passed but for another domain)"
    if policy.p == "none" and not subdomain:
        out.warnings.append("policy is p=none: monitoring only, spoofed mail is still delivered")
    if policy.pct < 100:
        out.warnings.append(
            f"pct={policy.pct}: the policy applies to only {policy.pct}% of failing mail"
        )
    if out.result == "fail" and out.disposition == "none":
        out.warnings.append("the domain asked for no action on this failure")
    return out
