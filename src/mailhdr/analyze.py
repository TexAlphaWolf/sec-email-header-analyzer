"""Put the pieces together: parse, rebuild the path, re-check authentication, collect findings."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import getaddresses, parsedate_to_datetime

from mailhdr import lookalike, psl
from mailhdr.authres import AuthResults, parse_auth_results
from mailhdr.dkim import DkimResult, verify_all
from mailhdr.dmarc import DmarcResult, evaluate
from mailhdr.dnsio import Resolver
from mailhdr.parse import Message, parse_message
from mailhdr.received import Chain, build_chain
from mailhdr.spf import SpfResult, check_host

SEVERITY_POINTS = {"info": 0, "low": 1, "medium": 2, "high": 5}


@dataclass
class Finding:
    severity: str  # info | low | medium | high
    code: str
    title: str
    detail: str = ""


@dataclass
class Analysis:
    summary: dict[str, str]
    chain: Chain
    claims: list[AuthResults]
    dkim: list[DkimResult]
    spf: SpfResult | None
    spf_inputs: dict[str, str]
    dmarc: DmarcResult | None
    findings: list[Finding] = field(default_factory=list)
    risk: str = "low"
    score: int = 0
    offline: bool = False
    problems: list[str] = field(default_factory=list)


def address_list(header_value: str) -> list[tuple[str, str]]:
    return [(n, a) for n, a in getaddresses([header_value]) if a]


def domain_of(addr: str) -> str:
    return addr.rpartition("@")[2].lower().strip(">").rstrip(".")


def _same_org(a: str, b: str) -> bool:
    if not a or not b:
        return False
    return a == b or (
        psl.organizational_domain(a) is not None
        and psl.organizational_domain(a) == psl.organizational_domain(b)
    )


def analyze(
    data: bytes,
    resolver: Resolver | None,
    *,
    ip: str | None = None,
    helo: str | None = None,
    mailfrom: str | None = None,
    brands: list[str] | None = None,
    now: int | None = None,
) -> Analysis:
    """``resolver=None`` means offline: no authentication is re-checked."""
    msg = parse_message(data)
    chain = build_chain(msg)
    claims = [parse_auth_results(h.value, h.index) for h in msg.all("Authentication-Results")]
    brands = brands if brands is not None else lookalike.load_brands()

    from_headers = msg.all("From")
    from_addrs = address_list(from_headers[0].decoded) if from_headers else []
    from_name, from_addr = from_addrs[0] if from_addrs else ("", "")
    from_domain = domain_of(from_addr)
    return_path = msg.first("Return-Path")
    rp_addr = (address_list(return_path.value) or [("", "")])[0][1] if return_path else ""
    envelope = mailfrom if mailfrom is not None else rp_addr

    def decoded(name: str) -> str:
        header = msg.first(name)
        return header.decoded if header else ""

    def raw(name: str) -> str:
        header = msg.first(name)
        return header.value if header else ""

    summary = {
        "from": decoded("From"),
        "to": decoded("To"),
        "subject": decoded("Subject"),
        "date": raw("Date"),
        "message_id": raw("Message-ID"),
        "return_path": raw("Return-Path"),
        "reply_to": decoded("Reply-To"),
    }

    result = Analysis(summary, chain, claims, [], None, {}, None, offline=resolver is None)
    result.problems.extend(msg.problems)

    spf_ip, ip_source = ip, "given with --ip"
    if spf_ip is None:
        top = next((h for h in chain.hops if h.from_ip), None)
        spf_ip = top.from_ip if top else None
        ip_source = "taken from the topmost Received header (assumed to be the server that connected to the recipient's)"
    spf_helo = (
        helo if helo is not None else next((h.from_host for h in chain.hops if h.from_host), "")
    )
    result.spf_inputs = {
        "ip": spf_ip or "",
        "ip_source": ip_source if spf_ip else "",
        "helo": spf_helo,
        "mailfrom": envelope,
    }

    if resolver is not None:
        result.dkim = verify_all(msg, resolver, now)
        if spf_ip and (envelope or spf_helo):
            result.spf = check_host(resolver, spf_ip, envelope, spf_helo, now)
        spf_domain = domain_of(envelope) if envelope else spf_helo
        if from_domain:
            result.dmarc = evaluate(resolver, from_domain, result.dkim, result.spf, spf_domain)

    result.findings = _findings(
        msg, result, from_name, from_addr, from_domain, rp_addr, brands, now
    )
    result.score = sum(SEVERITY_POINTS[f.severity] for f in result.findings)
    result.risk = "high" if result.score >= 5 else "medium" if result.score >= 2 else "low"
    return result


def _findings(
    msg: Message,
    res: Analysis,
    from_name: str,
    from_addr: str,
    from_domain: str,
    rp_addr: str,
    brands: list[str],
    now: int | None,
) -> list[Finding]:
    out: list[Finding] = []

    def add(severity: str, code: str, title: str, detail: str = "") -> None:
        out.append(Finding(severity, code, title, detail))

    # --- structure of the identity headers
    froms = msg.all("From")
    if not froms:
        add("high", "no-from", "There is no From header")
    if len(froms) > 1:
        add(
            "high",
            "multiple-from",
            f"{len(froms)} From headers",
            "Mail clients may show one while checks apply to another.",
        )
    elif froms and len(address_list(froms[0].decoded)) > 1:
        add("medium", "multiple-from-addresses", "The From header holds more than one address")
    for name in ("Date", "Message-ID"):
        count = len(msg.all(name))
        if count == 0:
            add("low", f"no-{name.lower()}", f"No {name} header", "Real mail servers add one.")
        elif count > 1:
            add("medium", f"multiple-{name.lower()}", f"{count} {name} headers")
    if not msg.all("Received"):
        add(
            "low",
            "no-received",
            "No Received headers",
            "A message that came through a server always has at least one.",
        )

    date = msg.first("Date")
    if date:
        try:
            when = parsedate_to_datetime(date.value)
            when = when if when.tzinfo else when.replace(tzinfo=UTC)
            current = datetime.fromtimestamp(now, UTC) if now else datetime.now(UTC)
            if when - current > timedelta(days=1):
                add("low", "date-future", "The Date header is in the future", date.value)
            newest = max((h.time for h in res.chain.hops if h.time), default=None)
            if newest and abs(when - newest) > timedelta(days=2):
                add(
                    "low",
                    "date-far",
                    "The Date header is more than two days from the delivery time",
                    date.value,
                )
        except (TypeError, ValueError, IndexError):
            add("low", "date-bad", "The Date header cannot be read", date.value)

    # --- who it claims to be from
    if from_addr:
        embedded = re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", from_name)
        if embedded and embedded[0].lower() != from_addr.lower():
            add(
                "high",
                "display-name-address",
                f"The display name shows a different address ({embedded[0]})",
                f"The real sender is {from_addr}; mail apps often show only the name.",
            )
        for kind, why in lookalike.check_domain(from_domain, brands):
            sev = (
                "high"
                if kind in ("homoglyph", "mixed-script")
                else "medium"
                if kind in ("typosquat", "brand-in-domain")
                else "low"
            )
            add(sev, f"from-{kind}", f"From domain: {kind.replace('-', ' ')}", why)
        folded = from_name.lower().replace(" ", "")
        for brand in brands:
            name = brand.split(".")[0]
            if len(name) >= 5 and name in folded and not _same_org(from_domain, brand):
                add(
                    "medium",
                    "display-name-brand",
                    f"The display name mentions {name} but the address is at {from_domain}",
                )
                break

    reply = msg.first("Reply-To")
    if reply and from_domain:
        for _, addr in address_list(reply.decoded):
            rd = domain_of(addr)
            if rd and not _same_org(rd, from_domain):
                add(
                    "medium",
                    "reply-to-differs",
                    f"Replies would go to a different domain ({rd})",
                    f"From is at {from_domain}.",
                )
                break
            if rd and rd != from_domain:
                add("info", "reply-to-subdomain", f"Reply-To is at {rd}, From at {from_domain}")
                break
    if rp_addr and from_domain:
        rd = domain_of(rp_addr)
        if rd and not _same_org(rd, from_domain):
            add(
                "low",
                "return-path-differs",
                f"The bounce address is at a different domain ({rd})",
                "Normal for mailing services; it matters when authentication also fails.",
            )
    if not msg.all("Return-Path"):
        add(
            "info",
            "no-return-path",
            "No Return-Path header",
            "It is added when the final server accepts the message; a saved copy may lack it.",
        )

    # --- the delivery path
    for problem in res.chain.problems:
        add("low", "path", problem)
    if res.chain.origin is None and res.chain.hops:
        add("info", "private-origin", "Every sender address in the path is private or local")

    # --- authentication
    if res.offline:
        add("info", "offline", "Authentication was not re-checked (offline)")
    else:
        for d in res.dkim:
            if d.result in ("pass",):
                for w in d.warnings:
                    add("low", "dkim-warning", f"DKIM ({d.domain}): {w}")
            elif d.result in ("fail", "policy"):
                add(
                    "medium",
                    "dkim-" + d.result,
                    f"DKIM signature for {d.domain or '?'} did not pass: {d.reason}",
                )
            elif d.result in ("permerror", "temperror"):
                add(
                    "low",
                    "dkim-" + d.result,
                    f"DKIM signature for {d.domain or '?'} could not be checked: {d.reason}",
                )
        if not res.dkim:
            add("low", "no-dkim", "The message has no DKIM signature")
        if res.spf:
            if res.spf.result == "fail":
                add(
                    "high",
                    "spf-fail",
                    "SPF fail: the sending server is not allowed to send for this domain",
                    res.spf.reason,
                )
            elif res.spf.result == "softfail":
                add(
                    "medium",
                    "spf-softfail",
                    "SPF softfail: the sending server is probably not authorised",
                    res.spf.reason,
                )
            elif res.spf.result in ("permerror", "temperror"):
                add("low", "spf-" + res.spf.result, f"SPF could not be evaluated: {res.spf.reason}")
            elif res.spf.result in ("none", "neutral"):
                add("low", "spf-" + res.spf.result, f"SPF {res.spf.result}", res.spf.reason)
        else:
            add(
                "info",
                "spf-unchecked",
                "SPF was not checked",
                "It needs the connecting IP and the sender address.",
            )
        dm = res.dmarc
        if dm:
            if dm.result == "fail":
                sev = {"reject": "high", "quarantine": "high", "none": "medium"}.get(
                    dm.disposition, "medium"
                )
                add(
                    sev,
                    "dmarc-fail",
                    f"DMARC fail: {dm.reason}",
                    f"{from_domain} asks receivers to apply p={dm.applied_policy}.",
                )
            elif dm.result == "none":
                add("low", "dmarc-none", "The From domain publishes no DMARC policy", dm.reason)
            elif dm.result in ("temperror", "permerror"):
                add("low", "dmarc-" + dm.result, dm.reason)
            for w in dm.warnings:
                add("info", "dmarc-note", w)

        # --- what the message claims about itself versus what we computed
        mine = {
            "dkim": "pass" if any(d.passed for d in res.dkim) else "",
            "spf": res.spf.result if res.spf else "",
            "dmarc": res.dmarc.result if res.dmarc else "",
        }
        for ar in res.claims:
            for claim in ar.claims:
                if (
                    claim.method in mine
                    and claim.result == "pass"
                    and mine[claim.method]
                    and mine[claim.method] != "pass"
                ):
                    add(
                        "high",
                        "claimed-pass",
                        f"{ar.server or 'a header'} says {claim.method}=pass but mailhdr gets {mine[claim.method]}",
                        "The header may be forged, or DNS changed since the message was delivered, or the message was altered after it was checked.",
                    )
                if claim.method in mine and claim.result == "fail" and mine[claim.method] == "pass":
                    add(
                        "low",
                        "claimed-fail",
                        f"{ar.server or 'a header'} says {claim.method}=fail but mailhdr gets pass",
                    )
        if len(res.claims) > 1:
            add(
                "info",
                "many-auth-results",
                f"{len(res.claims)} Authentication-Results headers from {', '.join(a.server or '?' for a in res.claims)}",
                "Only the one from your own mail server can be trusted; senders can add their own.",
            )

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    out.sort(key=lambda f: order[f.severity])
    return out
