"""Rebuild the delivery path from the Received headers.

Every server a message passes through adds a Received header on top, so the list reads newest
first. Servers write these headers in their own styles, so the parser is tolerant: it pulls out
what it can find and leaves the rest empty. Only the topmost few headers were written by servers
the recipient trusts; everything below was written by someone else and can be invented.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from itertools import pairwise

from mailhdr.parse import Message

IP_KINDS = ("loopback", "private", "linklocal", "cgnat", "documentation", "public")

_DOC_NETS = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_BRACKET_IP = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]", re.I)
_BARE_IP = re.compile(r"(?<![\w.:])((?:\d{1,3}\.){3}\d{1,3})(?![\w.])")
_CLAUSE = re.compile(r"\b(from|by|with|id|for|via)\s+", re.I)


def classify_ip(text: str) -> str:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return "invalid"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return "loopback"
    if any(ip in net for net in _DOC_NETS):
        return "documentation"
    if ip.is_link_local:
        return "linklocal"
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT:
        return "cgnat"
    if ip.is_private or ip.is_unspecified or ip.is_reserved or ip.is_multicast:
        return "private"
    return "public"


@dataclass
class Hop:
    index: int  # position in the message, 0 = topmost (newest)
    raw: str
    from_host: str = ""  # what the sending server called itself (HELO/EHLO)
    from_rdns: str = ""  # the reverse-DNS name the receiving server recorded, if shown
    from_ip: str = ""
    by: str = ""
    protocol: str = ""
    id: str = ""
    for_addr: str = ""
    time: datetime | None = None
    delay: timedelta | None = None  # time since the previous (older) hop
    notes: list[str] = field(default_factory=list)

    @property
    def ip_kind(self) -> str:
        return classify_ip(self.from_ip) if self.from_ip else ""


def _strip_comments_keep(text: str) -> str:
    """Hide the content of (...) so words inside comments are not mistaken for clauses, but keep
    the text recoverable by position: the content is replaced by same-length placeholders."""
    out, depth = [], 0
    for ch in text:
        if ch == "(":
            depth += 1
            out.append(ch)
        elif ch == ")" and depth:
            depth -= 1
            out.append(ch)
        elif depth:
            out.append("\x00" if ch.isalpha() else ch)
        else:
            out.append(ch)
    return "".join(out)


def parse_received(value: str, index: int = 0) -> Hop:
    hop = Hop(index=index, raw=value)
    body, _, date_text = value.rpartition(";")
    if not body:
        body, date_text = value, ""
    if date_text.strip():
        try:
            when = parsedate_to_datetime(date_text.strip())
            hop.time = when if when.tzinfo else when.replace(tzinfo=UTC)
        except (TypeError, ValueError, IndexError):
            hop.notes.append("unreadable date")
    # restore the true text for each clause by slicing the original with the masked offsets
    masked = _strip_comments_keep(body)
    spans = [(m.group(1).lower(), m.end()) for m in _CLAUSE.finditer(masked)]
    starts = [m.start() for m in _CLAUSE.finditer(masked)]
    clauses: dict[str, str] = {}
    for i, (name, end) in enumerate(spans):
        stop = starts[i + 1] if i + 1 < len(starts) else len(body)
        clauses.setdefault(name, body[end:stop].strip())

    sender = clauses.get("from", "")
    if sender:
        hop.from_host = sender.split()[0].strip("()[]") if not sender.startswith("(") else ""
        comment = " ".join(re.findall(r"\(([^()]*)\)", sender))
        brackets = _BRACKET_IP.findall(sender)
        bare = _BARE_IP.findall(comment)
        found = brackets + [b for b in bare if b not in brackets]
        if (
            not found
            and re.fullmatch(r"\[?[0-9A-Fa-f:.]+\]?", sender.split()[0])
            and re.search(r"[.:]", sender.split()[0])
        ):
            found = [sender.split()[0].strip("[]")]
            hop.from_host = ""
        for ip in found:
            ip = ip.rstrip(".")
            if classify_ip(ip) != "invalid":
                hop.from_ip = ip
                break
        # reverse-DNS name: first hostname-looking token inside the comment that is not an IP
        for token in re.split(r"[\s,]+", re.sub(r"\[[^\]]*\]", " ", comment)):
            token = token.strip("()<>")
            token = token.removeprefix("helo=").removeprefix("HELO=")
            if (
                "." in token
                and classify_ip(token) == "invalid"
                and re.fullmatch(r"[A-Za-z0-9._-]+", token)
            ):
                hop.from_rdns = token.lower()
                break
        if hop.from_host and classify_ip(hop.from_host.strip("[]")) != "invalid":
            hop.from_host = hop.from_host.strip("[]")
    hop.by = (clauses.get("by", "").split() or [""])[0].strip("()")
    hop.protocol = (clauses.get("with", "").split() or [""])[0].strip("()")
    hop.id = (clauses.get("id", "").split() or [""])[0].strip("()<>;")
    m = re.search(r"<?([^\s<>;()]+@[^\s<>;()]+)>?", clauses.get("for", ""))
    hop.for_addr = m.group(1) if m else ""
    return hop


@dataclass
class Chain:
    hops: list[Hop]  # topmost (newest) first, as in the message
    origin: Hop | None = None  # earliest hop with a non-private source address
    total_delay: timedelta | None = None
    problems: list[str] = field(default_factory=list)

    @property
    def chronological(self) -> list[Hop]:
        return list(reversed(self.hops))


SLOW_HOP = timedelta(hours=1)
SKEW = timedelta(minutes=5)


def build_chain(msg: Message) -> Chain:
    hops = [parse_received(h.value, i) for i, h in enumerate(msg.all("Received"))]
    chain = Chain(hops=hops)
    ordered = chain.chronological
    previous: Hop | None = None
    for hop in ordered:
        if previous is not None and hop.time and previous.time:
            hop.delay = hop.time - previous.time
            if hop.delay < -SKEW:
                chain.problems.append(
                    f"hop {hop.index + 1} (by {hop.by or '?'}) is dated {-hop.delay} before the hop that handed it the message: clocks disagree or a header was forged"
                )
            elif hop.delay > SLOW_HOP:
                chain.problems.append(
                    f"hop {hop.index + 1} (by {hop.by or '?'}) took {hop.delay} to accept the message"
                )
        if hop.time:
            previous = hop
    times = [h.time for h in ordered if h.time]
    if len(times) >= 2:
        chain.total_delay = times[-1] - times[0]
    for hop in ordered:
        if hop.from_ip and hop.ip_kind in ("public", "documentation"):
            chain.origin = hop
            break
    # each server should have received from the one before it
    for older, newer in pairwise(ordered):
        names = {n for n in (newer.from_host, newer.from_rdns) if n}
        if (
            older.by
            and names
            and older.by.lower() not in {n.lower() for n in names}
            and not _same_org(older.by, names)
        ):
            chain.problems.append(
                f"hop {newer.index + 1} says it received the message from {sorted(names)[0]}, but the hop before it was by {older.by}"
            )
    return chain


def _same_org(host: str, names: set[str]) -> bool:
    from mailhdr import psl

    org = psl.organizational_domain(host)
    return org is not None and any(psl.organizational_domain(n) == org for n in names)
