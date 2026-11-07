"""SPF (RFC 7208): ``check_host`` with macros, the DNS-lookup limits and every mechanism.

Results are the RFC's seven words: none, neutral, pass, fail, softfail, temperror, permerror.
Limits that keep a hostile record from turning one message into a flood of queries:
at most 10 DNS-querying terms (include, a, mx, ptr, exists, redirect), at most 10 names per mx or
ptr, and at most 2 "void" lookups (a name that does not exist or has no data).
"""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass, field
from urllib.parse import quote

from mailhdr.dnsio import DnsError, Resolver

MAX_LOOKUPS = 10
MAX_VOID = 2
MAX_NAMES = 10
MAX_DEPTH = 12  # include/redirect nesting; the lookup limit stops it first, this is a seatbelt

QUALIFIER_RESULT = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}


class SpfError(Exception):
    def __init__(self, result: str, reason: str) -> None:
        super().__init__(reason)
        self.result = result
        self.reason = reason


@dataclass
class SpfResult:
    result: str
    reason: str = ""
    domain: str = ""
    matched: str = ""  # the term that decided the result, e.g. "-all" or "ip4:192.0.2.0/24"
    lookups: int = 0
    void_lookups: int = 0
    explanation: str = ""
    trace: list[str] = field(default_factory=list)
    record: str = ""


@dataclass
class _Ctx:
    resolver: Resolver
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    sender: str
    helo: str
    lookups: int = 0
    void: int = 0
    trace: list[str] = field(default_factory=list)
    now: int = 0

    def count_lookup(self, what: str) -> None:
        self.lookups += 1
        if self.lookups > MAX_LOOKUPS:
            raise SpfError("permerror", f"more than {MAX_LOOKUPS} DNS lookups (at {what})")

    def count_void(self, name: str) -> None:
        self.void += 1
        if self.void > MAX_VOID:
            raise SpfError(
                "permerror", f"more than {MAX_VOID} lookups that found nothing (at {name})"
            )


# ---------------------------------------------------------------- helpers

_LABEL = re.compile(r"^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")


def valid_domain(name: str) -> bool:
    name = name.rstrip(".")
    if not name or len(name) > 253 or "." not in name:
        return False
    return all(_LABEL.match(label) for label in name.split("."))


def _normalise_ip(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr


def _ip_for_macro(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if isinstance(ip, ipaddress.IPv4Address):
        return str(ip)
    return ".".join(ip.exploded.replace(":", ""))


def _split_sender(sender: str, helo: str) -> tuple[str, str]:
    if "@" not in sender:
        return "postmaster", sender or helo
    local, _, domain = sender.rpartition("@")
    return local or "postmaster", domain


_MACRO = re.compile(r"%\{([slodiphcrtv])(\d*)(r?)([.\-+,/_=]*)\}|%%|%_|%-|%", re.I)


def expand_macros(
    spec: str, domain: str, ctx: _Ctx, *, exp: bool = False, validated: str | None = None
) -> str:
    local, sender_domain = _split_sender(ctx.sender, ctx.helo)

    def value(letter: str) -> str:
        match letter.lower():
            case "s":
                return f"{local}@{sender_domain}"
            case "l":
                return local
            case "o":
                return sender_domain
            case "d":
                return domain
            case "i":
                return _ip_for_macro(ctx.ip)
            case "p":
                return validated if validated is not None else "unknown"
            case "v":
                return "in-addr" if isinstance(ctx.ip, ipaddress.IPv4Address) else "ip6"
            case "h":
                return ctx.helo or "unknown"
            case "c" if exp:
                return str(ctx.ip)
            case "r" if exp:
                return "unknown"
            case "t" if exp:
                return str(ctx.now)
        raise SpfError("permerror", f"macro %{{{letter}}} is not allowed here")

    def sub(m: re.Match[str]) -> str:
        token = m.group(0)
        if token == "%%":
            return "%"
        if token == "%_":
            return " "
        if token == "%-":
            return "%20"
        if token == "%":
            raise SpfError("permerror", "stray % in a domain-spec")
        letter, digits, reverse, delims = m.group(1), m.group(2), m.group(3), m.group(4)
        text = value(letter)
        parts = re.split("[" + re.escape(delims or ".") + "]", text)
        if reverse:
            parts.reverse()
        if digits:
            if int(digits) == 0:
                raise SpfError("permerror", "macro digit transformer of 0")
            parts = parts[-int(digits) :]
        out = ".".join(parts)
        return quote(out, safe="") if letter.isupper() else out

    return _MACRO.sub(sub, spec)


def _trim_domain(name: str) -> str:
    name = name.rstrip(".")
    while len(name) > 253 and "." in name:
        name = name.split(".", 1)[1]
    return name


# ---------------------------------------------------------------- evaluation


def _fetch_record(resolver: Resolver, domain: str) -> str | None:
    try:
        texts = resolver.txt(domain)
    except DnsError as exc:
        if exc.kind == "temp":
            raise SpfError("temperror", f"DNS failure fetching the SPF record of {domain}") from exc
        return None
    records = [t for t in texts if re.match(r"(?i)^v=spf1( |$)", t)]
    if len(records) > 1:
        raise SpfError("permerror", f"{domain} publishes {len(records)} SPF records")
    return records[0] if records else None


_DIRECTIVE = re.compile(r"^([+\-~?]?)([A-Za-z0-9]+)(.*)$", re.S)
_MODIFIER = re.compile(r"^([A-Za-z][A-Za-z0-9_.\-]*)=(.*)$", re.S)


def _split_cidr(arg: str) -> tuple[str, int | None, int | None]:
    """'domain/24//64' -> ('domain', 24, 64); either length may be missing."""
    v4 = v6 = None
    m = re.match(r"^(.*?)(?:/(\d+))?(?://(\d+))?$", arg)
    assert m is not None
    base, p4, p6 = m.group(1), m.group(2), m.group(3)
    if p4 is not None:
        v4 = int(p4)
        if not 0 <= v4 <= 32:
            raise SpfError("permerror", f"IPv4 prefix /{v4} out of range")
    if p6 is not None:
        v6 = int(p6)
        if not 0 <= v6 <= 128:
            raise SpfError("permerror", f"IPv6 prefix //{v6} out of range")
    return base, v4, v6


def _addresses(ctx: _Ctx, name: str) -> list[str]:
    """Addresses of ``name`` in the family of the client, counting 'void' answers."""
    try:
        return (
            ctx.resolver.a(name)
            if isinstance(ctx.ip, ipaddress.IPv4Address)
            else ctx.resolver.aaaa(name)
        )
    except DnsError as exc:
        if exc.kind == "temp":
            raise SpfError("temperror", f"DNS failure looking up {name}") from exc
        ctx.count_void(name)
        return []


def _in_network(ctx: _Ctx, address: str, v4: int | None, v6: int | None) -> bool:
    try:
        candidate = _normalise_ip(address)
    except ValueError:
        return False
    if type(candidate) is not type(ctx.ip):
        return False
    prefix = v4 if isinstance(ctx.ip, ipaddress.IPv4Address) else v6
    bits = 32 if isinstance(ctx.ip, ipaddress.IPv4Address) else 128
    net = ipaddress.ip_network(f"{candidate}/{bits if prefix is None else prefix}", strict=False)
    return ctx.ip in net


def _match_mechanism(ctx: _Ctx, name: str, arg: str, domain: str, depth: int) -> bool:
    if name == "all":
        if arg:
            raise SpfError("permerror", "'all' takes no argument")
        return True

    if name in ("ip4", "ip6"):
        if not arg.startswith(":"):
            raise SpfError("permerror", f"{name} needs an address")
        try:
            net = ipaddress.ip_network(arg[1:], strict=False)
        except ValueError as exc:
            raise SpfError("permerror", f"bad {name} network {arg[1:][:40]!r}") from exc
        if (name == "ip4") != (net.version == 4):
            raise SpfError("permerror", f"{name}:{arg[1:]} has the wrong address family")
        if isinstance(ctx.ip, ipaddress.IPv4Address) and net.version == 6:
            return False
        if isinstance(ctx.ip, ipaddress.IPv6Address) and net.version == 4:
            return False
        return ctx.ip in net

    if name == "include":
        if not arg.startswith(":") or len(arg) == 1:
            raise SpfError("permerror", "include needs a domain")
        ctx.count_lookup(f"include{arg}")
        target = _trim_domain(expand_macros(arg[1:], domain, ctx))
        sub = _check(ctx, target, depth + 1, via=f"include:{target}")
        if sub.result == "pass":
            return True
        if sub.result in ("fail", "softfail", "neutral"):
            return False
        if sub.result == "none":
            raise SpfError("permerror", f"include:{target} has no SPF record")
        raise SpfError(sub.result, sub.reason)

    if name == "exists":
        if not arg.startswith(":") or len(arg) == 1:
            raise SpfError("permerror", "exists needs a domain")
        ctx.count_lookup(f"exists{arg}")
        target = _trim_domain(expand_macros(arg[1:], domain, ctx))
        try:
            found = ctx.resolver.a(target)  # always the A record, whatever the client's family
        except DnsError as exc:
            if exc.kind == "temp":
                raise SpfError("temperror", f"DNS failure looking up {target}") from exc
            ctx.count_void(target)
            return False
        return bool(found)

    if name == "a":
        ctx.count_lookup("a")
        spec, v4, v6 = _split_cidr(arg[1:] if arg.startswith(":") else arg)
        target = _trim_domain(expand_macros(spec, domain, ctx)) if arg.startswith(":") else domain
        return any(_in_network(ctx, a, v4, v6) for a in _addresses(ctx, target))

    if name == "mx":
        ctx.count_lookup("mx")
        spec, v4, v6 = _split_cidr(arg[1:] if arg.startswith(":") else arg)
        target = _trim_domain(expand_macros(spec, domain, ctx)) if arg.startswith(":") else domain
        try:
            hosts = ctx.resolver.mx(target)
        except DnsError as exc:
            if exc.kind == "temp":
                raise SpfError("temperror", f"DNS failure looking up MX of {target}") from exc
            ctx.count_void(target)
            return False
        if len(hosts) > MAX_NAMES:
            raise SpfError("permerror", f"{target} has more than {MAX_NAMES} MX records")
        # Every MX host is resolved before matching, so the lookup and void-lookup counts (and so
        # the result) do not depend on which host happens to match first.
        addresses = [a for _, host in sorted(hosts) for a in _addresses(ctx, host)]
        return any(_in_network(ctx, a, v4, v6) for a in addresses)

    if name == "ptr":
        ctx.count_lookup("ptr")
        target = (
            _trim_domain(expand_macros(arg[1:], domain, ctx)) if arg.startswith(":") else domain
        )
        return _ptr_match(ctx, target.lower())

    raise SpfError("permerror", f"unknown mechanism {name!r}")


def _ptr_match(ctx: _Ctx, target: str) -> bool:
    try:
        names = ctx.resolver.ptr(str(ctx.ip))
    except DnsError as exc:
        if exc.kind == "temp":
            return False  # RFC 7208 5.5: a failed PTR lookup just means no match
        ctx.count_void(str(ctx.ip))
        return False
    for host in names[:MAX_NAMES]:
        try:
            forward = (
                ctx.resolver.a(host)
                if isinstance(ctx.ip, ipaddress.IPv4Address)
                else ctx.resolver.aaaa(host)
            )
        except DnsError:
            continue
        if any(_safe_ip(a) == ctx.ip for a in forward) and (
            host == target or host.endswith("." + target)
        ):
            return True
    return False


def _safe_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return _normalise_ip(text)
    except ValueError:
        return None


def _check(ctx: _Ctx, domain: str, depth: int, via: str = "") -> SpfResult:
    if depth > MAX_DEPTH:
        raise SpfError("permerror", "SPF records are nested too deeply")
    if not valid_domain(domain):
        return SpfResult("none", f"{domain!r} is not a valid domain", domain)
    record = _fetch_record(ctx.resolver, domain)
    if record is None:
        ctx.trace.append(f"{domain}: no SPF record")
        return SpfResult("none", f"no SPF record at {domain}", domain)
    ctx.trace.append(f"{domain}: {record}")

    redirect: str | None = None
    exp: str | None = None
    seen_modifiers: set[str] = set()
    terms = record.split()[1:]
    # syntax first: a record with an error anywhere is a permerror even if an earlier term matches
    parsed: list[tuple[str, str, str, str]] = []  # (qualifier, name, arg, text)
    for term in terms:
        mod = _MODIFIER.match(term)
        if (
            mod
            and term[0] not in "+-~?"
            and mod.group(1).lower()
            not in ("a", "mx", "ptr", "all", "ip4", "ip6", "include", "exists")
        ):
            key, val = mod.group(1).lower(), mod.group(2)
            if key in ("redirect", "exp"):
                if key in seen_modifiers:
                    raise SpfError("permerror", f"{key}= appears twice")
                seen_modifiers.add(key)
                if not val:
                    raise SpfError("permerror", f"{key}= needs a domain")
                if key == "redirect":
                    redirect = val
                else:
                    exp = val
            continue
        m = _DIRECTIVE.match(term)
        if not m:
            raise SpfError("permerror", f"cannot read term {term[:30]!r}")
        qual, name, arg = m.group(1) or "+", m.group(2).lower(), m.group(3)
        if name not in ("all", "ip4", "ip6", "include", "a", "mx", "ptr", "exists"):
            raise SpfError("permerror", f"unknown mechanism {name!r}")
        parsed.append((qual, name, arg, term))

    for qual, name, arg, text in parsed:
        if _match_mechanism(ctx, name, arg, domain, depth):
            result = QUALIFIER_RESULT[qual]
            ctx.trace.append(f"  {text} matched -> {result}")
            res = SpfResult(result, f"matched {text}", domain, text, record=record)
            if result == "fail" and exp and depth == 0:
                res.explanation = _explanation(ctx, exp, domain)
            return res
    if redirect is not None and not any(n == "all" for _, n, _, _ in parsed):
        ctx.count_lookup(f"redirect={redirect}")
        target = _trim_domain(expand_macros(redirect, domain, ctx))
        ctx.trace.append(f"  redirect={target}")
        sub = _check(ctx, target, depth + 1, via=f"redirect={target}")
        if sub.result == "none":
            raise SpfError("permerror", f"redirect={target} has no SPF record")
        return sub
    ctx.trace.append("  nothing matched -> neutral")
    return SpfResult("neutral", "no mechanism matched", domain, record=record)


def _explanation(ctx: _Ctx, spec: str, domain: str) -> str:
    try:
        name = _trim_domain(expand_macros(spec, domain, ctx))
        texts = ctx.resolver.txt(name)
        if len(texts) != 1:
            return ""
        return expand_macros(texts[0], domain, ctx, exp=True)[:200]
    except (DnsError, SpfError):
        return ""


def check_host(
    resolver: Resolver, ip: str, sender: str, helo: str = "", now: int | None = None
) -> SpfResult:
    """Evaluate SPF for a client ``ip`` sending as ``sender`` (the MAIL FROM, or ``postmaster@helo``)."""
    try:
        addr = _normalise_ip(ip)
    except ValueError:
        return SpfResult("permerror", f"{ip!r} is not an IP address")
    _, domain = _split_sender(sender, helo)
    ctx = _Ctx(resolver, addr, sender, helo, now=int(time.time()) if now is None else now)
    try:
        res = _check(ctx, domain.rstrip(".").lower(), 0)
    except SpfError as exc:
        res = SpfResult(exc.result, exc.reason, domain)
    res.lookups, res.void_lookups, res.trace = ctx.lookups, ctx.void, ctx.trace
    return res
