"""Turn an Analysis into text, JSON or a self-contained HTML page.

Everything in a message is attacker-controlled text, so the HTML writer escapes every value, loads
nothing from outside, and carries a Content-Security-Policy that forbids scripts.
"""

from __future__ import annotations

import dataclasses
import html
import json
from datetime import datetime, timedelta
from typing import Any

from mailhdr import __version__, psl
from mailhdr.analyze import Analysis

RISK_WORDS = {
    "low": "LOW: nothing suspicious found",
    "medium": "MEDIUM: some signs worth a closer look",
    "high": "HIGH: likely spoofed or forged",
}


def _clean(text: str, limit: int = 300) -> str:
    """Strip control characters (terminal escape sequences from a hostile header) and trim."""
    out = "".join(ch if ch >= " " and ch != "\x7f" else " " for ch in text)
    return out if len(out) <= limit else out[: limit - 1] + "…"


LABELS = {"message_id": "Message-ID", "return_path": "Return-Path", "reply_to": "Reply-To"}


def _label(key: str) -> str:
    return LABELS.get(key, key.title())


def _hms(delta: timedelta | None) -> str:
    if delta is None:
        return "?"
    seconds = int(delta.total_seconds())
    sign = "-" if seconds < 0 else ""
    seconds = abs(seconds)
    return f"{sign}{seconds // 3600}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"


def to_dict(a: Analysis) -> dict[str, Any]:
    def convert(value: Any) -> Any:
        if dataclasses.is_dataclass(value) and not isinstance(value, type):
            return {f.name: convert(getattr(value, f.name)) for f in dataclasses.fields(value)}
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, timedelta):
            return value.total_seconds()
        if isinstance(value, list):
            return [convert(v) for v in value]
        if isinstance(value, dict):
            return {k: convert(v) for k, v in value.items()}
        return value

    data = convert(a)
    data["tool"] = {
        "name": "mailhdr",
        "version": __version__,
        "public_suffix_list": psl.list_version(),
    }
    return data  # type: ignore[no-any-return]


def to_json(a: Analysis) -> str:
    return json.dumps(to_dict(a), indent=2, ensure_ascii=False)


# ---------------------------------------------------------------- text


def _auth_lines(a: Analysis) -> list[str]:
    if a.offline:
        return ["  (not re-checked: offline mode)"]
    lines = []
    if not a.dkim:
        lines.append("  DKIM   none      the message carries no signature")
    for d in a.dkim:
        extra = f"{d.algorithm}, {d.key_bits}-bit key, {d.canon}" if d.algorithm else ""
        lines.append(
            f"  DKIM   {d.result:<9} d={_clean(d.domain) or '?'} s={_clean(d.selector) or '?'}  {d.reason}"
            + (f"  [{extra}]" if extra and d.passed else "")
        )
        lines += [f"           note: {w}" for w in d.warnings]
    if a.spf:
        lines.append(
            f"  SPF    {a.spf.result:<9} {_clean(a.spf.reason)}  [{a.spf.lookups} DNS lookups]"
        )
        i = a.spf_inputs
        lines.append(
            f"           checked: ip {i['ip'] or '?'}, sender {i['mailfrom'] or '(none)'}, helo {i['helo'] or '(none)'}"
        )
        if i["ip_source"]:
            lines.append(f"           the IP was {i['ip_source']}")
        if a.spf.explanation:
            lines.append(f"           the domain says: {_clean(a.spf.explanation)}")
    else:
        lines.append("  SPF    not checked (no connecting IP or no sender address)")
    dm = a.dmarc
    if dm:
        lines.append(f"  DMARC  {dm.result:<9} {_clean(dm.reason)}")
        if dm.policy:
            lines.append(
                f"           policy found at _dmarc.{dm.found_at}: p={dm.policy.p}"
                + (f" sp={dm.policy.sp}" if dm.policy.sp else "")
                + f" adkim={dm.policy.adkim} aspf={dm.policy.aspf} pct={dm.policy.pct}"
            )
        if dm.disposition:
            lines.append(f"           the domain asks receivers to: {dm.disposition}")
    for ar in a.claims:
        said = ", ".join(f"{c.method}={c.result}" for c in ar.claims) or "nothing"
        lines.append(
            f"  claimed by {_clean(ar.server) or '?'}: {said}   (what the message says about itself, not verified)"
        )
    return lines


def to_text(a: Analysis) -> str:
    s = a.summary
    out = [f"mailhdr {__version__}", "", "MESSAGE"]
    for key in ("from", "to", "subject", "date", "message_id", "return_path", "reply_to"):
        if s.get(key):
            out.append(f"  {_label(key):<12} {_clean(s[key])}")
    out += ["", f"VERDICT  {RISK_WORDS[a.risk]}", ""]

    out.append("DELIVERY PATH (oldest first)")
    if not a.chain.hops:
        out.append("  no Received headers")
    for n, hop in enumerate(a.chain.chronological, 1):
        who = _clean(hop.from_host or hop.from_rdns or "?")
        ip = f" [{hop.from_ip}, {hop.ip_kind}]" if hop.from_ip else ""
        when = hop.time.strftime("%Y-%m-%d %H:%M:%S %z") if hop.time else "no date"
        delay = f"  +{_hms(hop.delay)}" if hop.delay is not None else ""
        out.append(f"  {n}. {who}{ip} -> {_clean(hop.by or '?')}  {hop.protocol}  {when}{delay}")
    if a.chain.origin:
        out.append(
            f"  origin: {a.chain.origin.from_ip} ({a.chain.origin.ip_kind}), the earliest hop with a non-private address"
        )
    if a.chain.total_delay is not None:
        out.append(f"  total time in transit: {_hms(a.chain.total_delay)}")

    out += ["", "AUTHENTICATION (re-checked by mailhdr)", *_auth_lines(a)]
    out += ["", f"FINDINGS ({len(a.findings)})"]
    if not a.findings:
        out.append("  none")
    for f in a.findings:
        out.append(f"  [{f.severity.upper():<6}] {_clean(f.title)}")
        if f.detail:
            out.append(f"           {_clean(f.detail)}")
    for p in a.problems:
        out.append(f"  parser: {_clean(p)}")
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------- html

_CSS = """
:root{--bg:#fff;--fg:#1c2230;--mut:#5b6577;--line:#d9dee7;--card:#f6f8fb;--low:#1a7f4b;--medium:#a15c00;--high:#b3261e;--info:#35507a}
@media (prefers-color-scheme:dark){:root{--bg:#10141c;--fg:#e6eaf2;--mut:#9aa5b8;--line:#2b3445;--card:#171d29;--low:#4cc38a;--medium:#f0b04a;--high:#ff7b72;--info:#8fb0e8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:920px;margin:0 auto;padding:24px 16px 48px}h1{font-size:1.3rem;margin:0 0 4px}h2{font-size:1rem;margin:28px 0 8px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut)}
.verdict{border:1px solid var(--line);border-left:6px solid var(--c);border-radius:8px;background:var(--card);padding:12px 16px;margin:16px 0}
.verdict b{color:var(--c);font-size:1.1rem}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{color:var(--mut);font-weight:600;font-size:.85rem}.k{color:var(--mut);white-space:nowrap;width:1%}code{font:13px ui-monospace,monospace}
.tag{display:inline-block;min-width:4.5em;text-align:center;border-radius:4px;padding:0 6px;font-size:.8rem;font-weight:700;color:#fff;background:var(--c)}
.pass{--c:var(--low)}.fail,.high{--c:var(--high)}.medium,.softfail,.policy{--c:var(--medium)}.low{--c:var(--info)}.none,.neutral,.info,.temperror,.permerror{--c:#6b7589}
.pass.tag{background:var(--low)}.detail{color:var(--mut);font-size:.9rem}.scroll{overflow-x:auto}
"""


def to_html(a: Analysis) -> str:
    e = html.escape

    def tag(word: str) -> str:
        return f'<span class="tag {e(word)}">{e(word)}</span>'

    s = a.summary
    rows = "".join(
        f'<tr><td class="k">{e(_label(k))}</td><td>{e(_clean(v))}</td></tr>'
        for k, v in s.items()
        if v
    )
    hops = ""
    for n, hop in enumerate(a.chain.chronological, 1):
        hops += (
            f"<tr><td>{n}</td><td>{e(_clean(hop.from_host or hop.from_rdns or '?'))}</td>"
            f"<td><code>{e(hop.from_ip)}</code> {e(hop.ip_kind)}</td><td>{e(_clean(hop.by or '?'))}</td>"
            f"<td>{e(hop.protocol)}</td><td>{e(hop.time.strftime('%H:%M:%S') if hop.time else '-')}</td>"
            f"<td>{e('+' + _hms(hop.delay) if hop.delay is not None else '')}</td></tr>"
        )
    auth = ""
    if a.offline:
        auth = '<tr><td colspan="3">Not re-checked: offline mode.</td></tr>'
    else:
        for d in a.dkim:
            auth += f"<tr><td>DKIM</td><td>{tag(d.result)}</td><td>{e(_clean(d.domain))} / {e(_clean(d.selector))}: {e(d.reason)}</td></tr>"
        if not a.dkim:
            auth += f"<tr><td>DKIM</td><td>{tag('none')}</td><td>No signature.</td></tr>"
        if a.spf:
            auth += f"<tr><td>SPF</td><td>{tag(a.spf.result)}</td><td>{e(_clean(a.spf.reason))} <span class='detail'>(ip {e(a.spf_inputs['ip'])}, sender {e(a.spf_inputs['mailfrom'] or 'none')})</span></td></tr>"
        if a.dmarc:
            extra = f" Policy asks for: {e(a.dmarc.disposition)}." if a.dmarc.disposition else ""
            auth += f"<tr><td>DMARC</td><td>{tag(a.dmarc.result)}</td><td>{e(_clean(a.dmarc.reason))}.{extra}</td></tr>"
        for ar in a.claims:
            said = ", ".join(f"{c.method}={c.result}" for c in ar.claims)
            auth += f"<tr><td>Claimed</td><td>{tag('info')}</td><td>{e(_clean(ar.server))} says: {e(_clean(said))} <span class='detail'>(not verified)</span></td></tr>"
    finds = (
        "".join(
            f"<tr><td>{tag(f.severity)}</td><td>{e(_clean(f.title))}<div class='detail'>{e(_clean(f.detail))}</div></td></tr>"
            for f in a.findings
        )
        or '<tr><td colspan="2">Nothing found.</td></tr>'
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>mailhdr report</title>
<style>{_CSS}</style></head><body><main>
<h1>Email header analysis</h1><div class="detail">mailhdr {e(__version__)}</div>
<div class="verdict {e(a.risk)}"><b>{e(RISK_WORDS[a.risk])}</b></div>
<h2>Message</h2><table>{rows}</table>
<h2>Delivery path, oldest first</h2><div class="scroll"><table><tr><th>#</th><th>From</th><th>Address</th><th>By</th><th>With</th><th>Time</th><th>Delay</th></tr>{hops or '<tr><td colspan="7">No Received headers.</td></tr>'}</table></div>
<h2>Authentication, re-checked</h2><table>{auth}</table>
<h2>Findings</h2><table>{finds}</table>
</main></body></html>
"""
