"""Read Authentication-Results headers (RFC 8601): what the receiving server says it checked.

These are claims written by a server. They are only worth believing when they come from your own
server, and a sender can put a fake one in a message, so mailhdr shows them next to its own
re-computation instead of trusting them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_RESULT = re.compile(r"^([A-Za-z0-9_-]+)\s*=\s*([A-Za-z0-9_-]+)(.*)$", re.S)
_PROP = re.compile(r"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\s*=\s*(\"[^\"]*\"|[^\s;]+)")
_COMMENT = re.compile(r"\([^()]*\)")


@dataclass
class AuthClaim:
    method: str
    result: str
    props: dict[str, str] = field(default_factory=dict)
    comment: str = ""


@dataclass
class AuthResults:
    server: str
    claims: list[AuthClaim]
    index: int = 0

    def result(self, method: str) -> str | None:
        for claim in self.claims:
            if claim.method == method:
                return claim.result
        return None


def parse_auth_results(value: str, index: int = 0) -> AuthResults:
    pieces = [p.strip() for p in value.split(";")]
    server = _COMMENT.sub("", pieces[0]).split()[0].lower() if pieces and pieces[0] else ""
    claims: list[AuthClaim] = []
    for piece in pieces[1:]:
        if not piece or piece.lower() == "none":
            continue
        comments = " ".join(m.strip("()") for m in _COMMENT.findall(piece))
        plain = _COMMENT.sub(" ", piece).strip()
        m = _RESULT.match(plain)
        if not m:
            continue
        props = {k.lower(): v.strip('"') for k, v in _PROP.findall(m.group(3))}
        claims.append(AuthClaim(m.group(1).lower(), m.group(2).lower(), props, comments))
    return AuthResults(server, claims, index)
