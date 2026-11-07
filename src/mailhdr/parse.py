"""Split a message into headers and body without losing the original bytes.

DKIM signs exact bytes, so a header keeps its raw form (folding and all). Line endings are
normalised to CRLF on the way in, which is what a message looked like on the wire; a ``.eml`` saved
with bare LF therefore verifies the same way as the original.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.header import decode_header, make_header

MAX_MESSAGE = 32 * 1024 * 1024
MAX_HEADERS = 2000
MAX_HEADER_BYTES = 256 * 1024

_NAME = re.compile(rb"^[\x21-\x39\x3b-\x7e]+$")  # printable ASCII except ':'


class ParseError(ValueError):
    """The input is not something we can read as a message."""


@dataclass(frozen=True)
class Header:
    name: str  # as written, case kept
    raw: bytes  # the whole field as in the message, folding kept, ending with CRLF
    index: int  # position from the top, 0-based

    @property
    def raw_value(self) -> bytes:
        """Everything after the first colon, folding kept, without the final CRLF."""
        return self.raw.split(b":", 1)[1].removesuffix(b"\r\n")

    @property
    def value(self) -> str:
        """Unfolded, whitespace-trimmed text (no RFC 2047 decoding)."""
        text = self.raw_value.decode("utf-8", errors="replace")
        return re.sub(r"\r\n[ \t]*", " ", text).strip()

    @property
    def decoded(self) -> str:
        """``value`` with RFC 2047 encoded words decoded, for showing to people."""
        try:
            return str(make_header(decode_header(self.value)))
        except Exception:  # malformed encoded words are common in spam; show them as they are
            return self.value

    @property
    def lname(self) -> str:
        return self.name.lower()


@dataclass
class Message:
    headers: list[Header] = field(default_factory=list)
    body: bytes = b""
    from_line: str | None = None  # a leading mbox "From " line, kept apart
    problems: list[str] = field(default_factory=list)

    def all(self, name: str) -> list[Header]:
        """Every header called ``name``, top to bottom."""
        lname = name.lower()
        return [h for h in self.headers if h.lname == lname]

    def first(self, name: str) -> Header | None:
        found = self.all(name)
        return found[0] if found else None

    def values(self, name: str) -> list[str]:
        return [h.value for h in self.all(name)]


def _normalise_newlines(data: bytes) -> bytes:
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return data.replace(b"\n", b"\r\n")


def parse_message(data: bytes) -> Message:
    if len(data) > MAX_MESSAGE:
        raise ParseError(f"message is larger than {MAX_MESSAGE} bytes")
    if not data.strip():
        raise ParseError("empty input")
    data = _normalise_newlines(data)
    msg = Message()

    if data.startswith(b"From ") and not data.startswith(b"From:"):
        first, _, data = data.partition(b"\r\n")
        msg.from_line = first.decode("ascii", errors="replace")

    if data.startswith(b"\r\n"):  # a blank first line: there are no headers, only a body
        head, body = b"", data[2:]
    else:
        head, sep, body = data.partition(b"\r\n\r\n")
        if not sep:
            # no blank line: either headers only, or not a message at all
            head, body = data.removesuffix(b"\r\n"), b""
            msg.problems.append("no blank line between headers and body")
    if len(head) > MAX_HEADER_BYTES:
        raise ParseError("header section is unreasonably large")
    msg.body = body

    fields: list[bytearray] = []
    for line in head.split(b"\r\n") if head else []:
        if line[:1] in (b" ", b"\t"):
            if not fields:
                msg.problems.append("message starts with a continuation line")
                continue
            fields[-1] += line + b"\r\n"
        else:
            fields.append(bytearray(line + b"\r\n"))
    if len(fields) > MAX_HEADERS:
        raise ParseError(f"more than {MAX_HEADERS} header fields")

    for raw in fields:
        name, colon, _ = bytes(raw).partition(b":")
        if not colon or not _NAME.match(name):
            msg.problems.append(f"line is not a header field: {bytes(raw)[:40]!r}")
            continue
        msg.headers.append(Header(name.decode("ascii"), bytes(raw), len(msg.headers)))
    if not msg.headers:
        raise ParseError("no header fields found: is this an email?")
    return msg
