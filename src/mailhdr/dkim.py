"""DKIM (RFC 6376, 8301, 8463) verification written out in full.

Nothing here relies on a crypto library: RSA signatures are checked with Python integers and an
exact comparison of the whole PKCS#1 v1.5 block, Ed25519 uses ``mailhdr.ed25519``. Results use the
RFC 8601 words: pass, fail, policy, neutral, temperror, permerror.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import time
from dataclasses import dataclass, field

from mailhdr import ed25519
from mailhdr.der import (
    BIT_STRING,
    INTEGER,
    NULL,
    OID,
    SEQUENCE,
    DerError,
    decode_integer,
    decode_oid,
)
from mailhdr.der import children as der_children
from mailhdr.der import expect as der_expect
from mailhdr.der import parse as der_parse
from mailhdr.dnsio import DnsError, Resolver
from mailhdr.parse import Header, Message

MAX_SIGNATURES = 10
MAX_RSA_BITS = 16384
MIN_RSA_BITS = 1024  # RFC 8301: below this a verifier must not accept the signature
WEAK_RSA_BITS = 2048  # RFC 8301: signers should use 2048+, verifiers must accept 1024..2047
CLOCK_SLACK = 300

_RSA_OID = "1.2.840.113549.1.1.1"
# DigestInfo prefixes from RFC 8017 section 9.2 (DER of AlgorithmIdentifier plus the OCTET STRING header)
_DIGEST_INFO = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
}
ALGORITHMS = {
    "rsa-sha256": ("rsa", "sha256"),
    "rsa-sha1": ("rsa", "sha1"),
    "ed25519-sha256": ("ed25519", "sha256"),
}


class DkimError(Exception):
    """A problem that ends verification of one signature, carrying the RFC 8601 result word."""

    def __init__(self, result: str, reason: str) -> None:
        super().__init__(reason)
        self.result = result
        self.reason = reason


@dataclass
class DkimResult:
    result: str
    reason: str = ""
    domain: str = ""
    selector: str = ""
    identity: str = ""
    algorithm: str = ""
    key_bits: int = 0
    header_index: int = -1
    canon: str = ""
    body_length_limit: int | None = None
    signed_headers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.result == "pass"


# ---------------------------------------------------------------- tags

_WSP = b" \t\r\n"


def parse_tags(text: str) -> dict[str, str]:
    """Parse ``a=b; c=d`` (RFC 6376 3.2). A tag that appears twice makes the record invalid."""
    tags: dict[str, str] = {}
    for part in text.split(";"):
        if not part.strip():
            continue
        name, eq, value = part.partition("=")
        if not eq:
            raise DkimError("permerror", f"tag without a value: {part.strip()[:30]!r}")
        name = name.strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", name):
            raise DkimError("permerror", f"bad tag name: {name[:30]!r}")
        if name in tags:
            raise DkimError("permerror", f"tag {name}= appears twice")
        tags[name] = value.strip()
    return tags


def _b64(value: str, what: str) -> bytes:
    clean = re.sub(r"\s+", "", value)
    try:
        return base64.b64decode(clean, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DkimError("permerror", f"{what} is not valid base64") from exc


# ---------------------------------------------------------------- canonicalization

_WSP_RUN = re.compile(rb"[ \t]+")


def canon_body(body: bytes, mode: str) -> bytes:
    if mode == "simple":
        out = body
        while out.endswith(b"\r\n\r\n"):
            out = out[:-2]
        if not out:
            return b"\r\n"
        return out if out.endswith(b"\r\n") else out + b"\r\n"
    lines = body.split(b"\r\n")
    lines = [_WSP_RUN.sub(b" ", line).rstrip(b" ") for line in lines]
    while lines and lines[-1] == b"":
        lines.pop()
    return b"".join(line + b"\r\n" for line in lines)


def canon_header(raw: bytes, mode: str) -> bytes:
    """``raw`` is one header field, folding kept, ending in CRLF; the result also ends in CRLF."""
    if mode == "simple":
        return raw
    name, _, value = raw.partition(b":")
    value = re.sub(rb"\r\n(?=[ \t])", b"", value)
    value = _WSP_RUN.sub(b" ", value.replace(b"\r\n", b"")).strip(b" ")
    return name.strip(b" \t").lower() + b":" + value + b"\r\n"


def _blank_b(raw: bytes) -> bytes:
    """The signature header with the value of ``b=`` removed (RFC 6376 3.7)."""
    colon = raw.index(b":")
    head, rest = raw[: colon + 1], raw[colon + 1 :]
    new, count = re.subn(rb"(^|;)([ \t\r\n]*b[ \t\r\n]*=)[^;]*", rb"\1\2", rest, count=1)
    if count != 1:
        raise DkimError("permerror", "signature has no b= tag")
    return head + new


def select_headers(msg: Message, names: list[str], skip: int) -> list[Header]:
    """Pick headers the way a verifier must: each name takes the lowest unused instance, from the
    bottom up (RFC 6376 5.4.2). A name listed more times than the message has copies selects
    nothing for the extra entries, which is how a signer protects against added headers."""
    used: set[int] = {skip}
    chosen: list[Header] = []
    for name in names:
        lname = name.strip().lower()
        for header in reversed(msg.headers):
            if header.lname == lname and header.index not in used:
                used.add(header.index)
                chosen.append(header)
                break
    return chosen


# ---------------------------------------------------------------- keys


@dataclass
class KeyRecord:
    key_type: str  # rsa | ed25519
    public: bytes  # DER SPKI/RSAPublicKey for rsa, 32 raw bytes for ed25519
    testing: bool = False
    strict_identity: bool = False
    hashes: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    revoked: bool = False
    notes: str = ""


def parse_key_record(text: str) -> KeyRecord:
    tags = parse_tags(text)
    if "v" in tags and tags["v"] != "DKIM1":
        raise DkimError("permerror", f"unsupported key version {tags['v'][:10]!r}")
    if "p" not in tags:
        raise DkimError("permerror", "key record has no p= tag")
    flags = [f.strip() for f in tags.get("t", "").split(":")]
    key_type = tags.get("k", "rsa").lower()
    rec = KeyRecord(
        key_type=key_type,
        public=b"",
        testing="y" in flags,
        strict_identity="s" in flags,
        hashes=[h.strip().lower() for h in tags.get("h", "").split(":") if h.strip()],
        services=[s.strip().lower() for s in tags.get("s", "*").split(":") if s.strip()],
        notes=tags.get("n", ""),
    )
    if not re.sub(r"\s+", "", tags["p"]):
        rec.revoked = True
        return rec
    rec.public = _b64(tags["p"], "p=")
    return rec


def rsa_public_numbers(der: bytes) -> tuple[int, int]:
    """(n, e) from a SubjectPublicKeyInfo, or from a bare RSAPublicKey (seen in the wild)."""
    try:
        top = der_parse(der)
        der_expect(top, SEQUENCE, "public key")
        parts = der_children(top.value)
        if len(parts) == 2 and parts[0].tag == INTEGER:  # bare RSAPublicKey
            n = decode_integer(parts[0].value)
            e = decode_integer(der_expect(parts[1], INTEGER, "exponent").value)
            if n <= 0 or e <= 0:
                raise DerError("modulus and exponent must be positive")
            return n, e
        if len(parts) != 2:
            raise DerError("unexpected SubjectPublicKeyInfo layout")
        alg = der_children(der_expect(parts[0], SEQUENCE, "algorithm").value)
        der_expect(alg[0], OID, "algorithm oid")
        if decode_oid(alg[0].value) != _RSA_OID:
            raise DkimError("permerror", "p= holds a key that is not RSA")
        if len(alg) > 1:
            der_expect(alg[1], NULL, "algorithm parameters")
        bits = der_expect(parts[1], BIT_STRING, "key bits").value
        if not bits or bits[0] != 0:
            raise DerError("bit string with unused bits")
        inner = der_expect(der_parse(bits[1:]), SEQUENCE, "RSAPublicKey")
        nums = der_children(inner.value)
        if len(nums) != 2:
            raise DerError("RSAPublicKey needs two integers")
        n = decode_integer(der_expect(nums[0], INTEGER, "modulus").value)
        e = decode_integer(der_expect(nums[1], INTEGER, "exponent").value)
        if n <= 0 or e <= 0:
            raise DerError("modulus and exponent must be positive")
        return n, e
    except (DerError, IndexError) as exc:
        raise DkimError("permerror", f"unreadable RSA key: {exc}") from exc


def rsa_verify(n: int, e: int, digest: bytes, hash_name: str, signature: bytes) -> bool:
    """RSASSA-PKCS1-v1_5 verification. The whole encoded block is rebuilt and compared byte for
    byte, so there is no padding parser that could be fooled (the Bleichenbacher 2006 problem)."""
    k = (n.bit_length() + 7) // 8
    if len(signature) != k or e < 3 or e % 2 == 0 or e >= n:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    block = pow(s, e, n).to_bytes(k, "big")
    tail = _DIGEST_INFO[hash_name] + digest
    if k < len(tail) + 11:
        return False
    expected = b"\x00\x01" + b"\xff" * (k - len(tail) - 3) + b"\x00" + tail
    return block == expected


# ---------------------------------------------------------------- verification

_HASHES = {"sha256": hashlib.sha256, "sha1": hashlib.sha1}


def _domain_of(identity: str) -> str:
    return identity.rpartition("@")[2].lower()


def _verify_one(
    msg: Message, header: Header, resolver: Resolver, now: int, result: DkimResult
) -> None:
    tags = parse_tags(header.value)
    for required in ("v", "a", "b", "bh", "d", "h", "s"):
        if required not in tags:
            raise DkimError("permerror", f"missing required tag {required}=")
    if tags["v"] != "1":
        raise DkimError("permerror", f"unsupported version v={tags['v'][:10]}")
    algo = tags["a"].lower()
    if algo not in ALGORITHMS:
        raise DkimError("permerror", f"unknown algorithm a={tags['a'][:30]}")
    key_type, hash_name = ALGORITHMS[algo]
    result.algorithm = algo
    domain = tags["d"].lower().rstrip(".")
    selector = tags["s"]
    result.domain, result.selector = domain, selector
    result.identity = tags.get("i", f"@{domain}")
    signed = [h.strip() for h in tags["h"].split(":") if h.strip()]
    result.signed_headers = signed
    if "from" not in (h.lower() for h in signed):
        raise DkimError("permerror", "h= does not cover the From header")
    ident_domain = _domain_of(result.identity)
    if ident_domain != domain and not ident_domain.endswith("." + domain):
        raise DkimError("permerror", f"i= ({result.identity}) is not inside d= ({domain})")
    if "q" in tags and "dns/txt" not in tags["q"].lower().split(":"):
        raise DkimError("permerror", f"query method q={tags['q'][:20]} not supported")

    canon = tags.get("c", "simple/simple").lower()
    head_mode, _, body_mode = canon.partition("/")
    body_mode = body_mode or "simple"
    if head_mode not in ("simple", "relaxed") or body_mode not in ("simple", "relaxed"):
        raise DkimError("permerror", f"unknown canonicalization c={canon[:30]}")
    result.canon = f"{head_mode}/{body_mode}"

    for tag in ("t", "x", "l"):
        if tag in tags and not tags[tag].isdigit():
            raise DkimError("permerror", f"{tag}= is not a number")
    if "x" in tags and int(tags["x"]) < now - CLOCK_SLACK:
        raise DkimError("fail", "signature expired (x=)")
    if "t" in tags and int(tags["t"]) > now + CLOCK_SLACK:
        result.warnings.append("signature timestamp is in the future")
    if "x" in tags and "t" in tags and int(tags["x"]) < int(tags["t"]):
        raise DkimError("permerror", "x= is earlier than t=")

    sig = _b64(tags["b"], "b=")
    body_hash = _b64(tags["bh"], "bh=")

    # --- policy before any cryptography
    if algo == "rsa-sha1":
        raise DkimError("policy", "rsa-sha1 is not accepted (RFC 8301)")

    # --- the key
    qname = f"{selector}._domainkey.{domain}"
    try:
        records = [r for r in resolver.txt(qname) if re.search(r"(^|;)\s*p\s*=", r)]
    except DnsError as exc:
        if exc.kind == "temp":
            raise DkimError("temperror", f"DNS failure looking up {qname}") from exc
        raise DkimError("permerror", f"no key record at {qname}") from exc
    if not records:
        raise DkimError("permerror", f"no key record at {qname}")
    if len(records) > 1:
        raise DkimError("permerror", f"{len(records)} key records at {qname}; which one is meant?")
    key = parse_key_record(records[0])
    if key.revoked:
        raise DkimError("fail", "key has been revoked (empty p=)")
    if key.key_type != key_type:
        raise DkimError("permerror", f"key is {key.key_type} but the signature says {algo}")
    if key.hashes and hash_name not in key.hashes:
        raise DkimError("permerror", f"key does not allow {hash_name} (h=)")
    if "*" not in key.services and "email" not in key.services:
        raise DkimError("permerror", "key is not for email (s=)")
    if key.strict_identity and ident_domain != domain:
        raise DkimError("permerror", "key demands i= to match d= exactly (t=s)")
    if key.testing:
        result.warnings.append(
            "key is marked as a test (t=y); receivers are told to ignore failures"
        )

    # --- the body
    canon_b = canon_body(msg.body, body_mode)
    if "l" in tags:
        limit = int(tags["l"])
        result.body_length_limit = limit
        if limit > len(canon_b):
            raise DkimError("fail", "l= is longer than the body")
        if limit < len(canon_b):
            result.warnings.append(
                f"l={limit} signs only part of the body: {len(canon_b) - limit} bytes can be appended unnoticed"
            )
        canon_b = canon_b[:limit]
    if _HASHES[hash_name](canon_b).digest() != body_hash:
        raise DkimError("fail", "body hash did not verify")

    # --- the headers
    chosen = select_headers(msg, signed, header.index)
    data = b"".join(canon_header(h.raw, head_mode) for h in chosen)
    data += canon_header(_blank_b(header.raw), head_mode).removesuffix(b"\r\n")
    digest = _HASHES[hash_name](data).digest()

    if key_type == "rsa":
        n, e = rsa_public_numbers(key.public)
        bits = n.bit_length()
        result.key_bits = bits
        if bits > MAX_RSA_BITS:
            raise DkimError(
                "permerror", f"RSA key of {bits} bits is beyond the {MAX_RSA_BITS} limit"
            )
        if bits < MIN_RSA_BITS:
            raise DkimError(
                "policy", f"RSA key of {bits} bits is too short (RFC 8301 minimum is 1024)"
            )
        if bits < WEAK_RSA_BITS:
            result.warnings.append(f"RSA key of {bits} bits is weak; 2048 or more is recommended")
        ok = rsa_verify(n, e, digest, hash_name, sig)
    else:
        if len(key.public) != 32:
            raise DkimError("permerror", "Ed25519 key is not 32 bytes")
        result.key_bits = 256
        ok = ed25519.verify(key.public, digest, sig)
    if not ok:
        raise DkimError("fail", "signature did not verify")


def verify_signature(
    msg: Message, header: Header, resolver: Resolver, now: int | None = None
) -> DkimResult:
    result = DkimResult("permerror", header_index=header.index)
    try:
        _verify_one(msg, header, resolver, int(time.time()) if now is None else now, result)
        result.result, result.reason = "pass", "signature verified"
    except DkimError as exc:
        result.result, result.reason = exc.result, exc.reason
    return result


def verify_all(msg: Message, resolver: Resolver, now: int | None = None) -> list[DkimResult]:
    """One result per DKIM-Signature header, top to bottom (at most ``MAX_SIGNATURES``)."""
    headers = msg.all("DKIM-Signature")
    results = [verify_signature(msg, h, resolver, now) for h in headers[:MAX_SIGNATURES]]
    for _ in headers[MAX_SIGNATURES:]:
        results.append(DkimResult("neutral", f"more than {MAX_SIGNATURES} signatures; not checked"))
        break
    return results
