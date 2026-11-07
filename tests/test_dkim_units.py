"""DKIM edge cases: every way a signature or key record can be wrong has a named result."""

from __future__ import annotations

import base64
import contextlib
import re

import dkim as dkimpy
import pytest

from mailhdr.dkim import (
    DkimError,
    canon_body,
    canon_header,
    parse_key_record,
    parse_tags,
    rsa_public_numbers,
    rsa_verify,
    verify_all,
)
from mailhdr.dnsio import StaticResolver
from mailhdr.parse import parse_message
from tests.conftest import RAW_MESSAGE, pem, rsa_key, spki_b64

NOW = 1_794_000_000
KEYNAME = "sel._domainkey.example.com"


def signed(key, **kw):  # type: ignore[no-untyped-def]
    sig = dkimpy.DKIM(RAW_MESSAGE).sign(
        b"sel",
        b"example.com",
        pem(key),
        canonicalize=(b"relaxed", b"relaxed"),
        include_headers=[b"From", b"To", b"Subject"],
        **kw,
    )
    return sig + RAW_MESSAGE


def run(message: bytes, txt: list[str] | str | None, now: int = NOW):  # type: ignore[no-untyped-def]
    zone: dict = {}
    if txt is not None:
        zone[KEYNAME] = {"TXT": txt if isinstance(txt, list) else [txt]}
    return verify_all(parse_message(message), StaticResolver(zone), now=now)[0]


def keytxt(key, extra=""):  # type: ignore[no-untyped-def]
    return f"v=DKIM1; k=rsa; {extra}p={spki_b64(key)}"


def tamper(message: bytes, old: str, new: str) -> bytes:
    """Edit the DKIM-Signature header only (the first occurrence)."""
    assert old.encode() in message
    return message.replace(old.encode(), new.encode(), 1)


def test_canonicalization_rules():
    assert canon_header(b"Subject:  A \t b  \r\n", "relaxed") == b"subject:A b\r\n"
    assert canon_header(b"SubJect: a\r\n\tb\r\n", "relaxed") == b"subject:a b\r\n"
    assert canon_header(b"Subject: a \r\n", "simple") == b"Subject: a \r\n"
    assert canon_body(b"", "simple") == b"\r\n"
    assert canon_body(b"", "relaxed") == b""
    assert canon_body(b"a  b \r\n\r\n\r\n", "relaxed") == b"a b\r\n"
    assert canon_body(b"a  b \r\n\r\n\r\n", "simple") == b"a  b \r\n"
    assert canon_body(b"no newline", "simple") == b"no newline\r\n"


def test_tag_parsing():
    assert parse_tags("a=1; b = two ;;") == {"a": "1", "b": "two"}
    for bad in ("a=1; a=2", "novalue", "1a=2", "=x"):
        with pytest.raises(DkimError):
            parse_tags(bad)


def test_ok_baseline(rsa2048):  # type: ignore[no-untyped-def]
    assert run(signed(rsa2048), keytxt(rsa2048)).result == "pass"


@pytest.mark.parametrize(
    ("old", "new", "result", "word"),
    [
        ("v=1", "v=2", "permerror", "version"),
        ("a=rsa-sha256", "a=rsa-md5", "permerror", "algorithm"),
        ("a=rsa-sha256", "a=ed25519-sha256", "permerror", "key is rsa"),
        ("c=relaxed/relaxed", "c=weird/relaxed", "permerror", "canonicalization"),
        ("q=dns/txt", "q=http/foo", "permerror", "query method"),
        ("i=@example.com", "i=@evil.net", "permerror", "not inside"),
        ("h=from", "h=to", "permerror", "From"),
    ],
)
def test_signature_errors(rsa2048, old, new, result, word):  # type: ignore[no-untyped-def]
    msg = signed(rsa2048)
    msg = (
        re.sub(re.escape(old).encode(), new.encode(), msg, count=1, flags=re.I)
        if old == "h=from"
        else tamper(msg, old, new)
    )
    res = run(msg, keytxt(rsa2048))
    assert (res.result, word in res.reason) == (result, True), res.reason


def test_missing_required_tag(rsa2048):  # type: ignore[no-untyped-def]
    msg = re.sub(rb"\bbh=[^;]*;", b"", signed(rsa2048), count=1)
    res = run(msg, keytxt(rsa2048))
    assert res.result == "permerror" and "bh=" in res.reason


def test_expiry_and_future_timestamp(rsa2048):  # type: ignore[no-untyped-def]
    msg = signed(rsa2048, expire=True) if False else signed(rsa2048)
    t = int(re.search(rb"\bt=(\d+)", msg).group(1))  # type: ignore[union-attr]
    expired = msg.replace(b"; t=%d" % t, b"; t=%d; x=%d" % (t, t + 60), 1)
    assert b"x=" in expired
    res = run(expired, keytxt(rsa2048), now=t + 3600)
    assert res.result == "fail" and "expired" in res.reason
    future = run(msg, keytxt(rsa2048), now=t - 7200)
    assert any("future" in w for w in future.warnings)


def test_body_length_limit_is_flagged(rsa2048):  # type: ignore[no-untyped-def]
    msg = signed(rsa2048, length=True)
    res = run(msg + b"Click here to claim your prize\r\n", keytxt(rsa2048))
    assert res.result == "pass" and res.body_length_limit is not None
    assert any("appended" in w for w in res.warnings)
    short = run(tamper(msg, "l=", "l=999"), keytxt(rsa2048))
    assert short.result == "fail" and "longer" in short.reason


@pytest.mark.parametrize(
    ("txt", "result", "word"),
    [
        (None, "permerror", "no key"),
        ("v=DKIM1; k=rsa; p=", "fail", "revoked"),
        ("v=DKIM2; p=AAAA", "permerror", "version"),
        ("v=DKIM1; k=ed25519; p=AAAA", "permerror", "ed25519"),
        ("v=DKIM1; p=!!!!", "permerror", "base64"),
        ("v=DKIM1; h=sha1; p=AAAA", "permerror", "sha256"),
        ("v=DKIM1; s=other; p=AAAA", "permerror", "email"),
        ("v=DKIM1; p=AAAA", "permerror", "RSA key"),
        ("v=DKIM1; p=MAAA", "permerror", "RSA key"),
    ],
)
def test_key_record_errors(rsa2048, txt, result, word):  # type: ignore[no-untyped-def]
    res = run(signed(rsa2048), txt)
    assert (res.result, word in res.reason) == (result, True), res.reason


def test_two_key_records_is_ambiguous(rsa2048):  # type: ignore[no-untyped-def]
    res = run(signed(rsa2048), [keytxt(rsa2048), keytxt(rsa2048)])
    assert res.result == "permerror" and "2 key records" in res.reason


def test_dns_failure_is_temporary(rsa2048):  # type: ignore[no-untyped-def]
    res = run(signed(rsa2048), "!temp")
    assert res.result == "temperror"


def test_strict_and_testing_flags(rsa2048):  # type: ignore[no-untyped-def]
    res = run(signed(rsa2048), keytxt(rsa2048, "t=y; "))
    assert res.result == "pass" and any("test" in w for w in res.warnings)
    sub = tamper(signed(rsa2048), "i=@example.com", "i=@mail.example.com")
    assert run(sub, keytxt(rsa2048, "t=s; ")).result == "permerror"


def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    length = (
        bytes([n]) if n < 128 else bytes([0x81, n]) if n < 256 else bytes([0x82, n >> 8, n & 255])
    )
    return bytes([tag]) + length + body


def _spki(n: int, e: int = 65537) -> str:
    def integer(v: int) -> bytes:
        raw = v.to_bytes((v.bit_length() + 8) // 8, "big")
        return _der(0x02, raw)

    rsa_pub = _der(0x30, integer(n) + integer(e))
    alg = _der(0x30, bytes.fromhex("06092a864886f70d0101010500"))
    return base64.b64encode(_der(0x30, alg + _der(0x03, b"\x00" + rsa_pub))).decode()


def test_short_keys(rsa2048):  # type: ignore[no-untyped-def]
    # Only the key's size matters for the policy decision, so the modulus need not be a real RSA one.
    for bits in (512, 768):
        n = (1 << bits) - 159
        res = run(signed(rsa2048), f"v=DKIM1; k=rsa; p={_spki(n)}")
        assert res.result == "policy" and str(bits) in res.reason, res.reason


def test_1024_bit_key_passes_with_a_warning(rsa1024):  # type: ignore[no-untyped-def]
    res = run(signed(rsa1024), keytxt(rsa1024))
    assert res.result == "pass" and res.key_bits == 1024 and any("weak" in w for w in res.warnings)


def test_bare_rsapublickey_is_accepted(rsa2048):  # type: ignore[no-untyped-def]
    from cryptography.hazmat.primitives import serialization

    der = rsa2048.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.PKCS1
    )
    n, e = rsa_public_numbers(der)
    assert n == rsa2048.public_key().public_numbers().n and e == 65537


def test_more_than_ten_signatures_are_capped(rsa2048):  # type: ignore[no-untyped-def]
    one = signed(rsa2048)
    sig = one[: one.index(b"From:")]
    results = verify_all(parse_message(sig * 14 + RAW_MESSAGE), StaticResolver({}), now=NOW)
    assert len(results) == 11 and results[-1].result == "neutral"


# --- RSA primitive: the strictness that matters


def test_rsa_block_must_match_exactly(rsa2048):  # type: ignore[no-untyped-def]
    import hashlib

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    pub = rsa2048.public_key().public_numbers()
    digest = hashlib.sha256(b"x").digest()
    sig = rsa2048.sign(b"x", padding.PKCS1v15(), hashes.SHA256())
    assert rsa_verify(pub.n, pub.e, digest, "sha256", sig)
    assert not rsa_verify(pub.n, pub.e, hashlib.sha256(b"y").digest(), "sha256", sig)
    assert not rsa_verify(pub.n, pub.e, digest, "sha256", sig[:-1])
    assert not rsa_verify(pub.n, pub.e, digest, "sha256", b"\x00" * 256)
    assert not rsa_verify(pub.n, 1, digest, "sha256", sig)
    flipped = bytearray(sig)
    flipped[5] ^= 0x01
    assert not rsa_verify(pub.n, pub.e, digest, "sha256", bytes(flipped))


def test_bleichenbacher_forgery_with_e3_is_rejected():
    """The classic 2006 forgery: with e=3 and a verifier that ignores trailing bytes, a signature
    can be forged by taking a cube root. Rebuilding the whole block makes it fail here."""
    import hashlib

    from mailhdr.dkim import _DIGEST_INFO

    bits = 2048
    n = (1 << bits) - 12345  # any modulus of the right size: the forgery never needs the key
    k = bits // 8
    digest = hashlib.sha256(b"forged").digest()
    garbage_len = k - 3 - len(_DIGEST_INFO["sha256"]) - 32 - 10
    block = (
        b"\x00\x01\xff\x00"
        + _DIGEST_INFO["sha256"]
        + digest
        + b"\x00" * (k - 4 - len(_DIGEST_INFO["sha256"]) - 32)
    )
    target = int.from_bytes(block, "big")
    lo, hi = 0, 1 << (bits // 3 + 2)
    while lo < hi:  # integer cube root, rounded up so cube >= target
        mid = (lo + hi) // 2
        if mid**3 < target:
            lo = mid + 1
        else:
            hi = mid
    forged = lo.to_bytes(k, "big")
    assert garbage_len > 0 and lo**3 < n  # the cube fits under the modulus: a real forgery attempt
    assert not rsa_verify(n, 3, digest, "sha256", forged)


def test_der_garbage_never_crashes():
    import random

    rng = random.Random(7)
    good = base64.b64decode(spki_b64(rsa_key(1024)))
    for _ in range(300):
        data = bytearray(good)
        for _ in range(rng.randint(1, 4)):
            data[rng.randrange(len(data))] = rng.randrange(256)
        data = data[: rng.randint(0, len(data))] if rng.random() < 0.3 else data
        with contextlib.suppress(DkimError):
            rsa_public_numbers(bytes(data))


def test_key_record_parse_flags():
    rec = parse_key_record("v=DKIM1; k=rsa; t=y:s; h=sha256; s=email; p=QUJD")
    assert rec.testing and rec.strict_identity and rec.hashes == ["sha256"] and rec.public == b"ABC"


def test_unterminated_last_line_is_canonicalised_like_a_terminated_one():
    # On the wire the body always ends in CRLF, and relaxed canonicalisation drops the trailing
    # spaces of a line that has one. A saved copy that lost the final CRLF must give the same bytes.
    for mode in ("relaxed", "simple"):
        assert canon_body(b"a \r\nb ", mode) == canon_body(b"a \r\nb \r\n", mode)
