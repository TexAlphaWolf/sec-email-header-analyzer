"""My verifier against dkimpy: messages signed by dkimpy must verify with mine, and the same
tampering must be rejected by both."""

from __future__ import annotations

import dkim as dkimpy
import pytest

from mailhdr.dkim import verify_all
from mailhdr.dnsio import StaticResolver
from mailhdr.parse import parse_message
from tests.conftest import RAW_MESSAGE, pem, rsa_key, spki_b64

NOW = 1_794_000_000


def sign(
    key,
    canon=(b"relaxed", b"relaxed"),
    algo=b"rsa-sha256",
    message=RAW_MESSAGE,  # type: ignore[no-untyped-def]
    include_headers=(b"From", b"To", b"Subject", b"Date"),
    **kw,
):
    signer = dkimpy.DKIM(message)
    sig = signer.sign(
        b"sel",
        b"example.com",
        pem(key),
        canonicalize=canon,
        signature_algorithm=algo,
        include_headers=list(include_headers),
        **kw,
    )
    return sig + message


def zone(key) -> StaticResolver:  # type: ignore[no-untyped-def]
    return StaticResolver(
        {"sel._domainkey.example.com": {"TXT": [f"v=DKIM1; k=rsa; p={spki_b64(key)}"]}}
    )


@pytest.mark.parametrize(
    "canon",
    [
        (b"relaxed", b"relaxed"),
        (b"simple", b"simple"),
        (b"relaxed", b"simple"),
        (b"simple", b"relaxed"),
    ],
)
def test_dkimpy_signature_verifies(rsa2048, canon):  # type: ignore[no-untyped-def]
    signed = sign(rsa2048, canon)
    (res,) = verify_all(parse_message(signed), zone(rsa2048), now=NOW)
    assert res.result == "pass", res.reason
    assert res.key_bits == 2048 and res.canon == f"{canon[0].decode()}/{canon[1].decode()}"


def test_body_tamper_fails_in_both(rsa2048):  # type: ignore[no-untyped-def]
    signed = sign(rsa2048).replace(b"attached", b"ATTACHED")
    (res,) = verify_all(parse_message(signed), zone(rsa2048), now=NOW)
    assert res.result == "fail" and "body hash" in res.reason
    assert not dkimpy.verify(
        signed, dnsfunc=lambda n, **k: f"v=DKIM1; k=rsa; p={spki_b64(rsa2048)}".encode()
    )


def test_header_tamper_fails_in_both(rsa2048):  # type: ignore[no-untyped-def]
    signed = sign(rsa2048).replace(b"Subject: Quarterly", b"Subject: Urgent")
    (res,) = verify_all(parse_message(signed), zone(rsa2048), now=NOW)
    assert res.result == "fail" and "signature did not verify" in res.reason


def test_unsigned_header_change_still_passes(rsa2048):  # type: ignore[no-untyped-def]
    signed = sign(rsa2048).replace(b"Message-ID: <abc123", b"Message-ID: <zzz999")
    (res,) = verify_all(parse_message(signed), zone(rsa2048), now=NOW)
    assert res.result == "pass"


def test_lf_only_file_verifies(rsa2048):  # type: ignore[no-untyped-def]
    signed = sign(rsa2048).replace(b"\r\n", b"\n")
    (res,) = verify_all(parse_message(signed), zone(rsa2048), now=NOW)
    assert res.result == "pass"


def test_header_added_above_a_signed_one_is_caught(rsa2048):  # type: ignore[no-untyped-def]
    # From is listed twice in h=, so the signer committed to "exactly one From". Adding another on
    # top must break the signature, even though the original From is still there.
    signed = sign(rsa2048, include_headers=[b"From", b"From", b"To", b"Subject", b"Date"])
    assert b"h=from:from:" in signed.replace(b"\r\n", b"").replace(b" ", b"").lower()
    forged = b"From: ceo@example.com\r\n" + signed
    (res,) = verify_all(parse_message(forged), zone(rsa2048), now=NOW)
    assert res.result == "fail"
    (clean,) = verify_all(parse_message(signed), zone(rsa2048), now=NOW)
    assert clean.result == "pass"


def test_wrong_key_fails(rsa2048):  # type: ignore[no-untyped-def]
    other = rsa_key(2048)
    (res,) = verify_all(parse_message(sign(rsa2048)), zone(other), now=NOW)
    assert res.result == "fail" and "did not verify" in res.reason


def test_rsa_sha1_refused_by_policy(rsa2048):  # type: ignore[no-untyped-def]
    signed = sign(rsa2048, algo=b"rsa-sha1")
    (res,) = verify_all(parse_message(signed), zone(rsa2048), now=NOW)
    assert res.result == "policy" and "8301" in res.reason


def test_short_key_is_policy_and_1024_warns(rsa1024):  # type: ignore[no-untyped-def]
    signed = sign(rsa1024)
    (res,) = verify_all(parse_message(signed), zone(rsa1024), now=NOW)
    assert res.result == "pass" and any("weak" in w for w in res.warnings)
