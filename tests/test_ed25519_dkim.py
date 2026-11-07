"""Ed25519: the RFC 8032 vectors, the RFC 8463 sample message, and signatures from dkimpy."""

from __future__ import annotations

import base64

import dkim as dkimpy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519 as ced

from mailhdr import ed25519
from mailhdr.dkim import verify_all
from mailhdr.dnsio import StaticResolver
from mailhdr.parse import parse_message
from tests.conftest import RAW_MESSAGE, ed_b64

NOW = 1_794_000_000

RFC8032 = [  # (public key, message, signature) -- RFC 8032 section 7.1, tests 1 and 2
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
]


def test_rfc8032_vectors():
    for pk, msg, sig in RFC8032:
        assert ed25519.verify(bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig))
        bad = bytearray(bytes.fromhex(sig))
        bad[10] ^= 1
        assert not ed25519.verify(bytes.fromhex(pk), bytes.fromhex(msg), bytes(bad))


def test_rejects_malformed_inputs():
    pk = bytes.fromhex(RFC8032[0][0])
    sig = bytes.fromhex(RFC8032[0][2])
    assert not ed25519.verify(pk[:31], b"", sig)
    assert not ed25519.verify(pk, b"", sig[:63])
    # s >= L must be refused (malleability)
    big_s = sig[:32] + (int.from_bytes(sig[32:], "little") + ed25519._L).to_bytes(32, "little")
    assert not ed25519.verify(pk, b"", big_s)
    assert not ed25519.verify(b"\xff" * 32, b"", sig)  # y >= p


def test_agrees_with_cryptography_on_random_messages():
    import os

    for _ in range(25):
        key = ced.Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        msg = os.urandom(os.urandom(1)[0])
        sig = key.sign(msg)
        assert ed25519.verify(pub, msg, sig)
        assert not ed25519.verify(pub, msg + b"x", sig)


def _signed_ed(key, **kw):  # type: ignore[no-untyped-def]
    seed = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    signer = dkimpy.DKIM(RAW_MESSAGE)
    sig = signer.sign(
        b"edsel",
        b"example.com",
        base64.b64encode(seed),
        signature_algorithm=b"ed25519-sha256",
        canonicalize=(b"relaxed", b"relaxed"),
        include_headers=[b"From", b"To", b"Subject"],
        **kw,
    )
    return sig + RAW_MESSAGE


def test_dkimpy_ed25519_signature_verifies():
    key = ced.Ed25519PrivateKey.generate()
    zone = StaticResolver(
        {"edsel._domainkey.example.com": {"TXT": [f"v=DKIM1; k=ed25519; p={ed_b64(key)}"]}}
    )
    signed = _signed_ed(key)
    (res,) = verify_all(parse_message(signed), zone, now=NOW)
    assert res.result == "pass", res.reason
    assert res.algorithm == "ed25519-sha256" and res.key_bits == 256
    (bad,) = verify_all(parse_message(signed.replace(b"attached", b"ATTACHED")), zone, now=NOW)
    assert bad.result == "fail"
