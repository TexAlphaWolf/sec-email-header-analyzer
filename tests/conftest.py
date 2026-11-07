"""Shared helpers: keys, signed messages and a resolver built from them."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from mailhdr.dnsio import StaticResolver

RAW_MESSAGE = (
    b"From: Alice Example <alice@example.com>\r\n"
    b"To: Bob <bob@example.org>\r\n"
    b"Subject: Quarterly   report\r\n"
    b"Date: Fri, 06 Nov 2026 10:00:00 +0000\r\n"
    b"Message-ID: <abc123@example.com>\r\n"
    b"\r\n"
    b"Hello Bob,\r\n\r\nthe numbers   are attached.\r\n\r\nAlice\r\n"
)


def rsa_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def spki_b64(key: rsa.RSAPrivateKey) -> str:
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(der).decode()


def pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def ed_b64(key: ed25519.Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


@pytest.fixture(scope="session")
def rsa2048() -> rsa.RSAPrivateKey:
    return rsa_key(2048)


@pytest.fixture(scope="session")
def rsa1024() -> rsa.RSAPrivateKey:
    return rsa_key(1024)


@pytest.fixture
def zone_for(rsa2048):  # type: ignore[no-untyped-def]
    def make(**extra: list[str]) -> StaticResolver:
        zone = {"sel._domainkey.example.com": {"TXT": [f"v=DKIM1; k=rsa; p={spki_b64(rsa2048)}"]}}
        return StaticResolver(zone)

    return make
