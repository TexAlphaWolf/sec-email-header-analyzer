"""Regenerate the sample messages in examples/ (needs the dev extras: dkimpy, cryptography).

All names are fictional (``.example`` is reserved for documentation) and all addresses are in the
documentation ranges. Each run makes a fresh DKIM key, so the .eml files and zone.json change
together; commit them as a pair.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

OUT = Path(__file__).resolve().parent.parent / "examples"


def make_key() -> tuple[bytes, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    pub = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem, base64.b64encode(pub).decode()


def message(
    sender: str,
    rcpt: str,
    subject: str,
    body: str,
    hops: list[str],
    extra: str = "",
    return_path: str | None = None,
) -> bytes:
    head = f"Return-Path: <{return_path or sender.split('<')[-1].rstrip('>')}>\r\n" + "".join(
        f"Received: {h}\r\n" for h in hops
    )
    head += (
        f"From: {sender}\r\nTo: {rcpt}\r\nSubject: {subject}\r\nDate: Fri, 06 Nov 2026 10:00:00 +0000\r\n"
        f"Message-ID: <{abs(hash(subject)) % 10**8}@{sender.split('@')[-1].rstrip('>')}>\r\n{extra}\r\n"
    )
    return (head + body.replace("\n", "\r\n")).encode()


def sign(raw: bytes, domain: str, selector: str, pem: bytes) -> bytes:
    sig = dkim.DKIM(raw).sign(
        selector.encode(),
        domain.encode(),
        pem,
        include_headers=[b"From", b"To", b"Subject", b"Date", b"Message-ID"],
    )
    return sig + raw


def main() -> None:
    OUT.mkdir(exist_ok=True)
    pem_a, pub_a = make_key()  # acmebank.example
    pem_b, pub_b = make_key()  # acmebamk.example (the look-alike, which is set up properly)
    zone = {
        "acmebank.example": {"TXT": ["v=spf1 ip4:192.0.2.0/24 -all"]},
        "_dmarc.acmebank.example": {
            "TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@acmebank.example"]
        },
        "s1._domainkey.acmebank.example": {"TXT": [f"v=DKIM1; k=rsa; p={pub_a}"]},
        "acmebamk.example": {"TXT": ["v=spf1 ip4:203.0.113.0/24 -all"]},
        "_dmarc.acmebamk.example": {"TXT": ["v=DMARC1; p=none"]},
        "s1._domainkey.acmebamk.example": {"TXT": [f"v=DKIM1; k=rsa; p={pub_b}"]},
    }
    (OUT / "zone.json").write_text(json.dumps(zone, indent=2) + "\n")
    (OUT / "brands.txt").write_text(
        "# the fictional bank used in these examples\nacmebank.example\n"
    )

    good_hops = [
        "from mail.acmebank.example (mail.acmebank.example [192.0.2.25]) by mx.recipient.example (Postfix) with ESMTPS id 4A1B2C for <alex@recipient.example>; Fri, 06 Nov 2026 10:00:04 +0000",
        "from app01.internal (unknown [10.0.5.14]) by mail.acmebank.example (Postfix) with ESMTP id 9F8E7D; Fri, 06 Nov 2026 10:00:01 +0000",
    ]
    body = "Dear customer,\n\nyour statement for October is ready in your online banking.\n\nAcme Bank\n"
    legit = sign(
        message(
            "Acme Bank <statements@acmebank.example>",
            "alex@recipient.example",
            "Your October statement",
            body,
            good_hops,
        ),
        "acmebank.example",
        "s1",
        pem_a,
    )
    (OUT / "01-legitimate.eml").write_bytes(legit)

    spoof_hops = [
        "from cheap-vps.example.net (unknown [203.0.113.50]) by mx.recipient.example (Postfix) with ESMTP id 5D6E7F for <alex@recipient.example>; Fri, 06 Nov 2026 10:00:09 +0000",
    ]
    phish = "Dear customer,\n\nwe noticed unusual activity. Confirm your identity within 24 hours: http://acmebank-verify.example.net/login\n\nAcme Bank Security\n"
    (OUT / "02-spoofed-sender.eml").write_bytes(
        message(
            "Acme Bank Security <security@acmebank.example>",
            "alex@recipient.example",
            "Urgent: confirm your account",
            phish,
            spoof_hops,
            return_path="bounce@cheap-vps.example.net",
        )
    )

    look_hops = [
        "from mail.acmebamk.example (mail.acmebamk.example [203.0.113.7]) by mx.recipient.example (Postfix) with ESMTPS id 7A8B9C for <alex@recipient.example>; Fri, 06 Nov 2026 10:00:12 +0000",
    ]
    look = sign(
        message(
            "Acme Bank <support@acmebamk.example>",
            "alex@recipient.example",
            "Your account has been limited",
            phish,
            look_hops,
            extra="Reply-To: helpdesk@mail-collector.example.org\r\n",
        ),
        "acmebamk.example",
        "s1",
        pem_b,
    )
    (OUT / "03-lookalike-domain.eml").write_bytes(look)

    forged = message(
        "Acme Bank <statements@acmebank.example>",
        "alex@recipient.example",
        "Invoice attached",
        phish,
        spoof_hops,
        extra="Authentication-Results: mx.recipient.example; dkim=pass header.d=acmebank.example; spf=pass smtp.mailfrom=acmebank.example; dmarc=pass header.from=acmebank.example\r\n",
        return_path="statements@acmebank.example",
    )
    (OUT / "04-forged-auth-results.eml").write_bytes(forged)

    (OUT / "05-altered-in-transit.eml").write_bytes(
        legit.replace(b"October is ready", b"October is ready (see attachment)").replace(
            b"your statement for October", b"your statement for October"
        )
    )
    (OUT / "06-display-name-trick.eml").write_bytes(
        message(
            '"statements@acmebank.example" <noreply@cheap-vps.example.net>',
            "alex@recipient.example",
            "Payment received",
            phish,
            spoof_hops,
        )
    )
    print("wrote", len(list(OUT.glob("*.eml"))), "messages and zone.json")


if __name__ == "__main__":
    main()
