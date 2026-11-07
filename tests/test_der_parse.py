from __future__ import annotations

import contextlib

import pytest

from mailhdr import der
from mailhdr.dkim import DkimError, rsa_public_numbers
from mailhdr.parse import MAX_HEADERS, ParseError, parse_message


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x30",
        b"\x30\x80\x00\x00",
        b"\x30\x81\x05\x00",
        b"\x30\x82\x00\x05" + b"\x00" * 5,
        b"\x1f\x01\x00",
        b"\x30\x05\x00",
        b"\x30\x85\x00\x00\x00\x00\x01\x00",
        b"\x30\x81",
    ],
)
def test_der_rejects_malformed(data):  # type: ignore[no-untyped-def]
    with pytest.raises(der.DerError):
        der.parse(data)


def test_der_trailing_bytes_and_integers():
    with pytest.raises(der.DerError):
        der.parse(b"\x05\x00\x00")
    assert der.decode_integer(b"\x00\xff") == 255 and der.decode_integer(b"\xff") == -1
    for bad in (b"", b"\x00\x01", b"\xff\xff"):
        with pytest.raises(der.DerError):
            der.decode_integer(bad)
    assert der.decode_oid(bytes.fromhex("2a864886f70d010101")) == "1.2.840.113549.1.1.1"
    for bad in (b"", b"\x80\x01", b"\x2a\x86"):
        with pytest.raises(der.DerError):
            der.decode_oid(bad)
    with pytest.raises(der.DerError):
        der.expect(der.parse(b"\x05\x00"), der.INTEGER, "x")


def test_negative_modulus_is_refused():
    # SEQUENCE { INTEGER -1, INTEGER 3 }: a bare RSAPublicKey with a negative modulus
    with pytest.raises(DkimError):
        rsa_public_numbers(bytes.fromhex("30060201ff020103"))
    with pytest.raises(DkimError):
        rsa_public_numbers(bytes.fromhex("30060201010201ff"))


# ---- message parsing


def test_mbox_line_lf_and_crlf_give_the_same_message():
    a = parse_message(
        b"From sender@x Mon Nov  6 10:00:00 2026\nFrom: a@b.example\nSubject: hi\n\nbody\n"
    )
    b = parse_message(b"From: a@b.example\r\nSubject: hi\r\n\r\nbody\r\n")
    assert (
        a.from_line
        and [h.raw for h in a.headers] == [h.raw for h in b.headers]
        and a.body == b.body
    )


def test_old_mac_line_endings():
    m = parse_message(b"From: a@b.example\rSubject: hi\r\rbody\r")
    assert [h.name for h in m.headers] == ["From", "Subject"] and m.body == b"body\r\n"


def test_folded_header_keeps_raw_but_unfolds_value():
    m = parse_message(b"Subject: one\r\n two\r\n\tthree\r\nFrom: a@b.example\r\n\r\nx")
    h = m.headers[0]
    assert h.raw == b"Subject: one\r\n two\r\n\tthree\r\n" and h.value == "one two three"
    assert (
        m.first("subject") is h
        and m.values("SUBJECT") == ["one two three"]
        and m.first("nope") is None
    )


def test_encoded_words_decode_and_bad_ones_survive():
    m = parse_message(b"Subject: =?utf-8?b?Y2Fmw6k=?=\r\nX: =?bogus?q?x?=\r\n\r\n")
    assert m.headers[0].decoded == "café" and m.headers[1].decoded


def test_missing_blank_line_and_junk_lines_are_noted():
    m = parse_message(b"From: a@b.example\r\nthis line is junk\r\nSubject: x\r\n")
    assert (
        m.body == b""
        and any("blank line" in p for p in m.problems)
        and any("not a header" in p for p in m.problems)
    )
    m2 = parse_message(b" continuation first\r\nFrom: a@b.example\r\n\r\n")
    assert any("continuation" in p for p in m2.problems)
    with pytest.raises(ParseError):  # a blank first line means "no headers"
        parse_message(b"\r\nFrom: a@b.example\r\n\r\n")


@pytest.mark.parametrize("data", [b"", b"   \r\n  ", b"not an email at all", b"\r\n\r\nbody only"])
def test_not_a_message(data):  # type: ignore[no-untyped-def]
    with pytest.raises(ParseError):
        parse_message(data)


def test_limits():
    with pytest.raises(ParseError):
        parse_message(b"X: y\r\n" * (MAX_HEADERS + 1) + b"\r\n")
    with pytest.raises(ParseError):
        parse_message(b"X: " + b"a" * 300_000 + b"\r\n\r\n")


def test_header_name_rules():
    m = parse_message(b"Good-Name: 1\r\nBad Name: 2\r\nFrom: a@b.example\r\n\r\n")
    assert [h.name for h in m.headers] == ["Good-Name", "From"]


def test_random_bytes_never_crash():
    import random

    rng = random.Random(3)
    for _ in range(300):
        blob = bytes(rng.choice(b"Fr om:\r\n\t =;<>@x") for _ in range(rng.randint(1, 200)))
        with contextlib.suppress(ParseError):
            parse_message(blob)
