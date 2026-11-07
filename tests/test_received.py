from __future__ import annotations

import re
from datetime import timedelta

import pytest

from mailhdr.parse import parse_message
from mailhdr.received import build_chain, classify_ip, parse_received


@pytest.mark.parametrize(
    ("ip", "kind"),
    [
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("10.1.2.3", "private"),
        ("192.168.0.9", "private"),
        ("172.16.5.5", "private"),
        ("169.254.1.1", "linklocal"),
        ("100.64.0.1", "cgnat"),
        ("fe80::1", "linklocal"),
        ("192.0.2.5", "documentation"),
        ("2001:db8::1", "documentation"),
        ("8.8.8.8", "public"),
        ("2606:4700::1111", "public"),
        ("::ffff:10.0.0.1", "private"),
        ("999.1.1.1", "invalid"),
        ("fd00::1", "private"),
    ],
)
def test_classify_ip(ip, kind):  # type: ignore[no-untyped-def]
    assert classify_ip(ip) == kind


def test_gmail_style():
    h = parse_received(
        "from mail-wr1-f41.google.com (mail-wr1-f41.google.com [209.85.221.41])\r\n by mx.example.org (Postfix) "
        "with ESMTPS id 4F3A21234 for <bob@example.org>; Fri, 06 Nov 2026 10:00:02 +0000 (UTC)"
    )
    assert (h.from_host, h.from_rdns, h.from_ip) == (
        "mail-wr1-f41.google.com",
        "mail-wr1-f41.google.com",
        "209.85.221.41",
    )
    assert (h.by, h.protocol, h.id, h.for_addr) == (
        "mx.example.org",
        "ESMTPS",
        "4F3A21234",
        "bob@example.org",
    )
    assert h.time is not None and h.time.year == 2026


def test_helo_differs_from_rdns():
    h = parse_received(
        "from localhost (unknown [203.0.113.9]) by mx.example.org with SMTP; Fri, 06 Nov 2026 10:00:00 +0000"
    )
    assert (
        h.from_host == "localhost" and h.from_ip == "203.0.113.9" and h.ip_kind == "documentation"
    )


def test_ipv6_and_exim_style():
    h = parse_received(
        "from [2001:db8::25] (helo=mailer.example.net) by mx.example.org with esmtp (Exim 4.97) id 1abc-0001; Fri, 06 Nov 2026 10:00:00 +0000"
    )
    assert h.from_ip == "2001:db8::25" and h.by == "mx.example.org" and h.protocol == "esmtp"
    h6 = parse_received(
        "from smtp.example.net ([IPv6:2001:db8::7]) by mx.example.org; Fri, 06 Nov 2026 10:00:00 +0000"
    )
    assert h6.from_ip == "2001:db8::7"


def test_words_inside_comments_are_not_clauses():
    h = parse_received(
        "from a.example.net (a.example.net [192.0.2.1] by mistake for nobody) by b.example.org with SMTP; Fri, 06 Nov 2026 10:00:00 +0000"
    )
    assert h.by == "b.example.org" and h.for_addr == ""


def test_internal_hop_only_and_garbage():
    h = parse_received(
        "by 2002:a05:6a20:1234 with SMTP id abc; Fri, 06 Nov 2026 10:00:00 -0800 (PST)"
    )
    assert h.by == "2002:a05:6a20:1234" and not h.from_ip and h.time is not None
    junk = parse_received("complete nonsense; not a date")
    assert junk.time is None and "unreadable date" in junk.notes
    assert parse_received("").by == ""


def msg(*received: str) -> bytes:
    return (
        "".join(f"Received: {r}\r\n" for r in received) + "From: a@b.example\r\n\r\nx\r\n"
    ).encode()


def test_chain_order_delay_and_origin():
    data = msg(
        "from relay.example.org (relay.example.org [198.51.100.9]) by mx.example.org; Fri, 06 Nov 2026 10:00:30 +0000",
        "from client (unknown [10.0.0.5]) by relay.example.org; Fri, 06 Nov 2026 10:00:10 +0000",
        "from laptop ([203.0.113.77]) by client; Fri, 06 Nov 2026 10:00:00 +0000",
    )
    chain = build_chain(parse_message(data))
    assert [h.index for h in chain.chronological] == [2, 1, 0]
    assert chain.chronological[1].delay == timedelta(seconds=10)
    assert chain.origin is not None and chain.origin.from_ip == "203.0.113.77"
    assert chain.total_delay == timedelta(seconds=30)


def test_time_going_backwards_and_slow_hop_are_reported():
    back = msg(
        "from a.example.org ([198.51.100.9]) by mx.example.org; Fri, 06 Nov 2026 09:00:00 +0000",
        "from b.example.org ([198.51.100.8]) by a.example.org; Fri, 06 Nov 2026 10:00:00 +0000",
    )
    assert any("clocks disagree" in p for p in build_chain(parse_message(back)).problems)
    slow = msg(
        "from a.example.org ([198.51.100.9]) by mx.example.org; Fri, 06 Nov 2026 14:00:00 +0000",
        "from b.example.org ([198.51.100.8]) by a.example.org; Fri, 06 Nov 2026 10:00:00 +0000",
    )
    assert any("took 4:00:00" in p for p in build_chain(parse_message(slow)).problems)


def test_chain_continuity():
    broken = msg(
        "from other.example.net ([198.51.100.9]) by mx.example.org; Fri, 06 Nov 2026 10:00:30 +0000",
        "from client ([203.0.113.1]) by relay.example.org; Fri, 06 Nov 2026 10:00:10 +0000",
    )
    assert any(
        re.search(r"other\.example\.net", p) for p in build_chain(parse_message(broken)).problems
    )
    fine = msg(
        "from relay.example.org ([198.51.100.9]) by mx.example.org; Fri, 06 Nov 2026 10:00:30 +0000",
        "from client ([203.0.113.1]) by relay.example.org; Fri, 06 Nov 2026 10:00:10 +0000",
    )
    assert not build_chain(parse_message(fine)).problems


def test_no_received_headers():
    chain = build_chain(parse_message(b"From: a@b.example\r\n\r\nx\r\n"))
    assert chain.hops == [] and chain.origin is None
