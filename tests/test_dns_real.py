"""DnsPythonResolver against a small DNS server running in this process, so the real wire
protocol (and dnspython's error types) is exercised without needing the Internet."""

from __future__ import annotations

import socket
import threading

import dns.flags
import dns.message
import dns.rcode
import dns.rrset
import pytest

from mailhdr.dnsio import DnsError, DnsPythonResolver

RECORDS = {
    ("long.example.com.", "TXT"): ['"v=spf1 ip4:192.0.2.0/24 " "include:_spf.example.net -all"'],
    ("host.example.com.", "A"): ["192.0.2.1", "192.0.2.2"],
    ("host.example.com.", "AAAA"): ["2001:db8::1"],
    ("example.com.", "MX"): ["20 mx2.example.com.", "10 mx1.example.com."],
    ("1.2.0.192.in-addr.arpa.", "PTR"): ["host.example.com."],
    ("empty.example.com.", "A"): [],  # the name exists, but not with this type
}


def serve(sock: socket.socket, stop: threading.Event) -> None:
    sock.settimeout(0.2)
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(4096)
        except TimeoutError:
            continue
        query = dns.message.from_wire(data)
        q = query.question[0]
        name, rtype = q.name.to_text(), dns.rdatatype.to_text(q.rdtype)
        reply = dns.message.make_response(query)
        if name.startswith("timeout."):
            continue
        if name.startswith("broken."):
            reply.set_rcode(dns.rcode.SERVFAIL)
        elif RECORDS.get((name, rtype)):
            reply.answer.append(
                dns.rrset.from_text_list(name, 60, "IN", rtype, RECORDS[(name, rtype)])
            )
        elif any(n == name for n, _ in RECORDS):
            pass  # NOERROR, no answer
        else:
            reply.set_rcode(dns.rcode.NXDOMAIN)
        sock.sendto(reply.to_wire(), addr)


@pytest.fixture(scope="module")
def resolver():  # type: ignore[no-untyped-def]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    stop = threading.Event()
    thread = threading.Thread(target=serve, args=(sock, stop), daemon=True)
    thread.start()
    yield DnsPythonResolver("127.0.0.1", timeout=1.0, port=sock.getsockname()[1])
    stop.set()
    thread.join()
    sock.close()


def test_answers(resolver):  # type: ignore[no-untyped-def]
    assert resolver.txt("long.example.com") == [
        "v=spf1 ip4:192.0.2.0/24 include:_spf.example.net -all"
    ]
    assert sorted(resolver.a("host.example.com")) == ["192.0.2.1", "192.0.2.2"]
    assert resolver.aaaa("host.example.com") == ["2001:db8::1"]
    assert sorted(resolver.mx("example.com")) == [(10, "mx1.example.com"), (20, "mx2.example.com")]
    assert resolver.ptr("192.0.2.1") == ["host.example.com"]


def test_error_kinds(resolver):  # type: ignore[no-untyped-def]
    for call, kind in [
        (lambda: resolver.a("nothing.example.com"), "nxdomain"),
        (lambda: resolver.a("empty.example.com"), "nodata"),
        (lambda: resolver.txt("broken.example.com"), "temp"),
        (lambda: resolver.txt("timeout.example.com"), "temp"),
    ]:
        with pytest.raises(DnsError) as exc:
            call()
        assert exc.value.kind == kind


def test_nothing_listening_is_temporary():
    r = DnsPythonResolver("127.0.0.1", timeout=0.3, port=9)
    with pytest.raises(DnsError) as exc:
        r.txt("example.com")
    assert exc.value.kind == "temp"


def test_static_resolver_behaviours():
    from mailhdr.dnsio import StaticResolver

    z = StaticResolver({"Example.COM.": {"A": ["192.0.2.1"], "MX": ["10 Mail.Example.COM."]}})
    assert z.a("example.com") == ["192.0.2.1"] and z.mx("example.com") == [(10, "mail.example.com")]
    with pytest.raises(DnsError, match="nodata"):
        z.txt("example.com")
    with pytest.raises(DnsError, match="nxdomain"):
        z.aaaa("other.example")
    assert ("example.com", "A") in z.queries
