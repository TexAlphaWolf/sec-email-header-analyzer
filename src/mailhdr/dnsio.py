"""DNS access behind a small interface, so everything above it runs without a network.

``Resolver`` is what SPF, DKIM and DMARC need. ``DnsPythonResolver`` asks a real server
(dnspython is imported only when it is used). ``StaticResolver`` answers from a dictionary or a
JSON zone file: that is how tests run and how a saved message can be re-analysed later with the
DNS data it had at the time.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol


class DnsError(Exception):
    """A lookup that did not produce an answer. ``kind`` says why:

    nxdomain  the name does not exist
    nodata    the name exists but has no record of that type
    temp      a timeout, a server failure, anything that may work later
    """

    def __init__(self, kind: str, name: str = "", detail: str = "") -> None:
        super().__init__(f"{kind}: {name} {detail}".strip())
        self.kind = kind
        self.name = name


class Resolver(Protocol):
    def txt(self, name: str) -> list[str]: ...
    def a(self, name: str) -> list[str]: ...
    def aaaa(self, name: str) -> list[str]: ...
    def mx(self, name: str) -> list[tuple[int, str]]: ...
    def ptr(self, address: str) -> list[str]: ...


def _norm(name: str) -> str:
    return name.rstrip(".").lower()


class StaticResolver:
    """Answers from a dict like ``{"example.com": {"TXT": ["v=spf1 -all"], "A": ["192.0.2.1"]}}``.

    A name that is absent is NXDOMAIN; a name that is present without the asked type is NODATA;
    a record value of ``"!temp"`` makes that lookup fail the way a timeout would.
    """

    def __init__(self, zone: Mapping[str, Mapping[str, list[str]]] | None = None) -> None:
        self.zone: dict[str, dict[str, list[str]]] = {
            _norm(k): {t.upper(): list(v) for t, v in recs.items()}
            for k, recs in (zone or {}).items()
        }
        self.queries: list[tuple[str, str]] = []

    @classmethod
    def from_file(cls, path: str | Path) -> StaticResolver:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("a zone file is a JSON object: name -> {type -> [values]}")
        return cls(data)

    def _get(self, name: str, rtype: str) -> list[str]:
        key = _norm(name)
        self.queries.append((key, rtype))
        records = self.zone.get(key)
        if records is None:
            raise DnsError("nxdomain", key)
        values = records.get(rtype)
        if values is None:
            raise DnsError("nodata", key)
        if values == ["!temp"]:
            raise DnsError("temp", key, "simulated failure")
        return values

    def txt(self, name: str) -> list[str]:
        return self._get(name, "TXT")

    def a(self, name: str) -> list[str]:
        return self._get(name, "A")

    def aaaa(self, name: str) -> list[str]:
        return self._get(name, "AAAA")

    def mx(self, name: str) -> list[tuple[int, str]]:
        out = []
        for value in self._get(name, "MX"):
            pref, _, host = value.partition(" ")
            out.append((int(pref), _norm(host)))
        return out

    def ptr(self, address: str) -> list[str]:
        import ipaddress

        # keyed by the reverse name, like a real zone: 10.2.0.192.in-addr.arpa
        return [_norm(v) for v in self._get(ipaddress.ip_address(address).reverse_pointer, "PTR")]


class DnsPythonResolver:
    """A real resolver. ``server`` (an IP) overrides the machine's own; ``timeout`` is per query."""

    def __init__(self, server: str | None = None, timeout: float = 5.0, port: int = 53) -> None:
        import dns.resolver

        self._dns = dns.resolver
        self._resolver = dns.resolver.Resolver(configure=server is None)
        if server:
            self._resolver.nameservers = [server]
            self._resolver.port = port
        self._resolver.lifetime = timeout
        self._resolver.timeout = timeout

    def _query(self, name: str, rtype: str):  # type: ignore[no-untyped-def]
        import dns.exception
        import dns.resolver

        try:
            return self._resolver.resolve(name, rtype)
        except dns.resolver.NXDOMAIN as exc:
            raise DnsError("nxdomain", name) from exc
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers) as exc:
            kind = "nodata" if isinstance(exc, dns.resolver.NoAnswer) else "temp"
            raise DnsError(kind, name, str(exc)[:80]) from exc
        except (dns.exception.Timeout, dns.exception.DNSException, OSError) as exc:
            raise DnsError("temp", name, type(exc).__name__) from exc

    def txt(self, name: str) -> list[str]:
        return [
            b"".join(r.strings).decode("utf-8", errors="replace") for r in self._query(name, "TXT")
        ]

    def a(self, name: str) -> list[str]:
        return [r.address for r in self._query(name, "A")]

    def aaaa(self, name: str) -> list[str]:
        return [r.address for r in self._query(name, "AAAA")]

    def mx(self, name: str) -> list[tuple[int, str]]:
        return [(int(r.preference), _norm(str(r.exchange))) for r in self._query(name, "MX")]

    def ptr(self, address: str) -> list[str]:
        import dns.reversename

        return [
            _norm(str(r)) for r in self._query(str(dns.reversename.from_address(address)), "PTR")
        ]
