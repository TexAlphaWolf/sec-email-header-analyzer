"""Command line: ``mailhdr analyze message.eml``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from mailhdr import __version__, lookalike
from mailhdr.analyze import analyze
from mailhdr.dnsio import DnsPythonResolver, Resolver, StaticResolver
from mailhdr.parse import MAX_MESSAGE, ParseError
from mailhdr.report import to_html, to_json, to_text

LEVELS = {"low": 0, "medium": 1, "high": 2}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mailhdr",
        description="Analyse an email's headers: delivery path, SPF, DKIM, DMARC, spoofing signs.",
    )
    p.add_argument("--version", action="version", version=f"mailhdr {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("analyze", help="analyse a message saved as .eml (use - for standard input)")
    a.add_argument("file")
    a.add_argument("--format", choices=["text", "json", "html"], default="text")
    a.add_argument(
        "-o", "--output", help="write the report to this file instead of standard output"
    )
    g = a.add_mutually_exclusive_group()
    g.add_argument(
        "--offline", action="store_true", help="make no DNS queries and re-check nothing"
    )
    g.add_argument(
        "--zone", metavar="FILE", help="answer DNS from a JSON file instead of the network"
    )
    a.add_argument("--dns-server", metavar="IP", help="ask this DNS server instead of the system's")
    a.add_argument(
        "--ip",
        help="the IP that delivered the message to the recipient's server (default: topmost Received)",
    )
    a.add_argument("--helo", help="the HELO/EHLO name that server announced")
    a.add_argument("--mailfrom", help="the envelope sender (default: the Return-Path header)")
    a.add_argument(
        "--brands", metavar="FILE", help="domains to guard against look-alikes, one per line"
    )
    a.add_argument(
        "--fail-on",
        choices=["medium", "high"],
        help="exit with status 1 if the risk is at least this level",
    )
    return p


def _read(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read(MAX_MESSAGE + 1)
    file = Path(path)
    if file.stat().st_size > MAX_MESSAGE:
        raise ParseError(f"{path} is larger than {MAX_MESSAGE} bytes")
    return file.read_bytes()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        data = _read(args.file)
        resolver: Resolver | None
        if args.offline:
            resolver = None
        elif args.zone:
            resolver = StaticResolver.from_file(args.zone)
        else:
            resolver = DnsPythonResolver(server=args.dns_server)
        brands = lookalike.load_brands(args.brands) if args.brands else None
        result = analyze(
            data, resolver, ip=args.ip, helo=args.helo, mailfrom=args.mailfrom, brands=brands
        )
    except (OSError, ParseError, ValueError) as exc:
        print(f"mailhdr: {exc}", file=sys.stderr)
        return 2
    text = {"text": to_text, "json": to_json, "html": to_html}[args.format](result)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    if args.fail_on and LEVELS[result.risk] >= LEVELS[args.fail_on]:
        return 1
    return 0
