from __future__ import annotations

import json
from pathlib import Path

import pytest

from mailhdr.analyze import analyze
from mailhdr.cli import main
from mailhdr.dnsio import StaticResolver
from mailhdr.report import to_dict, to_html, to_json, to_text

EX = Path(__file__).resolve().parent.parent / "examples"
ARGS = ["--zone", str(EX / "zone.json"), "--brands", str(EX / "brands.txt")]


def test_text_report(capsys):  # type: ignore[no-untyped-def]
    assert main(["analyze", str(EX / "02-spoofed-sender.eml"), *ARGS]) == 0
    out = capsys.readouterr().out
    for needle in (
        "VERDICT  HIGH",
        "DELIVERY PATH",
        "DMARC  fail",
        "asks receivers to: reject",
        "Message-ID",
    ):
        assert needle in out


def test_json_report_is_valid_and_complete(capsys):  # type: ignore[no-untyped-def]
    main(["analyze", str(EX / "01-legitimate.eml"), "--format", "json", *ARGS])
    data = json.loads(capsys.readouterr().out)
    assert (
        data["risk"] == "low"
        and data["spf"]["result"] == "pass"
        and data["dkim"][0]["key_bits"] == 2048
    )
    assert data["tool"]["public_suffix_list"] and data["chain"]["hops"][0]["time"].startswith(
        "2026-11-06"
    )


def test_html_report_is_self_contained(capsys):  # type: ignore[no-untyped-def]
    main(["analyze", str(EX / "03-lookalike-domain.eml"), "--format", "html", *ARGS])
    page = capsys.readouterr().out
    assert page.startswith("<!doctype html>") and "Content-Security-Policy" in page
    assert "<script" not in page and "http://" not in page.replace("http://www.w3.org", "")
    assert "acmebank.example" in page


def test_output_file_and_exit_codes(tmp_path, capsys):  # type: ignore[no-untyped-def]
    out = tmp_path / "r.html"
    assert (
        main(
            [
                "analyze",
                str(EX / "02-spoofed-sender.eml"),
                "--format",
                "html",
                "-o",
                str(out),
                *ARGS,
            ]
        )
        == 0
    )
    assert (
        out.read_text(encoding="utf-8").startswith("<!doctype html>")
        and capsys.readouterr().out == ""
    )
    assert main(["analyze", str(EX / "02-spoofed-sender.eml"), "--fail-on", "high", *ARGS]) == 1
    assert main(["analyze", str(EX / "01-legitimate.eml"), "--fail-on", "medium", *ARGS]) == 0
    assert (
        main(["analyze", str(EX / "05-altered-in-transit.eml"), "--fail-on", "medium", *ARGS]) == 1
    )


def test_bad_inputs_exit_2(tmp_path, capsys):  # type: ignore[no-untyped-def]
    assert main(["analyze", str(tmp_path / "missing.eml")]) == 2
    empty = tmp_path / "e.eml"
    empty.write_bytes(b"")
    assert main(["analyze", str(empty), "--offline"]) == 2
    text = tmp_path / "t.eml"
    text.write_bytes(b"just some text, no headers\n")
    assert main(["analyze", str(text), "--offline"]) == 2
    err = capsys.readouterr().err
    assert "mailhdr:" in err and "Traceback" not in err
    assert (
        main(["analyze", str(EX / "01-legitimate.eml"), "--zone", str(tmp_path / "nope.json")]) == 2
    )
    bad = tmp_path / "z.json"
    bad.write_text("[1,2]", encoding="utf-8")
    assert main(["analyze", str(EX / "01-legitimate.eml"), "--zone", str(bad)]) == 2


def test_stdin_and_offline(monkeypatch, capsys):  # type: ignore[no-untyped-def]
    import io
    import sys

    class FakeStdin:
        buffer = io.BytesIO((EX / "01-legitimate.eml").read_bytes())

    monkeypatch.setattr(sys, "stdin", FakeStdin())
    assert main(["analyze", "-", "--offline"]) == 0
    assert "not re-checked: offline" in capsys.readouterr().out


def test_version_flag(capsys):  # type: ignore[no-untyped-def]
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0 and "mailhdr 1.0.0" in capsys.readouterr().out


# --- hostile content

EVIL = (
    b"Return-Path: <a@evil.example>\r\n"
    b"Received: from <script>alert(1)</script> ([198.51.100.1]) by x; Fri, 06 Nov 2026 10:00:00 +0000\r\n"
    b'From: "<img src=x onerror=alert(1)>" <a@evil.example>\r\n'
    b"Subject: \x1b[31mred\x1b]0;pwned\x07 </title><script>alert(2)</script>\r\n"
    b"Date: Fri, 06 Nov 2026 10:00:00 +0000\r\n\r\nbody\r\n"
)


def test_html_escapes_everything():
    page = to_html(analyze(EVIL, None))
    assert "<script>alert" not in page and "<img src=x" not in page
    assert "&lt;script&gt;" in page or "&lt;img" in page


def test_text_strips_terminal_escapes():
    text = to_text(analyze(EVIL, None))
    assert "\x1b" not in text and "\x07" not in text


def test_to_dict_has_no_non_json_types():
    a = analyze((EX / "01-legitimate.eml").read_bytes(), StaticResolver.from_file(EX / "zone.json"))
    json.dumps(to_dict(a))
    assert json.loads(to_json(a))["summary"]["subject"] == "Your October statement"
