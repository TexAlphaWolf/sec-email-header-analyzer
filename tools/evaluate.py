"""Measure mailhdr against independent implementations. Prints a JSON summary, then OK or FAILED.

    pip install -e ".[dev]" && python tools/evaluate.py [seed]

Nothing here uses the network. What is compared, and with what:

  dkim      messages signed by dkimpy (all four canonicalisation modes, folded and repeated headers,
            odd whitespace), then damaged in six ways: mailhdr and dkimpy must give the same verdict
  ed25519   random signatures made by the ``cryptography`` package, good and bad
  rsa       random keys of 1024 to 4096 bits, signatures by ``cryptography``, good and bad
  spf       random zones evaluated by mailhdr and by pyspf
  psl       the Public Suffix List's own conformance file
  robust    thousands of damaged messages through the whole analysis: nothing may raise
  speed     how long the pieces take on this machine
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import random
import re
import statistics
import sys
import time
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

import dkim as dkimpy
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519 as ced
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from tests.test_psl import CASES, _expected, _given
from tests.test_spf_vs_pyspf import IPS, has_self_include, random_zone, run_pyspf

from mailhdr import ed25519, psl
from mailhdr.analyze import analyze
from mailhdr.dkim import rsa_public_numbers, rsa_verify, verify_all
from mailhdr.dnsio import StaticResolver
from mailhdr.parse import ParseError, parse_message


def spki(key: rsa.RSAPrivateKey) -> str:
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


# ---------------------------------------------------------------- DKIM

WORDS = [
    "alpha",
    "beta",
    "gamma",
    "delta",
    "report",
    "invoice",
    "meeting",
    "",
    "status\ttab",
    "quarterly",
    "",
    "update",
]


def random_message(rng: random.Random) -> bytes:
    def text(n: int) -> str:
        return " ".join(rng.choice(WORDS) for _ in range(n))

    subject = text(rng.randint(1, 30))
    if rng.random() < 0.4:  # fold the subject
        subject = subject.replace(" ", "\r\n ", 1) if " " in subject else subject
    headers = [
        f"From: {text(2)} <user@example.com>",
        f"To: {text(1)} <rcpt@example.org>",
        f"Subject: {subject}",
        "Date: Fri, 06 Nov 2026 10:00:00 +0000",
        f"Message-ID: <{rng.randrange(10**9)}@example.com>",
    ]
    for _ in range(rng.randint(0, 3)):
        headers.append(f"X-Tag: {text(rng.randint(1, 4))}{' ' * rng.randint(0, 3)}")
    lines = []
    for _ in range(rng.randint(0, 12)):
        line = text(rng.randint(0, 12))
        if rng.random() < 0.3:
            line += " " * rng.randint(1, 4)
        lines.append(line)
    # Mail that has crossed SMTP always ends its body with CRLF. (A body cut off mid-line is
    # a different matter: see "unterminated last line" in docs/limitations.md.)
    body = "\r\n".join(lines) + ("\r\n" * rng.randint(1, 3) if lines else "")
    return ("\r\n".join(headers) + "\r\n\r\n" + body).encode()


def damage(msg: bytes, kind: str, rng: random.Random) -> bytes:
    head, _, body = msg.partition(b"\r\n\r\n")
    if kind == "none":
        return msg
    if kind == "body-char" and body.strip():
        idx = [i for i, c in enumerate(body) if chr(c).isalpha()]
        if idx:
            i = rng.choice(idx)
            return head + b"\r\n\r\n" + body[:i] + b"Z" + body[i + 1 :]
    if kind == "body-append":
        return head + b"\r\n\r\n" + body + b"extra line\r\n"
    if kind == "subject":
        return re.sub(rb"(Subject: )(\S)", rb"\1X\2", msg, count=1)
    if kind == "sig-char":
        m = re.search(rb"\bb=([A-Za-z0-9+/]{20,})", msg)
        if m:
            i = m.start(1) + 5
            c = msg[i : i + 1]
            return msg[:i] + (b"A" if c != b"A" else b"B") + msg[i + 1 :]
    if kind == "trailing-space":
        return head + b"\r\n\r\n" + body.rstrip(b"\r\n") + b"  \r\n" if body.strip() else msg
    return msg


KINDS = ["none", "body-char", "body-append", "subject", "sig-char", "trailing-space"]


def eval_dkim(rng: random.Random, n: int, key: rsa.RSAPrivateKey) -> dict:
    txt = f"v=DKIM1; k=rsa; p={spki(key)}"
    resolver = StaticResolver({"sel._domainkey.example.com": {"TXT": [txt]}})
    canons = [
        (b"relaxed", b"relaxed"),
        (b"simple", b"simple"),
        (b"relaxed", b"simple"),
        (b"simple", b"relaxed"),
    ]
    stats = {
        "verdicts": 0,
        "agree": 0,
        "disagree": [],
        "mine_pass": 0,
        "mine_fail": 0,
        "by_damage": {k: {"changed": 0, "pass": 0, "fail": 0} for k in KINDS},
    }
    for _ in range(n):
        raw = random_message(rng)
        canon = rng.choice(canons)
        signed = (
            dkimpy.DKIM(raw).sign(
                b"sel",
                b"example.com",
                pem(key),
                canonicalize=canon,
                include_headers=[b"From", b"To", b"Subject", b"Date", b"X-Tag"],
            )
            + raw
        )
        for kind in KINDS:
            bad = damage(signed, kind, rng)
            mine = (
                verify_all(parse_message(bad), resolver, now=int(time.time()))[0].result == "pass"
            )
            theirs = bool(dkimpy.verify(bad, dnsfunc=lambda name, **kw: txt.encode()))
            stats["verdicts"] += 1
            if mine == theirs:
                stats["agree"] += 1
            else:
                stats["disagree"].append(
                    {
                        "damage": kind,
                        "canon": [c.decode() for c in canon],
                        "mine": mine,
                        "theirs": theirs,
                    }
                )
            stats["mine_pass" if mine else "mine_fail"] += 1
            row = stats["by_damage"][kind]
            if (
                kind == "none" or bad != signed
            ):  # some damages cannot be applied to every message (an empty body, say)
                row["changed"] += 1
                row["pass" if mine else "fail"] += 1
    return stats


# ---------------------------------------------------------------- primitives


def eval_ed25519(rng: random.Random, n: int) -> dict:
    ok = 0
    for _ in range(n):
        key = ced.Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        msg = rng.randbytes(rng.randint(0, 300))
        sig = key.sign(msg)
        bad = bytearray(sig)
        bad[rng.randrange(64)] ^= 1 << rng.randrange(8)
        ok += (
            ed25519.verify(pub, msg, sig)
            and not ed25519.verify(pub, msg, bytes(bad))
            and not ed25519.verify(pub, msg + b"!", sig)
        )
    return {"cases": n, "correct": ok}


def eval_rsa(rng: random.Random, per_size: int) -> dict:
    out = {}
    for bits in (1024, 2048, 3072, 4096):
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        nums = key.public_key().public_numbers()
        n, e = rsa_public_numbers(base64.b64decode(spki(key)))
        assert (n, e) == (nums.n, nums.e)
        good = 0
        for _ in range(per_size):
            msg = rng.randbytes(rng.randint(1, 200))
            sig = key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
            digest = hashlib.sha256(msg).digest()
            flipped = bytearray(sig)
            flipped[rng.randrange(len(sig))] ^= 1 << rng.randrange(8)
            good += (
                rsa_verify(n, e, digest, "sha256", sig)
                and not rsa_verify(n, e, digest, "sha256", bytes(flipped))
                and not rsa_verify(n, e, hashlib.sha256(msg + b"x").digest(), "sha256", sig)
            )
        out[str(bits)] = {"cases": per_size, "correct": good}
    return out


# ---------------------------------------------------------------- SPF


class _MP:
    """Just enough of pytest's monkeypatch for run_pyspf outside pytest."""

    def setattr(self, obj, name, value):  # type: ignore[no-untyped-def]
        setattr(obj, name, value)


def eval_spf(seeds: range) -> dict:
    from mailhdr.spf import check_host

    compared = agree = skipped = 0
    words: dict[str, int] = {}
    diffs = []
    for seed in seeds:
        rng = random.Random(seed)
        zone = random_zone(rng)
        if has_self_include(zone):
            skipped += 1
            continue
        for ip in IPS:
            sender = f"user@{rng.choice(['example.com', 'a.example.net', 'b.example.net', 'c.example.net', 'mx.example.net'])}"
            mine = check_host(StaticResolver(zone), ip, sender, "mx.example.net", now=0).result
            theirs = run_pyspf(zone, ip, sender, _MP())
            compared += 1
            words[mine] = words.get(mine, 0) + 1
            if mine == theirs:
                agree += 1
            else:
                diffs.append({"seed": seed, "ip": ip, "mine": mine, "theirs": theirs})
    return {
        "zones": len(seeds),
        "zones_skipped_self_include": skipped,
        "evaluations": compared,
        "agree": agree,
        "differences": diffs,
        "result_words": dict(sorted(words.items())),
    }


# ---------------------------------------------------------------- robustness


def eval_robust(rng: random.Random, n: int) -> dict:
    base = [p.read_bytes() for p in sorted((ROOT / "examples").glob("*.eml"))]
    resolver = StaticResolver.from_file(ROOT / "examples" / "zone.json")
    refused = ok = 0
    crashes = []
    for i in range(n):
        data = bytearray(rng.choice(base))
        for _ in range(rng.randint(1, 8)):
            op = rng.randrange(4)
            pos = rng.randrange(len(data) + 1)
            if op == 0 and data:
                data[min(pos, len(data) - 1)] = rng.randrange(256)
            elif op == 1:
                data[pos:pos] = rng.randbytes(rng.randint(1, 20))
            elif op == 2:
                del data[pos : pos + rng.randint(1, 40)]
            else:
                data[pos:pos] = rng.choice(
                    [b"\r\n", b"\r\n ", b";", b"=?utf-8?q?", b"\x00", b"<", b'"', b"(", b"%{"]
                )
        try:
            analyze(bytes(data), resolver)
            ok += 1
        except ParseError:
            refused += 1
        except Exception as exc:
            crashes.append({"case": i, "error": f"{type(exc).__name__}: {exc}"[:200]})
    return {
        "cases": n,
        "analysed": ok,
        "refused_as_not_a_message": refused,
        "crashes": crashes[:5],
        "crash_count": len(crashes),
    }


# ---------------------------------------------------------------- speed


def best_ms(fn, repeat: int = 20) -> float:  # type: ignore[no-untyped-def]
    times = []
    for _ in range(repeat):
        t = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t) * 1000)
    return round(statistics.median(times), 3)


def eval_speed(key: rsa.RSAPrivateKey) -> dict:
    raw = (ROOT / "examples" / "01-legitimate.eml").read_bytes()
    zone = StaticResolver.from_file(ROOT / "examples" / "zone.json")
    msg = parse_message(raw)
    ek = ced.Ed25519PrivateKey.generate()
    pub = ek.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sig = ek.sign(b"x" * 32)
    return {
        "parse_message_ms": best_ms(lambda: parse_message(raw)),
        "dkim_rsa2048_verify_ms": best_ms(lambda: verify_all(msg, zone)),
        "ed25519_verify_ms": best_ms(lambda: ed25519.verify(pub, b"x" * 32, sig), 10),
        "full_analysis_ms": best_ms(lambda: analyze(raw, zone), 10),
    }


def main() -> int:
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    rng = random.Random(seed)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    result = {
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.machine()}",
        "seed": seed,
        "dkimpy": metadata.version("dkimpy"),
        "pyspf": metadata.version("pyspf"),
        "public_suffix_list": psl.list_version(),
    }
    result["dkim"] = eval_dkim(rng, 150, key)
    result["ed25519"] = eval_ed25519(rng, 200)
    result["rsa"] = eval_rsa(rng, 40)
    result["spf"] = eval_spf(range(300))
    got = sum(
        1
        for g, e in CASES
        if (psl.organizational_domain(_given(g)) if _given(g) is not None else None) == _expected(e)
    )
    result["psl"] = {"cases": len(CASES), "correct": got}
    result["robust"] = eval_robust(rng, 5000)
    result["speed"] = eval_speed(key)
    print(json.dumps(result, indent=2))
    d, e, r, s, p, rb = (result[k] for k in ("dkim", "ed25519", "rsa", "spf", "psl", "robust"))
    ok = (
        d["agree"] == d["verdicts"]
        and d["by_damage"]["none"]["fail"] == 0  # an undamaged message always verifies
        and all(
            d["by_damage"][k]["pass"] == 0
            for k in ("body-char", "body-append", "subject", "sig-char")
        )
        and e["correct"] == e["cases"]
        and all(v["correct"] == v["cases"] for v in r.values())
        and s["agree"] == s["evaluations"]
        and s["evaluations"] > 1000
        and p["correct"] == p["cases"]
        and rb["crash_count"] == 0
    )
    print("OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    os.environ.setdefault("PYTHONHASHSEED", "0")
    raise SystemExit(main())
