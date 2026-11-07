"""The docs and the code must not drift apart."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = (ROOT / "src/mailhdr/analyze.py").read_text(encoding="utf-8")
DOC = (ROOT / "docs/findings.md").read_text(encoding="utf-8")

DYNAMIC = [
    "no-date", "no-message-id", "multiple-date", "multiple-message-id",
    "from-homoglyph", "from-mixed-script", "from-typosquat", "from-brand-in-domain", "from-idn",
    "dkim-fail", "dkim-policy", "dkim-permerror", "dkim-temperror",
    "spf-none", "spf-neutral", "spf-permerror", "spf-temperror",
    "dmarc-permerror", "dmarc-temperror",
]  # fmt: skip


def test_every_finding_code_is_documented():
    static = {
        c
        for c in re.findall(r'add\(\s*"(?:high|medium|low|info)",\s*"([a-z-]+)"', SRC)
        if not c.endswith("-")
    }
    for code in sorted(static | set(DYNAMIC)):
        assert f"`{code}`" in DOC, f"{code} is not in docs/findings.md"


def test_documented_codes_exist_in_code():
    documented = set(re.findall(r"`([a-z]+(?:-[a-z]+)+|path|offline)`", DOC))
    known = set(re.findall(r'"([a-z]+(?:-[a-z]+)*)"', SRC)) | set(DYNAMIC)
    unknown = {
        c for c in documented if c not in known and not any(c.startswith(k) for k in ("--",))
    }
    assert unknown <= {"no-from"} | known, unknown


def test_readme_numbers_match_the_evaluation_doc():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    evaluation = (ROOT / "docs/evaluation.md").read_text(encoding="utf-8")
    for number in ("900", "1,512", "78 of 78"):
        assert number in readme and number in evaluation
