"""Spot domains that imitate another one: one-letter typos, look-alike characters, mixed scripts."""

from __future__ import annotations

import unicodedata
from importlib import resources
from pathlib import Path

from mailhdr import psl

# Characters from other alphabets (and a few digits) that are drawn like a Latin letter.
_CONFUSABLE = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ј": "j",
    "ѕ": "s",
    "ԁ": "d",
    "ɡ": "g",
    "һ": "h",
    "ӏ": "l",
    "ո": "n",
    "ս": "u",
    "ν": "v",
    "ο": "o",
    "ρ": "p",
    "α": "a",
    "ι": "i",
    "κ": "k",
    "τ": "t",
    "ɑ": "a",
    "ǝ": "e",
    "ℓ": "l",
    "ⅰ": "i",
    "ı": "i",
}
_DIGITS = {"0": "o", "1": "l", "5": "s"}


def load_brands(path: str | Path | None = None) -> list[str]:
    text = (
        Path(path).read_text(encoding="utf-8")
        if path
        else resources.files("mailhdr").joinpath("data/brands.txt").read_text("utf-8")
    )
    brands = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            brands.append(line)
    return brands


def to_unicode(domain: str) -> str:
    """Show an internationalised (xn--) domain the way a person would see it."""
    out = []
    for label in domain.lower().split("."):
        try:
            out.append(label.encode("ascii").decode("idna") if label.startswith("xn--") else label)
        except UnicodeError:
            out.append(label)
    return ".".join(out)


def scripts(label: str) -> set[str]:
    found = set()
    for ch in label:
        if ch.isalpha():
            found.add(unicodedata.name(ch, "UNKNOWN").split()[0])
    return found


def skeleton(domain: str) -> str:
    """A form in which look-alikes collapse together: confusable letters become Latin, rn -> m."""
    text = unicodedata.normalize("NFKC", to_unicode(domain))
    text = "".join(_CONFUSABLE.get(ch, ch) for ch in text)
    return text.replace("rn", "m").replace("vv", "w")


def _digit_skeleton(text: str) -> str:
    return "".join(_DIGITS.get(ch, ch) for ch in text)


def edit_distance(a: str, b: str, limit: int = 3) -> int:
    """Levenshtein distance, giving up early (returns limit+1) when it is clearly larger."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > limit:
            return limit + 1
        prev = cur
    return prev[-1]


def check_domain(domain: str, brands: list[str]) -> list[tuple[str, str]]:
    """Return (kind, explanation) for each way ``domain`` imitates something. Empty if it does not."""
    domain = domain.lower().rstrip(".")
    shown = to_unicode(domain)
    found: list[tuple[str, str]] = []
    for label in shown.split("."):
        kinds = scripts(label)
        if len(kinds) > 1:
            found.append(
                ("mixed-script", f"label {label!r} mixes {', '.join(sorted(kinds))} letters")
            )
    if domain.startswith("xn--") or ".xn--" in domain:
        found.append(("idn", f"internationalised domain, shown as {shown}"))

    org = psl.organizational_domain(domain)
    if org is None or org in brands:
        return found
    org_shown = to_unicode(org)
    sk = skeleton(org)
    for brand in brands:
        if brand == org:
            continue
        brand_name = brand.split(".")[0]
        org_name = org_shown.split(".")[0]
        if sk == skeleton(brand) or _digit_skeleton(sk) == _digit_skeleton(brand):
            found.append(("homoglyph", f"{org_shown} looks like {brand} (look-alike characters)"))
            continue
        same_tld = org_shown.split(".", 1)[-1] == brand.split(".", 1)[-1]
        if same_tld and len(brand_name) >= 5 and edit_distance(org_name, brand_name, 1) == 1:
            found.append(("typosquat", f"{org_shown} is one character away from {brand}"))
        elif len(brand_name) >= 6 and brand_name in org_name.replace("-", ""):
            found.append(
                (
                    "brand-in-domain",
                    f"{org_shown} contains the name {brand_name!r} but is not {brand}",
                )
            )
    return found
