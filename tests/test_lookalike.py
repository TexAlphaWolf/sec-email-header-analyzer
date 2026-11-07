import pytest

from mailhdr.lookalike import check_domain, edit_distance, load_brands, skeleton, to_unicode

BRANDS = load_brands()


def kinds(domain: str) -> set[str]:
    return {k for k, _ in check_domain(domain, BRANDS)}


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("paypa1.com", {"homoglyph"}),
        ("paypal.com", set()),
        ("mail.paypal.com", set()),
        ("rnicrosoft.com", {"homoglyph"}),
        ("paypall.com", {"typosquat"}),
        ("paypai.com", {"typosquat"}),
        ("paypal-secure-login.com", {"brand-in-domain"}),
        ("xn--pypal-4ve.com", {"idn", "mixed-script", "homoglyph"}),
        ("example.org", set()),
        ("microsft.com", {"typosquat"}),
        ("gooogle.com", {"typosquat"}),
        ("github.io", set()),
        ("amazon.it", set()),
    ],
)
def test_lookalikes(domain, expected):  # type: ignore[no-untyped-def]
    assert kinds(domain) == expected


def test_cyrillic_a_in_paypal():
    spoof = "pаypal.com"  # Cyrillic a
    assert "mixed-script" in kinds(spoof) and "homoglyph" in kinds(spoof)
    assert "mixed-script" in kinds(spoof.encode("idna").decode())


def test_pure_cyrillic_is_not_mixed():
    assert "mixed-script" not in kinds("пример.рф")


def test_helpers():
    assert edit_distance("paypal", "paypal") == 0 and edit_distance("paypal", "paypa") == 1
    assert edit_distance("abc", "xyz", 1) == 2 and edit_distance("a", "abcdef", 2) == 3
    assert (
        to_unicode("xn--bcher-kva.example") == "bücher.example"
        and to_unicode("xn--zzz--.x") == "xn--zzz--.x"
    )
    assert skeleton("rnicrosoft.com") == "microsoft.com"


def test_custom_brand_file(tmp_path):  # type: ignore[no-untyped-def]
    f = tmp_path / "b.txt"
    f.write_text("# mine\nacmebank.com  # main site\n\n", encoding="utf-8")
    assert load_brands(f) == ["acmebank.com"]
    assert {k for k, _ in check_domain("acmebamk.com", ["acmebank.com"])} == {"typosquat"}
