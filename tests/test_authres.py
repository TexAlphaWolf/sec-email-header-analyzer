from mailhdr.authres import parse_auth_results


def test_typical_gmail_header():
    ar = parse_auth_results(
        "mx.google.com;\r\n dkim=pass header.i=@example.com header.s=sel header.b=AbCd;\r\n"
        " spf=pass (google.com: domain of bob@example.com designates 192.0.2.1 as permitted sender) smtp.mailfrom=bob@example.com;\r\n"
        " dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com"
    )
    assert ar.server == "mx.google.com"
    assert [(c.method, c.result) for c in ar.claims] == [
        ("dkim", "pass"),
        ("spf", "pass"),
        ("dmarc", "pass"),
    ]
    assert ar.claims[0].props["header.s"] == "sel"
    assert ar.claims[1].props["smtp.mailfrom"] == "bob@example.com"
    assert "designates" in ar.claims[1].comment
    assert ar.result("dmarc") == "pass" and ar.result("arc") is None


def test_none_and_garbage_are_tolerated():
    assert parse_auth_results("mx.example.org; none").claims == []
    assert parse_auth_results("").claims == []
    ar = parse_auth_results('mx.example.org; spf=fail smtp.helo="x y"; ;;; ???')
    assert ar.claims[0].result == "fail" and ar.claims[0].props["smtp.helo"] == "x y"
