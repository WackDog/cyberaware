import pytest

from url_checker import analyse_url


def warning_codes(result):
    return {warning["code"] for warning in result["warnings"]}


def test_normal_https_url_can_have_no_triggered_warnings():
    result = analyse_url("https://example.com/news")
    assert result["risk_level"] == "Low"
    assert result["score"] == 0
    assert result["warnings"] == []


def test_ip_address_hostname_is_flagged():
    result = analyse_url("https://203.0.113.42/account")
    assert "ip-host" in warning_codes(result)


def test_at_symbol_is_flagged():
    result = analyse_url("https://trusted.example@evil.example/login")
    assert result["hostname"] == "evil.example"
    assert "at-symbol" in warning_codes(result)


def test_http_is_flagged_when_explicitly_supplied():
    result = analyse_url("http://example.com")
    assert "http" in warning_codes(result)


def test_many_subdomains_are_flagged():
    result = analyse_url("https://a.b.c.d.example.com/path")
    assert "subdomains" in warning_codes(result)


def test_punycode_is_flagged():
    result = analyse_url("https://xn--exmple-cua.com")
    assert "punycode" in warning_codes(result)


def test_long_url_is_flagged():
    result = analyse_url("https://example.com/" + ("a" * 130))
    assert "length" in warning_codes(result)


def test_sensitive_terms_are_explained_as_context_not_proof():
    result = analyse_url("https://example.com/account/verify")
    assert "sensitive-terms" in warning_codes(result)


def test_missing_scheme_is_accepted_for_educational_analysis():
    result = analyse_url("example.com/login")
    assert result["hostname"] == "example.com"
    assert result["scheme"] == "not supplied"


def test_unsupported_scheme_is_rejected():
    with pytest.raises(ValueError, match="Only http:// and https://"):
        analyse_url("ftp://example.com/file")


def test_empty_url_is_rejected():
    with pytest.raises(ValueError, match="Enter a URL"):
        analyse_url("")
