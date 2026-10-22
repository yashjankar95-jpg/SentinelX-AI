from scanner import scan_url


def test_invalid_url():
    assert scan_url("not-a-url") == "Invalid URL"


def test_http_warning():
    result = scan_url("http://example.com")
    assert "HTTPS is not used" in result


def test_https_no_basic_warning():
    result = scan_url("https://example.com")
    assert "No basic warning detected" in result


def test_ip_address_warning():
    result = scan_url("http://192.0.2.1")
    assert "URL uses an IP address" in result


def test_embedded_credentials_warning():
    result = scan_url("https://user:pass@example.com")
    assert "embedded credentials" in result


def test_non_ascii_hostname_warning():
    result = scan_url("https://münich.example")
    assert "Non-ASCII hostname characters" in result


def test_url_with_at_symbol_warning():
    result = scan_url("https://example.com@evil.example")
    assert "@" in result


def test_url_with_invalid_port():
    assert scan_url("https://example.com:abc") == "Invalid URL"


def test_empty_url():
    assert scan_url("") == "Invalid URL"


def test_non_string_input():
    assert scan_url(None) == "Invalid URL"
