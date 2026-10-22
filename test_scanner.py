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
