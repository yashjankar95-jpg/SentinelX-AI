from urllib.parse import urlparse

def scan_url(url):
    parsed = urlparse(url.strip())

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return "Invalid URL"

    findings = []

    if parsed.scheme != "https":
        findings.append("Warning: HTTPS is not used")

    if parsed.username or parsed.password:
        findings.append("Warning: URL contains embedded credentials")

    if not findings:
        return "No basic warning detected. Safety is not guaranteed."

    return "\n".join(findings)


if __name__ == "__main__":
    url = input("Enter URL to inspect: ")
    print("\n=== SentinelX AI ===")
    print(scan_url(url))
