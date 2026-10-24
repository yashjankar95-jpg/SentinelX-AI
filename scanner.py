from urllib.parse import urlparse
import ipaddress
import re


def scan_url(url):
    if not isinstance(url, str) or not url.strip():
        return "Invalid URL"

    try:
        parsed = urlparse(url.strip())

        if parsed.scheme not in ("http", "https"):
            return "Invalid URL"

        if not parsed.hostname:
            return "Invalid URL"

        hostname = parsed.hostname.lower()

        # Validate the port, including its allowed range.
        port = parsed.port

    except ValueError:
        return "Invalid URL"

    findings = []

    if parsed.scheme != "https":
        findings.append("Warning: HTTPS is not used")

    if parsed.username or parsed.password:
        findings.append("Warning: URL contains embedded credentials")

    try:
        ipaddress.ip_address(hostname)
        findings.append("Caution: URL uses an IP address")
    except ValueError:
        pass

    if "@" in parsed.netloc:
        findings.append("Caution: '@' appears in the URL authority")

    if re.search(r"[^\x00-\x7F]", hostname):
        findings.append("Caution: Non-ASCII hostname characters")

    if not findings:
        return "No basic warning detected. Safety is not guaranteed."

    return "\n".join(findings)


if __name__ == "__main__":
    url = input("Enter URL to inspect: ")
    print("\n=== SentinelX AI ===")
    print(scan_url(url))
