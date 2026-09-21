import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup


def extract_urls(text_body="", html_body=""):
    """
    Extract URLs from plain-text and HTML email content.
    """

    urls = set()

    # Extract URLs from plain text
    if text_body:
        text_urls = re.findall(
            r"https?://[^\s<>'\"]+",
            text_body
        )

        urls.update(text_urls)

    # Extract URLs from HTML hyperlinks
    if html_body:
        soup = BeautifulSoup(html_body, "html.parser")

        for link in soup.find_all("a", href=True):
            href = link.get("href")

            if href.startswith(("http://", "https://")):
                urls.add(href)

    return sorted(urls)


def analyze_url(url):
    """
    Perform basic static analysis of a URL.
    """

    findings = []

    parsed = urlparse(url)

    domain = parsed.netloc.lower()

    # Suspicious IP-based URL
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        findings.append({
            "type": "IP-Based URL",
            "severity": "High",
            "evidence": url,
            "description": (
                "The URL uses an IP address instead of a normal domain name."
            )
        })

    # HTTP instead of HTTPS
    if parsed.scheme.lower() == "http":
        findings.append({
            "type": "Unencrypted HTTP",
            "severity": "Medium",
            "evidence": url,
            "description": (
                "The URL uses HTTP instead of HTTPS."
            )
        })

    # Suspicious keywords in URL
    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "password",
        "secure",
        "account",
        "update",
        "confirm"
    ]

    matched_keywords = [
        keyword
        for keyword in suspicious_keywords
        if keyword in url.lower()
    ]

    if matched_keywords:
        findings.append({
            "type": "Suspicious URL Keywords",
            "severity": "Medium",
            "evidence": ", ".join(matched_keywords),
            "description": (
                "The URL contains keywords commonly associated "
                "with credential or account verification pages."
            )
        })

    return {
        "url": url,
        "domain": domain,
        "findings": findings
    }