"""Email link analysis.

Checks for URL shorteners, suspicious TLDs, display/href mismatches, and
broken links.  Recognizes corporate email gateway URL rewriting (Proofpoint,
Mimecast, Microsoft Safe Links, Barracuda, ThreatDown/Malwarebytes, etc.)
as a legitimate security feature, not a phishing indicator.
"""
from __future__ import annotations

from email.message import EmailMessage
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from mail_tester.analysis.network_policy import LINK_ACCESS_NOTICE
from mail_tester.email_utils import get_html_body
from mail_tester.models import CheckResult, CheckStatus

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "bl.ink", "short.io",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".link", ".buzz", ".tk", ".ml", ".ga", ".cf",
}

# Known corporate email security gateways that rewrite URLs.
# These wrap original links through their proxy for safe-link scanning.
# When present, link mismatches and broken links are expected and benign.
GATEWAY_DOMAINS = {
    # Proofpoint URL Defense
    "urldefense.proofpoint.com",
    "urldefense.com",
    # Microsoft Safe Links
    "safelinks.protection.outlook.com",
    # Mimecast
    "protect-us.mimecast.com",
    "protect-eu.mimecast.com",
    "protect-au.mimecast.com",
    "protect.mimecast.com",
    # Barracuda
    "linkprotect.cudasvc.com",
    # ThreatDown / Malwarebytes
    "click.e.malwarebytes.com",
    "ep.threatdown.com",
    # Cisco Secure Email (IronPort)
    "secure-web.cisco.com",
    # Trend Micro
    "tmchecker.com",
    # FireEye / Trellix
    "fireeye.com",
    # Abnormal Security
    "abnormalsecurity.com",
    # Google Safe Browsing rewrites (in Workspace)
    "www.google.com/url",
}


def _is_gateway_url(url: str) -> bool:
    """Check if a URL is a corporate email gateway rewrite."""
    netloc = urlparse(url).netloc.lower()
    return any(gw in netloc for gw in GATEWAY_DOMAINS)


def _count_gateway_urls(urls: list[str]) -> int:
    """Count how many URLs are gateway-rewritten."""
    return sum(1 for u in urls if _is_gateway_url(u))


async def check_links(msg: EmailMessage) -> list[CheckResult]:
    results: list[CheckResult] = []
    html = get_html_body(msg)
    if not html:
        return results

    soup = BeautifulSoup(html, "html.parser")
    anchors = soup.find_all("a", href=True)
    urls = [a["href"] for a in anchors if a["href"].startswith("http")]

    if not urls:
        return results

    # Detect corporate email gateway URL rewriting
    gateway_count = _count_gateway_urls(urls)
    has_gateway = gateway_count > 0
    if has_gateway:
        # Identify which gateway
        gateway_names = set()
        for u in urls:
            netloc = urlparse(u).netloc.lower()
            if "proofpoint" in netloc:
                gateway_names.add("Proofpoint")
            elif "safelinks.protection.outlook" in netloc:
                gateway_names.add("Microsoft Safe Links")
            elif "mimecast" in netloc:
                gateway_names.add("Mimecast")
            elif "cudasvc" in netloc:
                gateway_names.add("Barracuda")
            elif "threatdown" in netloc or "malwarebytes" in netloc:
                gateway_names.add("ThreatDown/Malwarebytes")
            elif "cisco" in netloc:
                gateway_names.add("Cisco Secure Email")
            else:
                gateway_names.add("corporate email gateway")

        gw_label = ", ".join(sorted(gateway_names))
        results.append(
            CheckResult(
                name="EMAIL_GATEWAY",
                status=CheckStatus.PASS,
                score_delta=0.3,
                details=(
                    f"Email passed through {gw_label} safe-link protection "
                    f"({gateway_count} rewritten URL(s)). This is a legitimate "
                    f"enterprise security feature."
                ),
                extra={"gateways": sorted(gateway_names), "rewritten_count": gateway_count},
            )
        )

    # URL shorteners (skip gateway URLs)
    non_gateway_urls = [u for u in urls if not _is_gateway_url(u)]
    shortened = [u for u in non_gateway_urls if urlparse(u).netloc in SHORTENER_DOMAINS]
    if shortened:
        results.append(
            CheckResult(
                name="SHORTENED_URLS",
                status=CheckStatus.FAIL,
                score_delta=-0.5,
                details=f"Found {len(shortened)} shortened URL(s): {', '.join(shortened[:3])}",
            )
        )

    # Suspicious TLDs (skip gateway URLs)
    suspicious = [
        u for u in non_gateway_urls
        if any(urlparse(u).netloc.endswith(tld) for tld in SUSPICIOUS_TLDS)
    ]
    if suspicious:
        results.append(
            CheckResult(
                name="SUSPICIOUS_TLDS",
                status=CheckStatus.FAIL,
                score_delta=-0.5,
                details=f"Links to suspicious TLDs: {', '.join(suspicious[:3])}",
            )
        )

    # Display text vs href mismatch
    # When a gateway rewrites URLs, mismatches are EXPECTED (display shows
    # original URL, href is the gateway proxy).  Don't penalize.
    if not has_gateway:
        for a in anchors:
            href = a.get("href", "")
            text = a.get_text(strip=True)
            if text.startswith("http"):
                href_netloc = urlparse(href).netloc
                text_netloc = urlparse(text).netloc
                if href_netloc and text_netloc and href_netloc != text_netloc:
                    results.append(
                        CheckResult(
                            name="LINK_MISMATCH",
                            status=CheckStatus.FAIL,
                            score_delta=-1.0,
                            details=(
                                f"Display URL '{text[:60]}' does not match href "
                                f"'{href[:60]}'. This is a phishing indicator."
                            ),
                        )
                    )
                    break
    else:
        # Check for mismatches that are NOT gateway rewrites (real phishing
        # hidden behind gateway URLs is still possible but rare)
        for a in anchors:
            href = a.get("href", "")
            text = a.get_text(strip=True)
            if text.startswith("http") and not _is_gateway_url(href):
                href_netloc = urlparse(href).netloc
                text_netloc = urlparse(text).netloc
                if href_netloc and text_netloc and href_netloc != text_netloc:
                    results.append(
                        CheckResult(
                            name="LINK_MISMATCH",
                            status=CheckStatus.FAIL,
                            score_delta=-1.0,
                            details=(
                                f"Display URL '{text[:60]}' does not match href "
                                f"'{href[:60]}' (non-gateway link)."
                            ),
                        )
                    )
                    break

    # Never fetch email-derived URLs. Keep the static checks above, but make
    # the skipped reachability explicit so a result cannot imply validation.
    results.append(
        CheckResult(
            name="LINK_REACHABILITY_SKIPPED",
            status=CheckStatus.NONE,
            score_delta=0.0,
            details=LINK_ACCESS_NOTICE,
            extra={"reason": "hostile_email_content_policy"},
        )
    )

    return results
