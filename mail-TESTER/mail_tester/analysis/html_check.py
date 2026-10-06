from __future__ import annotations

from email.message import EmailMessage

from bs4 import BeautifulSoup

from mail_tester.email_utils import get_html_body, get_text_body
from mail_tester.models import CheckResult, CheckStatus


async def check_html(msg: EmailMessage) -> list[CheckResult]:
    results: list[CheckResult] = []

    html_body = get_html_body(msg)
    text_body = get_text_body(msg)

    if html_body is None and text_body is None:
        results.append(
            CheckResult(
                name="BODY",
                status=CheckStatus.FAIL,
                score_delta=-0.5,
                details="Email has no text or HTML body.",
            )
        )
        return results

    if html_body and not text_body:
        results.append(
            CheckResult(
                name="HTML_TEXT_RATIO",
                status=CheckStatus.FAIL,
                score_delta=-0.3,
                details="HTML email has no plain-text alternative. Many filters penalize this.",
            )
        )
    elif html_body and text_body:
        results.append(
            CheckResult(
                name="HTML_TEXT_RATIO",
                status=CheckStatus.PASS,
                score_delta=0.3,
                details="Email includes both HTML and plain-text parts.",
            )
        )

    if not html_body:
        return results

    soup = BeautifulSoup(html_body, "html.parser")

    # Image-to-text ratio
    images = soup.find_all("img")
    visible_text = soup.get_text(strip=True)
    if len(visible_text) < 50 and len(images) > 0:
        results.append(
            CheckResult(
                name="IMAGE_HEAVY",
                status=CheckStatus.FAIL,
                score_delta=-0.5,
                details=f"Email is image-heavy with minimal text ({len(visible_text)} chars, {len(images)} images).",
            )
        )

    # Broken image references
    for img in images:
        src = img.get("src", "")
        if src and not src.startswith(("http://", "https://", "cid:")):
            results.append(
                CheckResult(
                    name="BROKEN_IMAGE",
                    status=CheckStatus.FAIL,
                    score_delta=-0.2,
                    details=f"Image with non-resolvable src: {src[:80]}",
                )
            )
            break

    # Excessive inline CSS
    inline_style_count = len(soup.find_all(attrs={"style": True}))
    if inline_style_count > 50:
        results.append(
            CheckResult(
                name="EXCESSIVE_INLINE_CSS",
                status=CheckStatus.SOFTFAIL,
                score_delta=-0.2,
                details=f"Found {inline_style_count} elements with inline styles.",
            )
        )

    # Form elements
    forms = soup.find_all("form")
    if forms:
        results.append(
            CheckResult(
                name="FORM_IN_EMAIL",
                status=CheckStatus.FAIL,
                score_delta=-1.0,
                details=f"Email contains {len(forms)} form element(s). Most email clients block forms.",
            )
        )

    # JavaScript
    scripts = soup.find_all("script")
    if scripts:
        results.append(
            CheckResult(
                name="JAVASCRIPT",
                status=CheckStatus.FAIL,
                score_delta=-1.0,
                details="Email contains <script> tags. Email clients strip JavaScript.",
            )
        )

    return results
