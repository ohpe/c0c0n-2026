"""Parse Authentication-Results and ARC headers from the email.

These headers are added by the receiving MTA at delivery time and represent
the *actual* authentication outcome the mail server saw. They're the ground
truth, whereas our own SPF/DKIM checks re-evaluate from the stored .eml
(which may have been modified after delivery).
"""
from __future__ import annotations

import re
from email.message import EmailMessage

from mail_tester.models import CheckResult, CheckStatus


def _parse_authresults(header: str) -> dict[str, dict]:
    """Parse an Authentication-Results header into a dict of method -> result.

    Example input:
      spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=example.com;
      dkim=pass header.d=example.com; dmarc=pass

    Returns: {'spf': {'result': 'pass', 'detail': '...'}, ...}
    """
    results: dict[str, dict] = {}
    # Split on semicolons, each part is one method result
    parts = re.split(r"\s*;\s*", header)
    for part in parts:
        part = part.strip()
        # Match: method=result
        match = re.match(r"(\w+)\s*=\s*(\w+)(.*)", part)
        if match:
            method = match.group(1).lower()
            result = match.group(2).lower()
            rest = match.group(3).strip()
            # If we already have this method (e.g. multiple dkim), use first
            if method not in results:
                results[method] = {"result": result, "detail": rest}
    return results


async def check_auth_results(msg: EmailMessage) -> list[CheckResult]:
    """Extract and report what the receiving mail server saw at delivery time."""
    results: list[CheckResult] = []

    # Authentication-Results header
    auth_header = msg.get("Authentication-Results")
    if auth_header:
        parsed = _parse_authresults(auth_header)

        for method in ["spf", "dkim", "dmarc"]:
            if method in parsed:
                entry = parsed[method]
                result_str = entry["result"]
                detail = entry.get("detail", "")

                # Map to our status (informational only, no score impact)
                status_map = {
                    "pass": CheckStatus.PASS,
                    "fail": CheckStatus.FAIL,
                    "softfail": CheckStatus.SOFTFAIL,
                    "neutral": CheckStatus.NEUTRAL,
                    "none": CheckStatus.NONE,
                    "temperror": CheckStatus.TEMPERROR,
                    "permerror": CheckStatus.PERMERROR,
                }
                status = status_map.get(result_str, CheckStatus.NONE)

                results.append(CheckResult(
                    name=f"ORIGINAL_{method.upper()}",
                    status=status,
                    score_delta=0.0,  # Informational only
                    details=f"At delivery: {method.upper()}={result_str} {detail}".strip(),
                    extra={"method": method, "result": result_str, "source": "Authentication-Results"},
                ))

    # Received-SPF header (alternative source)
    received_spf = msg.get("Received-SPF")
    if received_spf and "ORIGINAL_SPF" not in {r.name for r in results}:
        # Parse "Pass (detail...)" or "Fail (detail...)"
        match = re.match(r"(\w+)\s*(.*)", received_spf.strip())
        if match:
            result_str = match.group(1).lower()
            detail = match.group(2).strip()[:150]
            status_map = {
                "pass": CheckStatus.PASS,
                "fail": CheckStatus.FAIL,
                "softfail": CheckStatus.SOFTFAIL,
                "neutral": CheckStatus.NEUTRAL,
                "none": CheckStatus.NONE,
            }
            results.append(CheckResult(
                name="ORIGINAL_SPF",
                status=status_map.get(result_str, CheckStatus.NONE),
                score_delta=0.0,
                details=f"At delivery: SPF={result_str} {detail}",
                extra={"method": "spf", "result": result_str, "source": "Received-SPF"},
            ))

    # ARC headers
    arc_results = msg.get_all("ARC-Authentication-Results") or []
    arc_seals = msg.get_all("ARC-Seal") or []

    if arc_seals:
        # Count ARC hops
        hop_count = len(arc_seals)
        # Get the latest ARC-Authentication-Results
        latest_arc = arc_results[0] if arc_results else ""
        arc_parsed = _parse_authresults(latest_arc) if latest_arc else {}

        arc_summary_parts = []
        for method in ["spf", "dkim", "dmarc"]:
            if method in arc_parsed:
                arc_summary_parts.append(f"{method}={arc_parsed[method]['result']}")

        summary = ", ".join(arc_summary_parts) if arc_summary_parts else "present but no results parsed"

        results.append(CheckResult(
            name="ARC",
            status=CheckStatus.PASS if arc_seals else CheckStatus.NONE,
            score_delta=0.0,  # Informational
            details=f"ARC chain with {hop_count} hop(s). Latest results: {summary}",
            extra={"hops": hop_count, "results": arc_parsed},
        ))

    if not results:
        results.append(CheckResult(
            name="ORIGINAL_AUTH",
            status=CheckStatus.NONE,
            score_delta=0.0,
            details="No Authentication-Results or ARC headers found in the email.",
        ))

    return results
