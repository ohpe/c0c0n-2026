from __future__ import annotations

import asyncio
import email
import email.policy
import re

import dkim

from mail_tester.models import CheckResult, CheckStatus


def _extract_dkim_tag(header_value: str, tag: str) -> str | None:
    pattern = rf"(?:^|;)\s*{tag}\s*=\s*([^;]+)"
    match = re.search(pattern, header_value)
    if match:
        return match.group(1).strip()
    return None


async def check_dkim(raw_eml: bytes) -> CheckResult:
    msg = email.message_from_bytes(raw_eml, policy=email.policy.default)
    dkim_header = msg.get("DKIM-Signature")

    if not dkim_header:
        return CheckResult(
            name="DKIM",
            status=CheckStatus.NONE,
            score_delta=-1.0,
            details="No DKIM-Signature header found in the email.",
        )

    d_domain = _extract_dkim_tag(dkim_header, "d") or "unknown"
    selector = _extract_dkim_tag(dkim_header, "s") or "unknown"

    loop = asyncio.get_running_loop()
    try:
        # 15-second timeout prevents hanging on malformed DKIM or slow DNS
        is_valid = await asyncio.wait_for(
            loop.run_in_executor(None, dkim.verify, raw_eml),
            timeout=15.0,
        )
    except asyncio.TimeoutError:
        return CheckResult(
            name="DKIM",
            status=CheckStatus.ERROR,
            score_delta=-0.5,
            details=f"DKIM verification timed out (d={d_domain}, s={selector}).",
            extra={"domain": d_domain, "selector": selector},
        )
    except Exception as exc:
        return CheckResult(
            name="DKIM",
            status=CheckStatus.ERROR,
            score_delta=-0.5,
            details=f"DKIM verification error: {exc}",
            extra={"domain": d_domain, "selector": selector},
        )

    if is_valid:
        return CheckResult(
            name="DKIM",
            status=CheckStatus.PASS,
            score_delta=1.5,
            details=f"DKIM signature valid (d={d_domain}, s={selector}).",
            extra={"domain": d_domain, "selector": selector},
        )
    else:
        return CheckResult(
            name="DKIM",
            status=CheckStatus.FAIL,
            score_delta=-1.5,
            details=f"DKIM signature INVALID (d={d_domain}, s={selector}).",
            extra={"domain": d_domain, "selector": selector},
        )
