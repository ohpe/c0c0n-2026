from __future__ import annotations

from email.message import EmailMessage

from mail_tester.email_utils import get_body_text
from mail_tester.models import CheckResult, CheckStatus

SPAM_KEYWORDS = [
    "viagra", "casino", "winner", "congratulations", "click here now",
    "urgent action", "$$$", "act now", "limited time", "free gift",
    "no obligation", "double your", "earn money", "work from home",
]

MAX_KEYWORD_PENALTY = -2.0


async def check_spam_content(msg: EmailMessage) -> CheckResult:
    body = get_body_text(msg)
    body_lower = body.lower()

    penalties: list[tuple[float, str]] = []
    bonuses: list[tuple[float, str]] = []

    # Spam keywords
    found = [kw for kw in SPAM_KEYWORDS if kw in body_lower]
    if found:
        penalty = max(-0.3 * len(found), MAX_KEYWORD_PENALTY)
        penalties.append((penalty, f"Spam keywords found: {', '.join(found[:5])}"))

    # Excessive caps
    if len(body) > 20:
        caps_count = sum(1 for c in body if c.isupper())
        caps_ratio = caps_count / len(body)
        if caps_ratio > 0.3:
            penalties.append((-0.5, f"Excessive capitals ({caps_ratio:.0%} of text)"))

    # Excessive exclamation marks
    excl_count = body.count("!")
    if excl_count > 5:
        penalties.append((-0.3, f"Too many exclamation marks ({excl_count})"))

    # Missing standard headers
    missing = []
    for h in ["Message-ID", "Date", "MIME-Version"]:
        if msg.get(h) is None:
            missing.append(h)
    if missing:
        penalties.append((-0.3, f"Missing headers: {', '.join(missing)}"))

    # List-Unsubscribe (good practice)
    if msg.get("List-Unsubscribe"):
        bonuses.append((0.3, "Has List-Unsubscribe header"))

    total_delta = sum(p[0] for p in penalties) + sum(b[0] for b in bonuses)
    all_details = [f"{d} ({s:+.1f})" for s, d in penalties + bonuses]

    status = CheckStatus.PASS if total_delta >= 0 else CheckStatus.FAIL

    return CheckResult(
        name="CONTENT",
        status=status,
        score_delta=total_delta,
        details="; ".join(all_details) if all_details else "No spam indicators detected.",
    )
