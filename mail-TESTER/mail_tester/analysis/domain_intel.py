"""Domain intelligence gathering.

Investigates the sender domain and link domains to provide context for
the LLM analysis.  Checks domain redirects, typosquatting/homoglyphs,
and relationships between the From domain and the domains found in the
email body.

Key defense: when a sender domain redirects to a brand, we check whether
the sender domain is a *lookalike* of that brand.  A lookalike domain that
redirects to the real brand is a classic phishing setup, not a legitimacy
signal.
"""
from __future__ import annotations

import logging
from urllib.parse import urlparse

from mail_tester.email_utils import extract_domain
from mail_tester.analysis.network_policy import LINK_ACCESS_NOTICE
from mail_tester.models import CheckResult

logger = logging.getLogger(__name__)

# ── Homoglyph / typosquatting maps ────────────────────────────────

# Characters that look alike across scripts + common keyboard typos
_HOMOGLYPHS: dict[str, str] = {
    "0": "o", "1": "l", "l": "i", "rn": "m",
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
}

# Common typosquatting patterns
_TYPO_PATTERNS = [
    # Single edit (substitution, insertion, deletion): gogle.com, googke.com
    lambda a, b: _edit_distance(a, b) == 1,
    # Adjacent character transposition: googel.com -> google.com
    lambda a, b: _edit_distance(a, b) == 2 and len(a) == len(b) and _has_transposition(a, b),
    # Double/triple char: gooogle.com
    lambda a, b: _deduplicate_runs(a) == _deduplicate_runs(b) and a != b,
    # Hyphen inserted WITHIN the brand: g-oogle.com (but NOT brand-suffix.com)
    lambda a, b: a.replace("-", "") == b and "-" in a,
]


def _edit_distance(a: str, b: str) -> int:
    """Levenshtein distance (good enough for short domain labels)."""
    if len(a) < len(b):
        return _edit_distance(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost))
        prev = curr
    return prev[len(b)]


def _deduplicate_runs(s: str) -> str:
    """Collapse repeated characters: 'gooogle' -> 'gogle'."""
    if not s:
        return s
    result = [s[0]]
    for c in s[1:]:
        if c != result[-1]:
            result.append(c)
    return "".join(result)


def _has_transposition(a: str, b: str) -> bool:
    """Check if a and b differ by exactly one adjacent-char swap."""
    if len(a) != len(b):
        return False
    diffs = [i for i in range(len(a)) if a[i] != b[i]]
    if len(diffs) == 2 and diffs[1] - diffs[0] == 1:
        return a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]
    return False


def _normalize_homoglyphs(domain: str) -> str:
    """Replace known homoglyphs with their ASCII equivalents."""
    result = domain
    for glyph, replacement in _HOMOGLYPHS.items():
        result = result.replace(glyph, replacement)
    return result


def _extract_base_domain(domain: str) -> str:
    """Strip www. and extract the registrable-ish part (label before TLD)."""
    d = domain.lower().removeprefix("www.")
    parts = d.split(".")
    # Return everything except TLD (last part, or last 2 for co.uk etc.)
    if len(parts) >= 3 and len(parts[-2]) <= 3:
        return ".".join(parts[:-2])
    if len(parts) >= 2:
        return parts[-2]
    return d


def is_typosquat(suspect: str, target: str) -> tuple[bool, str]:
    """Check if *suspect* is a typosquat/homoglyph of *target*.

    Returns (is_lookalike, reason).
    """
    s_base = _extract_base_domain(suspect.lower())
    t_base = _extract_base_domain(target.lower())

    if s_base == t_base:
        return False, ""

    # Homoglyph normalization
    s_norm = _normalize_homoglyphs(s_base)
    t_norm = _normalize_homoglyphs(t_base)
    if s_norm == t_norm and s_base != t_base:
        return True, f"Homoglyph attack: '{suspect}' uses lookalike characters to mimic '{target}'"

    # Typosquatting patterns
    for pattern_fn in _TYPO_PATTERNS:
        try:
            if pattern_fn(s_base, t_base):
                return True, f"Typosquatting: '{suspect}' is suspiciously similar to '{target}'"
        except Exception:
            continue

    # Check if the suspect contains the target brand name with extras
    # e.g., google-privacy.com contains "google" but isn't google.com
    if t_base in s_base and s_base != t_base and len(t_base) >= 4:
        # This is the tricky case: could be legitimate (apollo-privacy.com for apollo.io)
        # or malicious (google-security.com pretending to be google.com)
        # We flag it as "contains brand" but don't auto-classify -- let the LLM decide
        return False, ""

    return False, ""


# ── Main intelligence gathering ───────────────────────────────────


async def gather_domain_intel(
    sender_domain: str,
    link_checks: list[CheckResult],
    msg_headers: dict[str, str],
    html_body: str | None,
) -> dict:
    """Gather intelligence about the sender domain and linked domains."""
    intel: dict = {
        "sender_domain": sender_domain,
        "sender_redirect": None,
        "sender_redirect_domain": None,
        "is_lookalike": False,
        "lookalike_reason": "",
        "reply_to_domain": None,
        "return_path_domain": None,
        "link_domains": [],
        "domain_relationships": [],
    }

    if not sender_domain:
        return intel

    # Never browse to a sender or link domain. Static domain analysis below
    # remains available, while redirect intelligence is explicitly skipped.
    intel["domain_relationships"].append(
        f"Sender-domain website redirect check skipped. {LINK_ACCESS_NOTICE}"
    )

    # Extract Reply-To and Return-Path domains
    reply_to = msg_headers.get("Reply-To", "") or msg_headers.get("reply-to", "")
    if reply_to:
        rt_domain = extract_domain(reply_to)
        if rt_domain and rt_domain.lower() != sender_domain.lower():
            intel["reply_to_domain"] = rt_domain
            intel["domain_relationships"].append(
                f"Reply-To domain ({rt_domain}) differs from sender ({sender_domain})"
            )

    return_path = msg_headers.get("Return-Path", "") or msg_headers.get("return-path", "")
    if return_path:
        rp_domain = extract_domain(return_path)
        if rp_domain and rp_domain.lower() != sender_domain.lower():
            intel["return_path_domain"] = rp_domain
            intel["domain_relationships"].append(
                f"Return-Path domain ({rp_domain}) differs from sender ({sender_domain})"
            )

    # Collect unique link domains from the email body
    if html_body:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_body, "html.parser")
        link_domains: set[str] = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("http"):
                ld = urlparse(href).netloc
                if ld:
                    link_domains.add(ld.lower())
        intel["link_domains"] = sorted(link_domains)

        # Check relationships between sender and link domains
        for ld in link_domains:
            if sender_domain.lower() not in ld and ld not in sender_domain.lower():
                if (
                    intel["sender_redirect_domain"]
                    and _domains_related(intel["sender_redirect_domain"], ld)
                ):
                    if intel["is_lookalike"]:
                        intel["domain_relationships"].append(
                            f"Link domain {ld} matches the redirect target "
                            f"({intel['sender_redirect_domain']}), but the sender domain "
                            f"is a LOOKALIKE -- links pointing to the real brand is exactly "
                            f"what a phishing email would do"
                        )
                    else:
                        intel["domain_relationships"].append(
                            f"Link domain {ld} matches sender redirect target "
                            f"({intel['sender_redirect_domain']}) -- likely same organization"
                        )

                # Also check if any link domain is a typosquat of the sender's redirect
                if intel["sender_redirect_domain"]:
                    link_lookalike, link_reason = is_typosquat(ld, intel["sender_redirect_domain"])
                    if link_lookalike:
                        intel["domain_relationships"].append(
                            f"WARNING: Link {ld} is a lookalike of {intel['sender_redirect_domain']}: {link_reason}"
                        )

    return intel


def _domains_related(domain_a: str, domain_b: str) -> bool:
    """Check if two domains share the same base."""
    a = domain_a.lower().removeprefix("www.")
    b = domain_b.lower().removeprefix("www.")
    return a == b or a.endswith(f".{b}") or b.endswith(f".{a}")


def format_intel_for_llm(intel: dict) -> str:
    """Format domain intelligence into a text block for the LLM prompt."""
    lines: list[str] = []

    if intel.get("is_lookalike"):
        lines.append(
            f"- CRITICAL: {intel['lookalike_reason']}"
        )
        lines.append(
            f"- The sender domain redirects to {intel['sender_redirect']} "
            f"but this is likely a PHISHING SETUP using a lookalike domain"
        )
    elif intel.get("sender_redirect"):
        lines.append(
            f"- Sender domain ({intel['sender_domain']}) website redirects to: "
            f"{intel['sender_redirect']}"
        )

    if intel.get("reply_to_domain"):
        lines.append(
            f"- Reply-To uses a different domain: {intel['reply_to_domain']}"
        )

    if intel.get("return_path_domain"):
        lines.append(
            f"- Return-Path uses a different domain: {intel['return_path_domain']}"
        )

    if intel.get("link_domains"):
        lines.append(
            f"- Domains found in email links (static extraction only; not visited): {', '.join(intel['link_domains'])}"
        )

    for rel in intel.get("domain_relationships", []):
        lines.append(f"- {rel}")

    if not lines:
        lines.append("- No notable domain intelligence findings.")

    return "\n".join(lines)
