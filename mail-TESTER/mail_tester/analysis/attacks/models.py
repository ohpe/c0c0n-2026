"""Shared data classes for the attack surface analysis."""
from __future__ import annotations

from dataclasses import dataclass

from mail_tester.models import CheckResult, CheckStatus


@dataclass
class Finding:
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    exploit: str
    remediation: str


@dataclass
class Posture:
    """Security posture of the domain -- used to contextualize findings."""

    has_spf: bool = False
    spf_qualifier: str = ""  # -all, ~all, ?all, +all
    has_dkim: bool = False  # DKIM signature present (even if invalid in .eml)
    dkim_valid_at_delivery: bool = False
    has_dmarc: bool = False
    dmarc_policy: str = "none"  # none, quarantine, reject
    dmarc_sp: str = "none"
    dmarc_adkim: str = "r"  # r=relaxed, s=strict
    dmarc_aspf: str = "r"
    dmarc_pct: int = 100

    @property
    def dmarc_enforcing(self) -> bool:
        """True if DMARC actively blocks failed emails."""
        return (
            self.has_dmarc
            and self.dmarc_policy in ("quarantine", "reject")
            and self.dmarc_pct >= 90
        )

    @property
    def dkim_blocks_spf_abuse(self) -> bool:
        """True if DMARC+DKIM strict alignment means SPF abuse alone won't work."""
        return self.dmarc_enforcing and self.dmarc_adkim == "s"

    @property
    def spf_abuse_requires_alignment(self) -> bool:
        """True if exploiting SPF includes also requires DMARC alignment."""
        return self.dmarc_enforcing


def get_check(checks: list[CheckResult], name: str) -> CheckResult | None:
    """Look up a check by name in a results list."""
    for c in checks:
        if c.name == name:
            return c
    return None


def parse_dmarc_tags(record: str) -> dict[str, str]:
    """Parse semicolon-delimited DMARC tags into a dict."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def build_posture(checks: list[CheckResult]) -> Posture:
    """Build a ``Posture`` from a list of check results."""
    posture = Posture()

    spf = get_check(checks, "SPF")
    if spf and spf.status != CheckStatus.NONE:
        posture.has_spf = True
        if spf.record:
            for suffix in ("-all", "~all", "?all", "+all"):
                if spf.record.rstrip().endswith(suffix):
                    posture.spf_qualifier = suffix
                    break

    dkim = get_check(checks, "DKIM")
    if dkim and dkim.status != CheckStatus.NONE:
        posture.has_dkim = True

    orig_dkim = get_check(checks, "ORIGINAL_DKIM")
    if orig_dkim and orig_dkim.status == CheckStatus.PASS:
        posture.dkim_valid_at_delivery = True
        posture.has_dkim = True

    dmarc = get_check(checks, "DMARC")
    if dmarc and dmarc.record:
        posture.has_dmarc = True
        tags = parse_dmarc_tags(dmarc.record)
        posture.dmarc_policy = tags.get("p", "none")
        posture.dmarc_sp = tags.get("sp", posture.dmarc_policy)
        posture.dmarc_adkim = tags.get("adkim", "r")
        posture.dmarc_aspf = tags.get("aspf", "r")
        try:
            posture.dmarc_pct = int(tags.get("pct", "100"))
        except ValueError:
            posture.dmarc_pct = 100

    return posture
