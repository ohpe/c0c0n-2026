"""Shared DNS utilities.

Centralizes resolver creation and common DNS exception handling so that
analysis modules don't repeat the same 3-line setup and try/except blocks.
"""
from __future__ import annotations

import dns.asyncresolver
import dns.resolver

from mail_tester.config import settings

# DNS exceptions that indicate "no record" (not a transient error).
NO_RECORD_EXCEPTIONS = (
    dns.resolver.NXDOMAIN,
    dns.resolver.NoAnswer,
    dns.resolver.NoNameservers,
    dns.resolver.LifetimeTimeout,
)


def make_resolver(timeout: float | None = None) -> dns.asyncresolver.Resolver:
    """Create a configured async DNS resolver.

    Uses the application-wide DNS resolver address and the given timeout
    (defaults to ``settings.dnsbl_timeout`` which is 3s, but callers should
    pass an explicit timeout when they need something different).
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = [settings.dns_resolver]
    resolver.lifetime = timeout if timeout is not None else 5.0
    return resolver


async def resolve_txt(
    domain: str,
    resolver: dns.asyncresolver.Resolver | None = None,
) -> list[str]:
    """Resolve TXT records for *domain*, returning decoded strings.

    Returns an empty list if the domain has no TXT records or DNS fails.
    """
    if resolver is None:
        resolver = make_resolver()
    try:
        answers = await resolver.resolve(domain, "TXT")
        return [
            b"".join(rdata.strings).decode("ascii", errors="replace")
            for rdata in answers
        ]
    except NO_RECORD_EXCEPTIONS:
        return []
    except Exception:
        return []
