from __future__ import annotations

import ipaddress

from mail_tester.config import settings
from mail_tester.dns_utils import make_resolver, NO_RECORD_EXCEPTIONS
from mail_tester.models import CheckResult, CheckStatus

DNSBL_ZONES = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "cbl.abuseat.org",
    "b.barracudacentral.org",
]


async def check_blacklists(client_ip: str | None) -> CheckResult:
    if not client_ip:
        return CheckResult(
            name="DNSBL",
            status=CheckStatus.NONE,
            score_delta=0.0,
            details="No client IP available; blacklist check skipped.",
        )

    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return CheckResult(
            name="DNSBL",
            status=CheckStatus.ERROR,
            score_delta=0.0,
            details=f"Invalid IP address: {client_ip}",
        )

    if not isinstance(addr, ipaddress.IPv4Address):
        return CheckResult(
            name="DNSBL",
            status=CheckStatus.NONE,
            score_delta=0.0,
            details="DNSBL check only supports IPv4 addresses.",
        )

    reversed_ip = ".".join(reversed(client_ip.split(".")))
    resolver = make_resolver(timeout=settings.dnsbl_timeout)

    listed_on: list[str] = []

    for zone in DNSBL_ZONES:
        query = f"{reversed_ip}.{zone}"
        try:
            await resolver.resolve(query, "A")
            listed_on.append(zone)
        except NO_RECORD_EXCEPTIONS:
            pass
        except Exception:
            pass

    if listed_on:
        return CheckResult(
            name="DNSBL",
            status=CheckStatus.FAIL,
            score_delta=-1.5,
            details=f"IP {client_ip} is listed on: {', '.join(listed_on)}",
            extra={"listed_on": listed_on},
        )
    else:
        return CheckResult(
            name="DNSBL",
            status=CheckStatus.PASS,
            score_delta=0.5,
            details=f"IP {client_ip} is not listed on any of {len(DNSBL_ZONES)} checked blacklists.",
        )
