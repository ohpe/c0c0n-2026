from __future__ import annotations

import ipaddress

import dns.asyncresolver
import dns.resolver
import dns.reversename

from mail_tester.dns_utils import make_resolver, NO_RECORD_EXCEPTIONS
from mail_tester.models import CheckResult, CheckStatus


async def check_rdns(client_ip: str | None) -> CheckResult:
    """Check if the sending IP has a valid PTR (reverse DNS) record."""
    if not client_ip:
        return CheckResult(
            name="RDNS",
            status=CheckStatus.NONE,
            score_delta=0.0,
            details="No client IP available; reverse DNS check skipped.",
        )

    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return CheckResult(
            name="RDNS",
            status=CheckStatus.ERROR,
            score_delta=0.0,
            details=f"Invalid IP address: {client_ip}",
        )

    # Skip loopback
    if addr.is_loopback:
        return CheckResult(
            name="RDNS",
            status=CheckStatus.NONE,
            score_delta=0.0,
            details="Loopback address; reverse DNS check skipped.",
        )

    resolver = make_resolver()

    try:
        rev_name = dns.reversename.from_address(client_ip)
        answers = await resolver.resolve(rev_name, "PTR")
        ptr_records = [r.to_text().rstrip(".") for r in answers]
    except NO_RECORD_EXCEPTIONS:
        return CheckResult(
            name="RDNS",
            status=CheckStatus.FAIL,
            score_delta=-0.5,
            details=f"No PTR record found for {client_ip}. Mail servers without rDNS are often rejected.",
        )
    except Exception as exc:
        return CheckResult(
            name="RDNS",
            status=CheckStatus.ERROR,
            score_delta=0.0,
            details=f"rDNS lookup error for {client_ip}: {exc}",
        )

    if not ptr_records:
        return CheckResult(
            name="RDNS",
            status=CheckStatus.FAIL,
            score_delta=-0.5,
            details=f"No PTR record found for {client_ip}.",
        )

    # Verify forward-confirmed reverse DNS (FCrDNS):
    # The PTR hostname should resolve back to the original IP.
    hostname = ptr_records[0]
    rdtype = "A" if isinstance(addr, ipaddress.IPv4Address) else "AAAA"
    try:
        fwd_answers = await resolver.resolve(hostname, rdtype)
        fwd_ips = {r.to_text() for r in fwd_answers}
    except Exception:
        fwd_ips = set()

    if client_ip in fwd_ips:
        return CheckResult(
            name="RDNS",
            status=CheckStatus.PASS,
            score_delta=0.5,
            details=f"PTR record for {client_ip} is {hostname} (forward-confirmed).",
            extra={"ptr": hostname, "fcrdns": True},
        )
    else:
        return CheckResult(
            name="RDNS",
            status=CheckStatus.SOFTFAIL,
            score_delta=-0.2,
            details=f"PTR record for {client_ip} is {hostname}, but forward lookup doesn't match (no FCrDNS).",
            extra={"ptr": hostname, "fcrdns": False},
        )
