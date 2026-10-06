from __future__ import annotations

import ipaddress

import dns.asyncresolver
import dns.resolver

from mail_tester.dns_utils import make_resolver, NO_RECORD_EXCEPTIONS
from mail_tester.models import CheckResult, CheckStatus

MAX_DNS_LOOKUPS = 10


async def check_spf(domain: str, client_ip: str | None) -> CheckResult:
    if not client_ip:
        return CheckResult(
            name="SPF",
            status=CheckStatus.NONE,
            score_delta=0.0,
            details="No client IP available (uploaded .eml); SPF cannot be verified.",
        )

    resolver = make_resolver()

    try:
        answers = await resolver.resolve(domain, "TXT")
    except NO_RECORD_EXCEPTIONS:
        return CheckResult(
            name="SPF",
            status=CheckStatus.NONE,
            score_delta=-1.0,
            details=f"No DNS TXT records found for {domain}.",
        )
    except Exception as exc:
        return CheckResult(
            name="SPF",
            status=CheckStatus.TEMPERROR,
            score_delta=-0.5,
            details=f"DNS error querying SPF for {domain}: {exc}",
        )

    spf_record = None
    for rdata in answers:
        txt = b"".join(rdata.strings).decode("ascii", errors="replace")
        if txt.startswith("v=spf1"):
            spf_record = txt
            break

    if not spf_record:
        return CheckResult(
            name="SPF",
            status=CheckStatus.NONE,
            score_delta=-1.0,
            details=f"No SPF record found for {domain}.",
        )

    lookup_count = {"n": 0}
    result = await _evaluate_spf(spf_record, client_ip, domain, resolver, lookup_count)

    score_map = {
        CheckStatus.PASS: 1.5,
        CheckStatus.NEUTRAL: 0.0,
        CheckStatus.SOFTFAIL: -0.5,
        CheckStatus.FAIL: -1.5,
        CheckStatus.NONE: -1.0,
        CheckStatus.PERMERROR: -1.0,
        CheckStatus.TEMPERROR: -0.5,
    }

    return CheckResult(
        name="SPF",
        status=result,
        score_delta=score_map.get(result, 0.0),
        details=_spf_detail(result, domain, client_ip),
        record=spf_record,
        extra={"domain": domain},
    )


def _spf_detail(status: CheckStatus, domain: str, ip: str) -> str:
    msgs = {
        CheckStatus.PASS: f"IP {ip} is authorized by {domain}'s SPF record.",
        CheckStatus.FAIL: f"IP {ip} is NOT authorized by {domain}'s SPF record.",
        CheckStatus.SOFTFAIL: f"IP {ip} soft-fails {domain}'s SPF record (~all).",
        CheckStatus.NEUTRAL: f"SPF result is neutral for IP {ip} on {domain}.",
        CheckStatus.PERMERROR: f"SPF record for {domain} has a permanent error (too many lookups or syntax error).",
        CheckStatus.TEMPERROR: f"Temporary DNS error evaluating SPF for {domain}.",
        CheckStatus.NONE: f"No SPF record found for {domain}.",
    }
    return msgs.get(status, f"SPF result: {status.value}")


async def _evaluate_spf(
    record: str,
    client_ip: str,
    domain: str,
    resolver: dns.asyncresolver.Resolver,
    lookup_count: dict,
    depth: int = 0,
) -> CheckStatus:
    if depth > 10:
        return CheckStatus.PERMERROR

    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return CheckStatus.PERMERROR

    tokens = record.split()[1:]  # skip "v=spf1"

    for token in tokens:
        # Parse qualifier
        qualifier = "+"
        mechanism = token
        if token[0] in "+-~?":
            qualifier = token[0]
            mechanism = token[1:]

        status_for_qualifier = {
            "+": CheckStatus.PASS,
            "-": CheckStatus.FAIL,
            "~": CheckStatus.SOFTFAIL,
            "?": CheckStatus.NEUTRAL,
        }

        # Handle mechanisms
        if mechanism == "all":
            return status_for_qualifier[qualifier]

        elif mechanism.startswith("ip4:"):
            network_str = mechanism[4:]
            if "/" not in network_str:
                network_str += "/32"
            try:
                network = ipaddress.ip_network(network_str, strict=False)
                if isinstance(addr, ipaddress.IPv4Address) and addr in network:
                    return status_for_qualifier[qualifier]
            except ValueError:
                continue

        elif mechanism.startswith("ip6:"):
            network_str = mechanism[4:]
            if "/" not in network_str:
                network_str += "/128"
            try:
                network = ipaddress.ip_network(network_str, strict=False)
                if isinstance(addr, ipaddress.IPv6Address) and addr in network:
                    return status_for_qualifier[qualifier]
            except ValueError:
                continue

        elif mechanism == "a" or mechanism.startswith("a:"):
            lookup_count["n"] += 1
            if lookup_count["n"] > MAX_DNS_LOOKUPS:
                return CheckStatus.PERMERROR
            target = mechanism[2:] if mechanism.startswith("a:") else domain
            if await _ip_matches_a(target, addr, resolver):
                return status_for_qualifier[qualifier]

        elif mechanism == "mx" or mechanism.startswith("mx:"):
            lookup_count["n"] += 1
            if lookup_count["n"] > MAX_DNS_LOOKUPS:
                return CheckStatus.PERMERROR
            target = mechanism[3:] if mechanism.startswith("mx:") else domain
            if await _ip_matches_mx(target, addr, resolver):
                return status_for_qualifier[qualifier]

        elif mechanism.startswith("include:"):
            lookup_count["n"] += 1
            if lookup_count["n"] > MAX_DNS_LOOKUPS:
                return CheckStatus.PERMERROR
            include_domain = mechanism[8:]
            try:
                answers = await resolver.resolve(include_domain, "TXT")
                for rdata in answers:
                    txt = b"".join(rdata.strings).decode("ascii", errors="replace")
                    if txt.startswith("v=spf1"):
                        sub_result = await _evaluate_spf(
                            txt, client_ip, include_domain, resolver, lookup_count, depth + 1
                        )
                        if sub_result == CheckStatus.PASS:
                            return status_for_qualifier[qualifier]
                        break
            except Exception:
                continue

        elif mechanism.startswith("redirect="):
            lookup_count["n"] += 1
            if lookup_count["n"] > MAX_DNS_LOOKUPS:
                return CheckStatus.PERMERROR
            redirect_domain = mechanism[9:]
            try:
                answers = await resolver.resolve(redirect_domain, "TXT")
                for rdata in answers:
                    txt = b"".join(rdata.strings).decode("ascii", errors="replace")
                    if txt.startswith("v=spf1"):
                        return await _evaluate_spf(
                            txt, client_ip, redirect_domain, resolver, lookup_count, depth + 1
                        )
            except Exception:
                return CheckStatus.PERMERROR

    return CheckStatus.NEUTRAL


async def _ip_matches_a(
    domain: str, addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    resolver: dns.asyncresolver.Resolver,
) -> bool:
    rdtype = "A" if isinstance(addr, ipaddress.IPv4Address) else "AAAA"
    try:
        answers = await resolver.resolve(domain, rdtype)
        return any(ipaddress.ip_address(r.to_text()) == addr for r in answers)
    except Exception:
        return False


async def _ip_matches_mx(
    domain: str, addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
    resolver: dns.asyncresolver.Resolver,
) -> bool:
    try:
        mx_answers = await resolver.resolve(domain, "MX")
        for mx in mx_answers:
            mx_host = mx.exchange.to_text().rstrip(".")
            if await _ip_matches_a(mx_host, addr, resolver):
                return True
    except Exception:
        pass
    return False
