from __future__ import annotations

from mail_tester.dns_utils import make_resolver, NO_RECORD_EXCEPTIONS
from mail_tester.models import CheckResult, CheckStatus


def _parse_dmarc(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def _org_domain(domain: str) -> str:
    """Approximate organizational domain (last two labels)."""
    parts = domain.rstrip(".").split(".")
    if len(parts) <= 2:
        return domain.rstrip(".")
    return ".".join(parts[-2:])


def _domains_align(from_domain: str, auth_domain: str, strict: bool) -> bool:
    from_domain = from_domain.rstrip(".").lower()
    auth_domain = auth_domain.rstrip(".").lower()
    if strict:
        return from_domain == auth_domain
    return _org_domain(from_domain) == _org_domain(auth_domain)


async def check_dmarc(
    from_domain: str,
    spf_result: CheckResult,
    dkim_result: CheckResult,
) -> CheckResult:
    resolver = make_resolver()

    dmarc_record = None
    try:
        answers = await resolver.resolve(f"_dmarc.{from_domain}", "TXT")
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("ascii", errors="replace")
            if txt.lower().startswith("v=dmarc1"):
                dmarc_record = txt
                break
    except NO_RECORD_EXCEPTIONS:
        pass
    except Exception as exc:
        return CheckResult(
            name="DMARC",
            status=CheckStatus.TEMPERROR,
            score_delta=-0.5,
            details=f"DNS error querying DMARC for {from_domain}: {exc}",
        )

    if not dmarc_record:
        return CheckResult(
            name="DMARC",
            status=CheckStatus.NONE,
            score_delta=-1.0,
            details=f"No DMARC record found for {from_domain}.",
        )

    policy = _parse_dmarc(dmarc_record)
    p = policy.get("p", "none")
    adkim = policy.get("adkim", "r")
    aspf = policy.get("aspf", "r")

    spf_aligned = (
        spf_result.status == CheckStatus.PASS
        and _domains_align(
            from_domain,
            spf_result.extra.get("domain", ""),
            strict=(aspf == "s"),
        )
    )
    dkim_aligned = (
        dkim_result.status == CheckStatus.PASS
        and _domains_align(
            from_domain,
            dkim_result.extra.get("domain", ""),
            strict=(adkim == "s"),
        )
    )

    dmarc_pass = spf_aligned or dkim_aligned

    if dmarc_pass:
        score_map = {"reject": 2.0, "quarantine": 1.5, "none": 1.0}
        return CheckResult(
            name="DMARC",
            status=CheckStatus.PASS,
            score_delta=score_map.get(p, 1.0),
            details=f"DMARC passes (policy={p}, SPF aligned={spf_aligned}, DKIM aligned={dkim_aligned}).",
            record=dmarc_record,
            extra={"policy": p, "spf_aligned": spf_aligned, "dkim_aligned": dkim_aligned},
        )
    else:
        score_map = {"reject": -2.0, "quarantine": -1.5, "none": -0.5}
        return CheckResult(
            name="DMARC",
            status=CheckStatus.FAIL,
            score_delta=score_map.get(p, -0.5),
            details=f"DMARC fails (policy={p}, SPF aligned={spf_aligned}, DKIM aligned={dkim_aligned}).",
            record=dmarc_record,
            extra={"policy": p, "spf_aligned": spf_aligned, "dkim_aligned": dkim_aligned},
        )
