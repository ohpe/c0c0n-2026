"""Deterministic technical analysis of email MIME content and headers.

This module deliberately keeps technical evidence separate from scoring checks. It
records observable parser/formatting anomalies for the dashboard and supplies a
bounded context block to an optional LLM, which can add interpretation without
being the source of the raw facts.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import email
import email.policy
import quopri
import re
from datetime import datetime
from email.message import EmailMessage
from email.utils import getaddresses, parsedate_to_datetime
from ipaddress import ip_address
from bs4 import BeautifulSoup

from mail_tester.models import HeaderEvidence, ReceivedHop, TechnicalFinding, TechnicalReport

_MAX_EVIDENCE = 3
_MAX_FINDINGS = 40
_MAX_HOPS = 20
_MAX_CONTEXT = 12_000
_INVENTORY_HEADERS = {
    "from", "to", "cc", "bcc", "reply-to", "return-path", "delivered-to",
    "subject", "date", "message-id", "in-reply-to", "references",
    "mime-version", "content-type", "content-transfer-encoding",
    "authentication-results", "received-spf", "arc-authentication-results",
    "arc-seal", "dkim-signature", "x-mailer", "user-agent", "x-priority",
    "importance", "list-unsubscribe",
}
_SINGLETON_HEADERS = {
    "date", "from", "message-id", "mime-version", "return-path", "subject", "to",
}
_ZERO_WIDTH_RE = re.compile(r"[​-‏‪-‮⁠﻿]")
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def _finding(
    area: str,
    category: str,
    severity: str,
    title: str,
    explanation: str,
    evidence: list[str] | None = None,
    reference: str | None = None,
) -> TechnicalFinding:
    return TechnicalFinding(
        area=area,
        category=category,
        severity=severity,
        title=title,
        explanation=explanation,
        evidence=[str(item)[:300] for item in (evidence or [])[:_MAX_EVIDENCE]],
        reference=reference,
    )


def _safe_payload(part: EmailMessage) -> str:
    payload = part.get_payload()
    return payload if isinstance(payload, str) else ""


def _decode_transfer_encoding(part: EmailMessage) -> tuple[bytes | None, str | None]:
    """Decode a leaf payload strictly enough to expose malformed encodings."""
    payload = _safe_payload(part)
    encoding = (part.get("Content-Transfer-Encoding") or "7bit").strip().lower()
    if encoding == "base64":
        compact = re.sub(r"\s+", "", payload)
        try:
            return base64.b64decode(compact, validate=True), None
        except (binascii.Error, ValueError):
            return None, "invalid base64 payload"
    if encoding == "quoted-printable":
        if re.search(r"=(?![0-9A-Fa-f]{2}|\\r?\\n|$)", payload):
            return None, "invalid quoted-printable escape"
        return quopri.decodestring(payload.encode("ascii", errors="replace")), None
    if encoding in {"7bit", "8bit", "binary", ""}:
        try:
            return payload.encode("ascii" if encoding == "7bit" else "utf-8"), None
        except UnicodeEncodeError:
            return None, "7bit payload contains non-ASCII characters"
    return None, f"unsupported transfer encoding: {encoding}"


def _decode_text(part: EmailMessage, decoded: bytes | None) -> str:
    if decoded is None:
        try:
            content = part.get_content()
            return content if isinstance(content, str) else ""
        except (LookupError, UnicodeError, ValueError):
            return ""
    charset = part.get_content_charset() or "ascii"
    try:
        return decoded.decode(charset, errors="strict")
    except LookupError:
        return decoded.decode("utf-8", errors="replace")
    except UnicodeError:
        return decoded.decode(charset, errors="replace")


def _max_mime_depth(msg: EmailMessage) -> int:
    """Compute multipart nesting depth with a hard traversal cap."""
    max_depth = 0
    stack: list[tuple[EmailMessage, int]] = [(msg, 0)]
    visited = 0
    while stack and visited < 200:
        part, depth = stack.pop()
        visited += 1
        max_depth = max(max_depth, depth)
        if part.is_multipart():
            stack.extend((child, depth + 1) for child in part.iter_parts())
    return max_depth


def _body_findings(msg: EmailMessage) -> list[TechnicalFinding]:
    findings: list[TechnicalFinding] = []
    parts = [part for part in msg.walk() if not part.is_multipart()][:100]
    max_depth = _max_mime_depth(msg)
    if max_depth >= 8:
        findings.append(_finding(
            "body", "mime", "medium" if max_depth < 15 else "high",
            "Deep MIME multipart nesting",
            "The MIME tree is unusually deep and may cause different parsers or gateways to stop inspecting inner parts. This is a structural indicator, not proof of maliciousness.",
            [f"maximum multipart depth: {max_depth}"], "RFC 2046",
        ))
    if not parts:
        findings.append(_finding(
            "body", "mime", "low", "No leaf MIME body part",
            "The message has no decodable leaf body part to inspect.",
            reference="RFC 2045",
        ))
        return findings

    if len(parts) > 1:
        structure = ", ".join(
            f"{part.get_content_type()} ({part.get('Content-Transfer-Encoding', '7bit')})"
            for part in parts[:8]
        )
        findings.append(_finding(
            "body", "mime", "info", "Multipart body structure",
            "The message contains multiple leaf MIME parts; compare their rendered content because filters may inspect different representations.",
            [structure], "RFC 2046",
        ))

    rendered_text: list[str] = []
    html_payloads: list[str] = []
    attachment_parts = [part for part in msg.walk() if part.get_content_disposition() == "attachment"]
    attachment_names = [str(part.get_filename() or "").strip() for part in attachment_parts]
    nonempty_names = [name for name in attachment_names if name]
    if len(nonempty_names) != len(set(nonempty_names)) and nonempty_names:
        findings.append(_finding(
            "body", "attachment", "medium", "Duplicate attachment filenames",
            "Multiple attachment parts use the same filename. This can cause user-interface ambiguity and parser/gateway differences; payloads were not opened.",
            [", ".join(nonempty_names[:_MAX_EVIDENCE])], "MIME Content-Disposition",
        ))
    for index, part in enumerate(parts, start=1):
        transfer_encoding = (part.get("Content-Transfer-Encoding") or "7bit").lower()
        payload = _safe_payload(part)
        decoded, decode_error = _decode_transfer_encoding(part)
        label = f"part {index} ({part.get_content_type()}, {transfer_encoding})"
        if decode_error:
            findings.append(_finding(
                "body", "encoding", "medium", "Malformed MIME transfer encoding",
                "The declared transfer encoding cannot be decoded strictly. This can cause different filters and mail clients to inspect different bytes.",
                [f"{label}: {decode_error}"], "RFC 2045 §6",
            ))
        if transfer_encoding == "7bit" and any(ord(char) > 127 for char in payload):
            findings.append(_finding(
                "body", "encoding", "medium", "7bit payload contains non-ASCII data",
                "The payload declares 7bit transport but includes non-ASCII characters, which is an RFC/MIME consistency problem.",
                [label], "RFC 2045 §6.2",
            ))

        charset = part.get_content_charset()
        if charset:
            try:
                codecs.lookup(charset)
            except LookupError:
                findings.append(_finding(
                    "body", "charset", "medium", "Unknown declared charset",
                    "The MIME part declares a charset that Python cannot resolve; rendering and filtering may diverge.",
                    [f"{label}: charset={charset}"], "RFC 2045 §5.2",
                ))
        text = _decode_text(part, decoded)
        if "�" in text:
            findings.append(_finding(
                "body", "charset", "low", "Replacement characters after decoding",
                "Character replacement markers appeared while decoding a body part, suggesting a charset or byte mismatch.",
                [label], "RFC 2045 §5.2",
            ))
        if part.get_content_maintype() == "text":
            rendered_text.append(text)
        if part.get_content_type() == "text/html":
            html_payloads.append(text)

    plain_text = "\n".join(rendered_text)
    html_text = "\n".join(html_payloads)
    raw_html_bytes = len(html_text.encode("utf-8", errors="replace"))
    if html_text:
        soup = BeautifulSoup(html_text, "html.parser")
        hidden = soup.select('[style*="display:none"], [style*="display: none"], [style*="visibility:hidden"], [style*="visibility: hidden"]')
        hidden_text = " ".join(node.get_text(" ", strip=True) for node in hidden)
        hidden_style = re.findall(r"font-size\s*:\s*0(?:px|pt)?", html_text, flags=re.IGNORECASE)
        fixed_heights = re.findall(r"(?:height|min-height)\s*:\s*(\d{3,})(?:px|pt)", html_text, flags=re.IGNORECASE)
        blank_lines = max((len(match) for match in re.findall(r"(?:\r?\n[ \t]*){4,}", html_text)), default=0)
        if fixed_heights or blank_lines >= 8:
            evidence = []
            if fixed_heights:
                evidence.append(f"large fixed heights: {', '.join(fixed_heights[:3])}px")
            if blank_lines >= 8:
                evidence.append(f"blank-line run: {blank_lines} lines")
            findings.append(_finding(
                "body", "layout_evasion", "medium", "Suspicious layout spacer",
                "Large fixed dimensions or blank-line padding can push meaningful content below the preview fold or make a message appear empty. This is a layout heuristic, not proof of maliciousness.",
                evidence, "SOC detection heuristic",
            ))
        title_nodes = soup.find_all("title")
        if title_nodes:
            title_text = " ".join(node.get_text(" ", strip=True) for node in title_nodes)
            findings.append(_finding(
                "body", "obfuscation", "medium", "Text in HTML title element",
                "Text is stored in an HTML title element. In email bodies this may be suppressed by the mail client while remaining visible to raw-text scanners, creating a parser/rendering discrepancy.",
                [title_text[:240], f"title bytes: {len(title_text.encode('utf-8', errors='replace'))}"], "HTML content inspection",
            ))
        if hidden or hidden_style:
            hidden_bytes = len(hidden_text.encode("utf-8", errors="replace"))
            visible_text = soup.get_text(" ", strip=True)
            if visible_bytes := len(visible_text.encode("utf-8", errors="replace")):
                ratio = hidden_bytes / visible_bytes if visible_bytes else float("inf")
                if ratio >= 10 or raw_html_bytes >= 60000 and visible_bytes < 6000:
                    findings.append(_finding(
                        "body", "obfuscation", "high", "Large hidden-to-visible content ratio",
                        "Hidden or non-visible content is disproportionately larger than rendered text, a pattern associated with Bayesian poisoning and scanner/rendering divergence. Legitimate marketing templates can also produce this signal.",
                        [f"hidden bytes: {hidden_bytes}", f"visible bytes: {visible_bytes}", f"ratio: {ratio:.1f}:1"], "SOC detection heuristic",
                    ))
            findings.append(_finding(
                "body", "obfuscation", "high", "Hidden HTML content",
                "Text is present in elements or styles that hide it from normal readers while leaving it available to some filters or automated processing.",
                [hidden_text[:200] or "hidden CSS rule detected"], "RFC 5322 (content is application-specific HTML)",
            ))
        comments = re.findall(r"<!--(.*?)-->", html_text, flags=re.DOTALL)
        if any(_URL_RE.search(comment) or len(comment) > 120 for comment in comments):
            findings.append(_finding(
                "body", "obfuscation", "low", "Suspicious HTML comments",
                "Large or URL-bearing HTML comments may be used to alter filter tokenization without changing the visible message.",
                [comments[0][:200]], "HTML content inspection",
            ))
        if _ZERO_WIDTH_RE.search(html_text) or _ZERO_WIDTH_RE.search(plain_text):
            findings.append(_finding(
                "body", "obfuscation", "medium", "Zero-width or bidirectional control characters",
                "Invisible Unicode controls can split keywords, reorder displayed text, or make visual review disagree with filter input.",
                ["Unicode format/control characters detected"], "Unicode TR39",
            ))
        entity_matches = re.findall(r"(?:&#x?[0-9a-f]+;|%[0-9a-f]{2})", html_text, flags=re.IGNORECASE)
        if len(entity_matches) >= 2:
            findings.append(_finding(
                "body", "obfuscation", "low", "Encoded HTML or URL characters",
                "Repeated character/entity escapes are present in HTML and may be intended to evade simple keyword or URL filters.",
                [", ".join(entity_matches[:_MAX_EVIDENCE])], "HTML/URL encoding",
            ))
        data_urls = re.findall(r"(?:src|href)\s*=\s*[\"']data:", html_text, flags=re.IGNORECASE)
        if data_urls:
            findings.append(_finding(
                "body", "obfuscation", "medium", "Data URI embedded in HTML",
                "A data URI embeds content directly inside the message, making inspection and URL reputation checks less transparent.",
                [f"{len(data_urls)} data URI reference(s)"], "RFC 2397",
            ))
        hrefs = [match for match in _URL_RE.findall(html_text)]
        if any("xn--" in url.lower() for url in hrefs):
            findings.append(_finding(
                "body", "url", "medium", "Punycode URL domain",
                "A link uses an internationalized domain encoded with xn--; inspect the decoded Unicode domain for homograph risk.",
                [url[:200] for url in hrefs if "xn--" in url.lower()], "RFC 3492",
            ))
        unsubscribe_like = [
            link for link in soup.find_all("a", href=True)
            if "unsubscribe" in link.get_text(" ", strip=True).casefold()
            or "unsubscribe" in str(link.get("href", "")).casefold()
        ]
        if unsubscribe_like:
            hosts = sorted({(re.search(r"https?://([^/#?]+)", str(link.get("href", "")), re.IGNORECASE) or [None, ""])[1].casefold() for link in unsubscribe_like})
            findings.append(_finding(
                "body", "link_relationship", "low", "Unsubscribe-like link present",
                "The message contains an unsubscribe-like link. Its domain and relationship to the sender should be reviewed; marketing mail commonly uses third-party tracking domains, so this is not proof of fraud.",
                [f"hosts: {', '.join(hosts[:_MAX_EVIDENCE]) or 'non-HTTP/relative'}"], "List-Unsubscribe / HTML link heuristic",
            ))
        if any(url.lower().startswith("data:") for url in hrefs):
            findings.append(_finding(
                "body", "url", "medium", "Embedded data URL",
                "A body URL uses the data scheme rather than a network host, which can hide payloads from ordinary link checks.",
                ["data: URL detected"], "RFC 2397",
            ))
        base_nodes = soup.find_all("base", href=True)
        relative_targets = [
            node.get("href", "") or node.get("src", "")
            for node in soup.find_all(["a", "img", "form"], href=True)
        ]
        relative_targets = [target for target in relative_targets if target and not re.match(r"^[a-z][a-z0-9+.-]*:", target, re.IGNORECASE)]
        if base_nodes and relative_targets:
            findings.append(_finding(
                "body", "url", "medium", "HTML base tag with relative targets",
                "A base URL changes how relative links are interpreted by a mail client. The relationship is reported statically; the base or targets were not resolved or visited.",
                [f"base={str(base_nodes[0].get('href'))[:180]}", f"relative targets: {len(relative_targets)}"], "HTML URL resolution",
            ))

        doc_tags = {name: len(soup.find_all(name)) for name in ("html", "head", "body")}
        if any(count > 1 for count in doc_tags.values()):
            findings.append(_finding(
                "body", "structure", "medium", "Repeated HTML document containers",
                "The HTML part contains multiple html/head/body containers, which can render differently across tolerant mail clients and strict scanners.",
                [f"counts: {doc_tags}"], "HTML parsing heuristic",
            ))
        if re.search(r"</body>\s*</html>\s*<", html_text, flags=re.IGNORECASE | re.DOTALL):
            findings.append(_finding(
                "body", "structure", "medium", "Content follows a closed HTML document",
                "Additional markup appears after a closed body/html pair, creating parser-dependent content boundaries.",
                ["markup after </body></html>"], "HTML parsing heuristic",
            ))

        visible = soup.get_text(" ", strip=True)
        if plain_text.strip() and visible.strip() and _normalized_text(plain_text) != _normalized_text(visible):
            findings.append(_finding(
                "body", "representation", "low", "Plain-text and HTML representations differ",
                "The text and HTML alternatives are not equivalent after normalization; this can create a reader/filter discrepancy.",
                [f"plain={plain_text[:120]}", f"html={visible[:120]}"], "RFC 2046 §5.1.4",
            ))

    # MIME declarations are inspected independently of decoded rendering.
    content_types = [str(value) for value in msg.get_all("Content-Type", [])]
    full_content_type = "\n".join(content_types)
    if "multipart/encrypted" in full_content_type.lower():
        has_control = any(part.get_content_type().lower() == "application/pgp-encrypted" for part in msg.walk())
        if not has_control:
            findings.append(_finding(
                "body", "mime", "high", "Encrypted multipart lacks PGP control part",
                "The message declares multipart/encrypted but no application/pgp-encrypted control part was parsed. Different gateways and clients may handle the remaining content differently.",
                [full_content_type[:300]], "RFC 1847",
            ))
    if "multipart/signed" in full_content_type.lower():
        has_signature = any(part.get_content_type().lower() in {"application/pgp-signature", "application/pkcs7-signature", "application/x-pkcs7-signature"} for part in msg.walk())
        if not has_signature:
            findings.append(_finding(
                "body", "mime", "medium", "Signed multipart lacks signature part",
                "The message declares multipart/signed but no standard signature part was parsed. This may be a broken legitimate signature or a structural evasion attempt.",
                [full_content_type[:300]], "RFC 1847",
            ))
    for content_type in content_types:
        boundary = re.search(r"boundary\s*=\s*(?:\"([^\"]*)\"|([^;\s]+))", content_type, re.IGNORECASE)
        if boundary:
            boundary_value = boundary.group(1) or boundary.group(2) or ""
            if "\x00" in boundary_value or "%00" in boundary_value.lower() or boundary_value != boundary_value.rstrip():
                findings.append(_finding(
                    "body", "mime", "medium", "Suspicious MIME boundary declaration",
                    "The boundary contains a NUL/encoded-NUL or trailing whitespace that can produce parser differences.",
                    [repr(boundary_value[:200])], "RFC 2046 §5.1.1",
                ))

    return findings


def _normalized_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().casefold()


def _parse_received(value: str, position: int) -> ReceivedHop:
    raw = " ".join(value.split())
    before_date, separator, date_text = raw.rpartition(";")
    date_text = date_text.strip() if separator else ""
    timestamp: str | None = None
    anomalies: list[str] = []
    if date_text:
        try:
            timestamp = parsedate_to_datetime(date_text).isoformat()
        except (TypeError, ValueError, OverflowError):
            anomalies.append("unparseable timestamp")
    else:
        anomalies.append("missing timestamp separator")

    from_match = re.search(r"\bfrom\s+(.+?)(?=\s+by\s+|\s+with\s+|\s+id\s+|$)", before_date, re.IGNORECASE)
    by_match = re.search(r"\bby\s+(.+?)(?=\s+with\s+|\s+id\s+|$)", before_date, re.IGNORECASE)
    with_match = re.search(r"\bwith\s+(.+?)(?=\s+id\s+|$)", before_date, re.IGNORECASE)
    from_value = from_match.group(1).strip() if from_match else None
    by_value = by_match.group(1).strip() if by_match else None
    with_value = with_match.group(1).strip() if with_match else None
    if not from_match:
        anomalies.append("missing from clause")
    if not by_match:
        anomalies.append("missing by clause")

    from_ip = None
    for candidate in re.findall(r"(?:\[|\()([^\]\)\s]+)(?:\]|\))", before_date):
        try:
            ip_address(candidate)
            from_ip = candidate
            break
        except ValueError:
            continue

    if from_value and by_value and from_value.casefold() == by_value.casefold():
        anomalies.append("from/by host identical")
    return ReceivedHop(
        position=position,
        raw=raw[:600],
        from_value=from_value,
        by_value=by_value,
        with_value=with_value,
        from_ip=from_ip,
        timestamp=timestamp,
        anomalies=anomalies,
    )


def _raw_header_value(raw_headers: str, name: str) -> str:
    match = re.search(
        rf"(?im)^{re.escape(name)}:\s*([^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*)",
        raw_headers,
    )
    return re.sub(r"\s+", " ", match.group(1)).strip() if match else ""


def _address_parts(msg: EmailMessage, name: str, raw_headers: str = "") -> list[tuple[str, str]]:
    values = msg.get_all(name, []) or []
    parsed = [(local, domain) for local, domain in getaddresses(values) if local and domain]
    if parsed or not raw_headers:
        return parsed
    raw_value = _raw_header_value(raw_headers, name)
    return [
        (local, domain)
        for local, domain in re.findall(
            r"([A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+)@([A-Za-z0-9.-]+)",
            raw_value,
        )
        if local and domain
    ]


def _canonical_address(local: str, domain: str, *, gmail_dots: bool = False) -> str:
    local = local.casefold()
    domain = domain.rstrip(".").casefold()
    if gmail_dots and domain in {"gmail.com", "googlemail.com"}:
        local = local.split("+", 1)[0].replace(".", "")
    return f"{local}@{domain}"


def _header_findings(msg: EmailMessage, raw_headers: str = "") -> tuple[list[TechnicalFinding], list[ReceivedHop]]:
    findings: list[TechnicalFinding] = []
    hops = [_parse_received(value, index) for index, value in enumerate(msg.get_all("Received") or [], start=1)][:_MAX_HOPS]

    if len(hops) > 1:
        for current, older in zip(hops, hops[1:]):
            if current.timestamp and older.timestamp:
                try:
                    current_dt = datetime.fromisoformat(current.timestamp)
                    older_dt = datetime.fromisoformat(older.timestamp)
                    if current_dt < older_dt:
                        current.anomalies.append("timestamp order violation")
                        findings.append(_finding(
                            "headers", "received_chain", "high", "Received timestamp order violation",
                            "Received headers are newest-first; an older header has a later timestamp than the newer hop. This can indicate clock skew, rewriting, or fabricated routing data.",
                            [f"hop {current.position}: {current.timestamp}", f"hop {older.position}: {older.timestamp}"], "RFC 5321 §4.4",
                        ))
                except ValueError:
                    pass

    for hop in hops:
        if hop.anomalies:
            findings.append(_finding(
                "headers", "received_chain", "low", f"Received hop {hop.position} is irregular",
                "The hop is parseable only with incomplete or unusual Received syntax. Treat this as evidence for review, not proof of spoofing.",
                [", ".join(hop.anomalies), hop.raw[:200]], "RFC 5321 §4.4",
            ))
    if len(hops) >= 2:
        findings.append(_finding(
            "headers", "received_chain", "info", f"Received chain contains {len(hops)} hops",
            "The complete chain was parsed in the order presented by the message. The newest hop is position 1.",
            [f"hop {hop.position}: from={hop.from_value or '?'} by={hop.by_value or '?'}" for hop in hops[:_MAX_EVIDENCE]], "RFC 5321 §4.4",
        ))

    for name in _SINGLETON_HEADERS:
        values = msg.get_all(name) or []
        if len(values) > 1:
            findings.append(_finding(
                "headers", "syntax", "medium", f"Duplicate singleton header: {name}",
                "Multiple instances of a normally singleton header can create parser differentials between mail clients and security filters.",
                [f"{len(values)} values present"], "RFC 5322 §3.6",
            ))

    if msg.defects:
        findings.append(_finding(
            "headers", "syntax", "medium", "Parser detected malformed message syntax",
            "The standard library email parser recorded defects while processing this message. Review the raw message because different parsers may recover differently.",
            [type(defect).__name__ for defect in msg.defects], "RFC 5322",
        ))

    sender = _address_parts(msg, "From", raw_headers)[:1]
    recipients: list[tuple[str, str, str]] = []
    for header_name in ("To", "Cc", "Delivered-To"):
        recipients.extend((local, domain, header_name) for local, domain in _address_parts(msg, header_name, raw_headers))
    if sender and recipients:
        sender_local, sender_domain = sender[0]
        sender_exact = _canonical_address(sender_local, sender_domain)
        sender_gmail = _canonical_address(sender_local, sender_domain, gmail_dots=True)
        for recipient_local, recipient_domain, header_name in recipients:
            recipient_exact = _canonical_address(recipient_local, recipient_domain)
            recipient_gmail = _canonical_address(recipient_local, recipient_domain, gmail_dots=True)
            if recipient_exact == sender_exact:
                findings.append(_finding(
                    "headers", "address_relationship", "medium", "Sender and recipient are the same address",
                    "The message addresses the same mailbox it claims to come from. This can be legitimate for tests or automated mail, but is worth reviewing in phishing triage.",
                    [f"From={sender_exact}", f"{header_name}={recipient_exact}"], "RFC 5322 §3.6.3",
                ))
            elif sender_gmail == recipient_gmail and sender_domain.rstrip(".").casefold() in {"gmail.com", "googlemail.com"}:
                findings.append(_finding(
                    "headers", "address_normalization", "medium", "Sender and recipient match after Gmail normalization",
                    "The addresses differ textually but become identical after removing Gmail local-part dots and a trailing domain dot. Google mailbox normalization makes this a potentially meaningful identity reuse signal.",
                    [f"From={sender_local}@{sender_domain}", f"{header_name}={recipient_local}@{recipient_domain}"], "Google mailbox normalization",
                ))

    for name in ("From", "To", "Cc", "Reply-To", "Return-Path", "Delivered-To"):
        for local, domain in _address_parts(msg, name):
            if domain.endswith("."):
                findings.append(_finding(
                    "headers", "address_normalization", "info", f"Trailing dot in {name} domain",
                    "The address contains an absolute DNS-style domain spelling. It is equivalent for DNS lookup, but should be compared carefully without changing arbitrary local parts.",
                    [f"{name}: {local}@{domain}"], "RFC 5321 §4.1.2",
                ))

    return findings, hops


def _header_inventory(msg: EmailMessage) -> list[HeaderEvidence]:
    """Capture bounded observed headers, preserving repeated values and order."""
    inventory: list[HeaderEvidence] = []
    occurrences: dict[str, int] = {}
    for name, value in msg.raw_items():
        name_lower = name.casefold()
        if name_lower not in _INVENTORY_HEADERS and name_lower != "received":
            continue
        occurrences[name_lower] = occurrences.get(name_lower, 0) + 1
        inventory.append(HeaderEvidence(
            name=name,
            value=" ".join(str(value).split())[:600],
            occurrence=occurrences[name_lower],
        ))
        if len(inventory) >= 80:
            break
    return inventory


def analyze_technical(raw_eml: bytes, msg: EmailMessage | None = None) -> TechnicalReport:
    """Return deterministic technical findings for a raw message."""
    parsed = msg or email.message_from_bytes(raw_eml, policy=email.policy.default)
    raw_headers = raw_eml.split(b"\n\n", 1)[0].decode("utf-8", errors="replace")
    body_findings = _body_findings(parsed)
    header_findings, received_hops = _header_findings(parsed, raw_headers)
    all_findings = (body_findings + header_findings)[:_MAX_FINDINGS]
    if all_findings:
        counts = f"{len(body_findings)} body and {len(header_findings)} header finding(s)"
        summary = f"Technical review found {counts}; see evidence below."
    else:
        summary = "No deterministic MIME, body, or header anomalies were detected."
    return TechnicalReport(
        summary=summary,
        body_findings=body_findings[:_MAX_FINDINGS],
        header_findings=header_findings[:_MAX_FINDINGS],
        received_hops=received_hops,
        header_inventory=_header_inventory(parsed),
    )


def format_technical_for_llm(report: TechnicalReport | None) -> str:
    """Format technical findings as bounded, clearly labelled LLM context."""
    if report is None:
        return "No deterministic technical report is available."
    lines = [report.summary, "BODY TECHNICAL FINDINGS:"]
    for finding in report.body_findings:
        evidence = "; ".join(finding.evidence)
        reference = f" [{finding.reference}]" if finding.reference else ""
        lines.append(f"- {finding.severity.upper()} {finding.title}{reference}: {finding.explanation} Evidence: {evidence}")
    lines.append("HEADER TECHNICAL FINDINGS:")
    for finding in report.header_findings:
        evidence = "; ".join(finding.evidence)
        reference = f" [{finding.reference}]" if finding.reference else ""
        lines.append(f"- {finding.severity.upper()} {finding.title}{reference}: {finding.explanation} Evidence: {evidence}")
    return "\n".join(lines)[:_MAX_CONTEXT]
