from __future__ import annotations

from enum import Enum
from pydantic import BaseModel


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    ERROR = "error"


class CheckResult(BaseModel):
    name: str
    status: CheckStatus
    score_delta: float
    details: str
    record: str | None = None
    extra: dict = {}


class TechnicalFinding(BaseModel):
    """A bounded, evidence-based technical email finding."""

    area: str  # body or headers
    category: str
    severity: str  # info, low, medium, high
    title: str
    explanation: str
    evidence: list[str] = []
    reference: str | None = None


class ReceivedHop(BaseModel):
    """Parsed information from one Received header, newest hop first."""

    position: int
    raw: str
    from_value: str | None = None
    by_value: str | None = None
    with_value: str | None = None
    from_ip: str | None = None
    timestamp: str | None = None
    anomalies: list[str] = []


class HeaderEvidence(BaseModel):
    """One observed header value, preserving duplicate/order information."""

    name: str
    value: str
    occurrence: int = 1


class TechnicalReport(BaseModel):
    """Deterministic MIME/body and header analysis persisted with a result."""

    version: str = "1"
    summary: str = "No technical findings."
    body_findings: list[TechnicalFinding] = []
    header_findings: list[TechnicalFinding] = []
    received_hops: list[ReceivedHop] = []
    header_inventory: list[HeaderEvidence] = []


class TechnicalAssessment(BaseModel):
    """The optional LLM interpretation of deterministic technical evidence."""

    summary: str = ""
    body: str = ""
    headers: str = ""
    findings: list[str] = []


class LLMAnalysis(BaseModel):
    is_suspicious: bool
    confidence: float
    category: str  # phishing, spam, scam, legitimate, suspicious
    reasoning: str
    indicators: list[str] = []
    technical_analysis: TechnicalAssessment | None = None
    provider: str | None = None
    model: str | None = None


class ChatMessage(BaseModel):
    """One persisted question or answer in an analysis conversation."""

    role: str  # user or assistant
    content: str
    created_at: str


class AttackFinding(BaseModel):
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    exploit: str
    remediation: str


class AnalysisResult(BaseModel):
    id: str
    created_at: str
    sender_address: str | None = None
    recipient_address: str | None = None
    subject: str | None = None
    source: str  # smtp or upload
    client_ip: str | None = None
    overall_score: float
    rating: str
    checks: list[CheckResult]
    llm_analysis: LLMAnalysis | None = None
    technical_report: TechnicalReport | None = None
    simulation_overrides: dict[str, str | None] = {}
    recommendations: list[str]
    attack_surface: list[AttackFinding] = []
