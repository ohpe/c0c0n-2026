"""Red-team attack surface analysis sub-package.

Each module focuses on one attack category (SPF, DMARC, DKIM, etc.) and
returns a list of ``Finding`` objects.  The ``orchestrator`` module ties
them all together.
"""
from mail_tester.analysis.attacks.models import Finding, Posture

__all__ = ["Finding", "Posture"]
