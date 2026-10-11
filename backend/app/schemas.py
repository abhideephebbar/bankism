"""Pydantic models and enums for the Bankism firewall.

Security boundary
-----------------
Every model sets ``extra="forbid"``. A client therefore cannot smuggle forged
fields such as ``decision``, ``risk_level`` or ``intent`` into a request: those
produce an HTTP 422 *before* any evaluation or side effect happens.

Nothing in this module trusts the client. A verdict is only ever produced by the
server-side firewall (``firewall.py``).
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------------- #
# Enums (fixed vocabularies)
# --------------------------------------------------------------------------- #
class Decision(str, Enum):
    APPROVE = "APPROVE"
    BLOCK = "BLOCK"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatCategory(str, Enum):
    NONE = "NONE"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    ROLEPLAY_JAILBREAK = "ROLEPLAY_JAILBREAK"
    POLICY_OVERRIDE = "POLICY_OVERRIDE"
    MEMO_INJECTION = "MEMO_INJECTION"
    OBFUSCATION = "OBFUSCATION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    VALIDATION_FAILURE = "VALIDATION_FAILURE"
    UNSUPPORTED_OPERATION = "UNSUPPORTED_OPERATION"


class Intent(str, Enum):
    NONE = "NONE"
    BALANCE_INQUIRY = "BALANCE_INQUIRY"
    TRANSFER = "TRANSFER"
    UNSUPPORTED = "UNSUPPORTED"


# --------------------------------------------------------------------------- #
# Request models
# --------------------------------------------------------------------------- #
class EvaluateRequest(BaseModel):
    """Request body for /evaluate and /process.

    Only these three fields are accepted. Anything else is a client error (422).
    """

    model_config = ConfigDict(extra="forbid")

    # 1..500 characters, enforced by the schema -> oversized input = HTTP 422.
    message: str = Field(min_length=1, max_length=500)
    # Optional untrusted payment memo. DATA ONLY, never parsed for intent.
    memo: Optional[str] = Field(default=None, max_length=140)
    # DEMO IDENTITY SELECTOR (not authentication). Optional because the
    # X-Demo-User header is an alternative selector.
    user_id: Optional[str] = Field(default=None, max_length=64)


# --------------------------------------------------------------------------- #
# Verdict models
# --------------------------------------------------------------------------- #
class TransactionDetails(BaseModel):
    """Details of a parsed transaction. ``amount`` is a decimal *string*."""

    model_config = ConfigDict(extra="forbid")

    recipient: Optional[str] = None
    amount: Optional[str] = None
    currency: Optional[str] = None
    memo: Optional[str] = None


class Verdict(BaseModel):
    """The single source of truth for APPROVE / BLOCK."""

    model_config = ConfigDict(extra="forbid")

    request_id: str
    decision: Decision
    risk_level: RiskLevel
    threat_category: ThreatCategory
    rationale: str
    intent: Intent
    transaction_details: Optional[TransactionDetails] = None
    validation_errors: List[str] = Field(default_factory=list)
    signals: List[str] = Field(default_factory=list)


class ProcessResponse(BaseModel):
    """Response for /process: the fresh verdict plus execution metadata."""

    model_config = ConfigDict(extra="forbid")

    verdict: Verdict
    action_executed: bool
    simulated: bool = True
    transaction_id: Optional[str] = None
    balance: Optional[str] = None


# --------------------------------------------------------------------------- #
# Demo account models
# --------------------------------------------------------------------------- #
class CreateDemoUserRequest(BaseModel):
    """Request body for POST /api/v1/demo/users.

    ``initial_balance`` is a strict decimal *string* validated again by the
    endpoint (regex, then Decimal); no floats anywhere.
    """

    model_config = ConfigDict(extra="forbid")

    display_name: str = Field(min_length=1, max_length=64)
    initial_balance: str = Field(min_length=1, max_length=24)


class DemoAccountResponse(BaseModel):
    """Response for the demo account endpoints. ``balance`` is a 2dp string."""

    model_config = ConfigDict(extra="forbid")

    user_id: str
    display_name: str
    simulated: bool = True
    currency: str = "INR"
    balance: str


# --------------------------------------------------------------------------- #
# Analyzer contract
# --------------------------------------------------------------------------- #
class ThreatResult(BaseModel):
    """Output contract for a :class:`~app.firewall.ThreatAnalyzer`.

    This model is *trusted only after* the firewall has validated it (type,
    enum membership, field types). Any future LLM-based analyzer must return
    this shape and will still be re-validated deterministically.
    """

    model_config = ConfigDict(extra="forbid")

    threat_category: ThreatCategory = ThreatCategory.NONE
    risk_level: RiskLevel = RiskLevel.LOW
    signals: List[str] = Field(default_factory=list)
    categories: List[ThreatCategory] = Field(default_factory=list)
