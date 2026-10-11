"""FastAPI application for the Bankism defensive firewall.

Endpoints
---------
* ``GET  /health``                - liveness probe.
* ``POST /api/v1/evaluate``       - returns a verdict only; NEVER changes state.
* ``POST /api/v1/process``        - re-runs the full evaluation server-side and only
  executes an action if the *fresh* server verdict is APPROVE.
* ``POST /api/v1/demo/users``     - create a new simulated demo account.
* ``GET  /api/v1/demo/account/{user_id}`` - look up a demo account balance.

Security boundaries are commented inline. A client-supplied verdict is never
accepted: request models forbid extra fields, so forging ``decision`` etc. yields
HTTP 422 with no side effects.
"""

from __future__ import annotations

import re
from decimal import Decimal
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Path, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .banking import (
    CURRENCY,
    MAX_INITIAL_BALANCE,
    BankingError,
    BankingService,
    UnknownUserError,
    get_banking_service,
)
from .firewall import Firewall, ThreatAnalyzer, get_threat_analyzer, resolve_identity
from .schemas import (
    CreateDemoUserRequest,
    Decision,
    DemoAccountResponse,
    EvaluateRequest,
    Intent,
    ProcessResponse,
    RiskLevel,
    ThreatCategory,
    Verdict,
)

app = FastAPI(
    title="Bankism Firewall",
    description="Blue-team defensive AI firewall for simulated banking requests.",
    version="1.0.0",
)

# Dev CORS for local frontends and hosted demos. Additional allowed origins
# can be provided as a comma-separated list in BANKISM_CORS_ORIGINS (for
# example the deployed frontend's URL). Not a production configuration.
import os

_EXTRA_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("BANKISM_CORS_ORIGINS", "").split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        *_EXTRA_ORIGINS,
    ],
    # The hosted frontend plus all of its Netlify deploy previews
    # (https://<hash>--bankism.netlify.app). Starlette does not support
    # wildcards inside allow_origins, so a regex is used instead.
    allow_origin_regex=r"https://([a-z0-9-]+--)?bankism\.netlify\.app",
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-Demo-User"],
)


def _firewall(
    banking: BankingService = Depends(get_banking_service),
    analyzer: ThreatAnalyzer = Depends(get_threat_analyzer),
) -> Firewall:
    return Firewall(banking=banking, analyzer=analyzer)


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "bankism-firewall",
        "simulated": True,
        "currency": "INR",
    }


@app.post("/api/v1/evaluate", response_model=Verdict)
def evaluate(
    payload: EvaluateRequest,
    x_demo_user: Optional[str] = Header(default=None, alias="X-Demo-User"),
    firewall: Firewall = Depends(_firewall),
) -> Verdict:
    """Evaluate a request and return a verdict. No side effects, ever."""
    return firewall.evaluate(
        message=payload.message,
        memo=payload.memo,
        user_id=payload.user_id,
        header_user=x_demo_user,
    )


@app.post("/api/v1/process", response_model=ProcessResponse)
def process(
    payload: EvaluateRequest,
    x_demo_user: Optional[str] = Header(default=None, alias="X-Demo-User"),
    firewall: Firewall = Depends(_firewall),
    banking: BankingService = Depends(get_banking_service),
) -> ProcessResponse:
    """Re-run full evaluation server-side, then execute only on a fresh APPROVE."""
    # The client verdict (if any) is not even in the request model. We recompute.
    verdict = firewall.evaluate(
        message=payload.message,
        memo=payload.memo,
        user_id=payload.user_id,
        header_user=x_demo_user,
    )

    if verdict.decision != Decision.APPROVE:
        return ProcessResponse(verdict=verdict, action_executed=False, simulated=True)

    # Re-resolve the demo sender exactly as the firewall did.
    sender, _errors, _signals = resolve_identity(payload.user_id, x_demo_user, banking)
    if sender is None:  # defensive: should be impossible after an APPROVE
        return ProcessResponse(
            verdict=_execution_failure_verdict(verdict.request_id),
            action_executed=False,
            simulated=True,
        )

    try:
        if verdict.intent == Intent.BALANCE_INQUIRY:
            balance = banking.get_balance(sender)
            return ProcessResponse(
                verdict=verdict,
                action_executed=True,
                simulated=True,
                balance=str(balance.quantize(Decimal("0.01"))),
            )

        if verdict.intent == Intent.TRANSFER and verdict.transaction_details is not None:
            details = verdict.transaction_details
            # The banking service re-validates every field independently.
            txn = banking.execute_transfer(
                user_id=sender,
                recipient=details.recipient or "",
                amount=Decimal(details.amount or "0"),
                memo=details.memo,
            )
            return ProcessResponse(
                verdict=verdict,
                action_executed=True,
                simulated=True,
                transaction_id=txn["transaction_id"],
                balance=txn["balance_after"],
            )
    except Exception:  # noqa: BLE001 - any failure = fail closed, no side effects
        return ProcessResponse(
            verdict=_execution_failure_verdict(verdict.request_id),
            action_executed=False,
            simulated=True,
        )

    # Approval with nothing executable (should not happen): fail closed.
    return ProcessResponse(
        verdict=_execution_failure_verdict(verdict.request_id),
        action_executed=False,
        simulated=True,
    )


#: Strict INR amount shape: digits with an optional 1-2 decimal fraction.
#: Rejects negatives, scientific notation, NaN/Infinity and >2 decimals.
_INITIAL_BALANCE_RE = re.compile(r"^\d+(\.\d{1,2})?$")


@app.post("/api/v1/demo/users", response_model=DemoAccountResponse)
def create_demo_user(
    payload: CreateDemoUserRequest,
    banking: BankingService = Depends(get_banking_service),
) -> DemoAccountResponse:
    """Create a new simulated demo account. No floats: string -> regex -> Decimal."""
    raw_balance = payload.initial_balance.strip()
    if not _INITIAL_BALANCE_RE.fullmatch(raw_balance):
        raise HTTPException(
            status_code=422,
            detail="initial_balance must be a non-negative INR amount with at most two decimal places",
        )
    balance = Decimal(raw_balance)
    if balance > MAX_INITIAL_BALANCE:
        raise HTTPException(status_code=422, detail="initial_balance exceeds the allowed limit")

    try:
        account = banking.create_user(payload.display_name, balance)
    except BankingError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return DemoAccountResponse(
        user_id=account["user_id"],
        display_name=account["display_name"],
        simulated=True,
        currency=CURRENCY,
        balance=str(account["balance"].quantize(Decimal("0.01"))),
    )


@app.get("/api/v1/demo/account/{user_id}", response_model=DemoAccountResponse)
def get_demo_account(
    user_id: str = Path(max_length=64),
    banking: BankingService = Depends(get_banking_service),
) -> DemoAccountResponse:
    """Return the demo account's display name and current balance."""
    uid = user_id.strip().lower()
    try:
        account = banking.get_account(uid)
    except UnknownUserError as exc:
        raise HTTPException(status_code=404, detail="unknown demo account") from exc

    return DemoAccountResponse(
        user_id=uid,
        display_name=account["display_name"],
        simulated=True,
        currency=CURRENCY,
        balance=str(account["balance"].quantize(Decimal("0.01"))),
    )


def _execution_failure_verdict(request_id: str) -> Verdict:
    return Verdict(
        request_id=request_id,
        decision=Decision.BLOCK,
        risk_level=RiskLevel.HIGH,
        threat_category=ThreatCategory.VALIDATION_FAILURE,
        rationale="Action could not be executed safely; blocked.",
        intent=Intent.NONE,
        transaction_details=None,
        validation_errors=["execution failed"],
        signals=["execution_failure"],
    )
