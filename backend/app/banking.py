"""SIMULATED in-memory banking service for the Bankism firewall demo.

Security / honesty notes
------------------------
* This is 100% fake. There are no real bank APIs, no network calls, and no real
  money. It exists only to demonstrate a security boundary around an action.
* ``user_id`` and the ``X-Demo-User`` header are **demo identity selectors**,
  NOT authentication. See ``firewall.py`` for how identity is resolved.
* The service re-checks safety independently of the firewall. It never trusts
  the caller: amount must be a positive ``Decimal`` with <= 2 decimals, funds
  must be sufficient, and the payee must be a known account. This is a
  defence-in-depth check, not a substitute for the firewall.

State is held on a single module-level instance so tests can reset it with
``reset_demo_state()``. Tests may also inject their own instance via the
``get_banking_service`` dependency.
"""

from __future__ import annotations

import itertools
import threading
import uuid
from decimal import Decimal
from typing import Dict, List, Optional

#: The single supported currency. Documented in the README.
CURRENCY = "INR"
#: Hard per-transaction cap enforced by both firewall and banking service.
MAX_TRANSACTION_AMOUNT = Decimal("100000.00")
#: Hard per-account cap for the initial balance of a newly created demo user.
MAX_INITIAL_BALANCE = Decimal("1000000.00")


# --------------------------------------------------------------------------- #
# Errors (raised by the banking service; the API turns them into BLOCK)
# --------------------------------------------------------------------------- #
class BankingError(Exception):
    """Base class for banking-layer safety failures."""


class UnknownUserError(BankingError):
    pass


class UnknownPayeeError(BankingError):
    pass


class InsufficientFundsError(BankingError):
    pass


class InvalidAmountError(BankingError):
    pass


# --------------------------------------------------------------------------- #
# Deterministic demo dataset (seed data)
# --------------------------------------------------------------------------- #
def _payee(name: str, account: str) -> Dict[str, str]:
    return {"name": name, "account": account}


#: Three demo users with fixed balances and known payees. Amounts are Decimal.
DEMO_USERS: Dict[str, Dict] = {
    "alice": {
        "display_name": "Alice",
        "balance": Decimal("25000.00"),
        "payees": {
            "priya": _payee("Priya", "AC-PRIYA-001"),
            "rahul": _payee("Rahul", "AC-RAHUL-002"),
            "meera": _payee("Meera", "AC-MEERA-003"),
            "arjun": _payee("Arjun", "AC-ARJUN-004"),
        },
    },
    "bob": {
        "display_name": "Bob",
        "balance": Decimal("12000.00"),
        "payees": {
            "priya": _payee("Priya", "AC-PRIYA-001"),
            "kiran": _payee("Kiran", "AC-KIRAN-005"),
            "deepa": _payee("Deepa", "AC-DEEPA-006"),
        },
    },
    "carol": {
        "display_name": "Carol",
        "balance": Decimal("8000.00"),
        "payees": {
            "rahul": _payee("Rahul", "AC-RAHUL-002"),
            "sana": _payee("Sana", "AC-SANA-007"),
            "vikram": _payee("Vikram", "AC-VIKRAM-008"),
        },
    },
}

#: Union of every payee known to any seeded demo user. New demo accounts get a
#: fresh copy of this directory so they can transact with the same payees.
KNOWN_PAYEE_DIRECTORY: Dict[str, Dict] = {
    key: dict(payee)
    for user in DEMO_USERS.values()
    for key, payee in user["payees"].items()
}


# --------------------------------------------------------------------------- #
# Service
# --------------------------------------------------------------------------- #
class BankingService:
    """In-memory simulated bank. Thread-safe enough for a local demo."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.reset()

    # -- lifecycle -------------------------------------------------------- #
    def reset(self) -> None:
        """Restore seeded balances and clear all transactions."""
        with self._lock:
            self._users: Dict[str, Dict] = {
                uid: {
                    "display_name": data["display_name"],
                    "balance": data["balance"],
                    "payees": {k: dict(v) for k, v in data["payees"].items()},
                }
                for uid, data in DEMO_USERS.items()
            }
            self._transactions: List[Dict] = []
            self._counter = itertools.count(1)

    # -- reads ------------------------------------------------------------ #
    def user_exists(self, user_id: Optional[str]) -> bool:
        if not user_id:
            return False
        return user_id.strip().lower() in self._users

    def users(self) -> Dict[str, str]:
        """Return ``{user_id: display_name}`` for all demo users."""
        with self._lock:
            return {uid: d["display_name"] for uid, d in self._users.items()}

    def get_balance(self, user_id: str) -> Decimal:
        with self._lock:
            uid = (user_id or "").strip().lower()
            if uid not in self._users:
                raise UnknownUserError("unknown user")
            return self._users[uid]["balance"]

    def get_account(self, user_id: str) -> Dict:
        """Return ``{"display_name", "balance"}`` for the lowercased user id."""
        with self._lock:
            uid = (user_id or "").strip().lower()
            if uid not in self._users:
                raise UnknownUserError("unknown user")
            return {
                "display_name": self._users[uid]["display_name"],
                "balance": self._users[uid]["balance"],
            }

    def list_payees(self, user_id: str) -> Dict[str, Dict[str, str]]:
        with self._lock:
            uid = (user_id or "").strip().lower()
            if uid not in self._users:
                raise UnknownUserError("unknown user")
            return {k: dict(v) for k, v in self._users[uid]["payees"].items()}

    def transactions(self) -> List[Dict]:
        """Return a copy of the transaction log."""
        with self._lock:
            return [dict(t) for t in self._transactions]

    # -- writes ----------------------------------------------------------- #
    def create_user(self, display_name: str, initial_balance: Decimal) -> Dict:
        """Create a new demo account with a copy of the known payee directory.

        Raises a :class:`BankingError` subclass on any invalid input; the API
        layer turns that into HTTP 422.
        """
        if not isinstance(initial_balance, Decimal):
            raise InvalidAmountError("initial_balance must be a Decimal")
        if initial_balance.is_nan() or not initial_balance.is_finite():
            raise InvalidAmountError("initial_balance must be finite")
        if initial_balance < 0:
            raise InvalidAmountError("initial_balance must be non-negative")
        if initial_balance.as_tuple().exponent < -2:
            raise InvalidAmountError("initial_balance must have at most 2 decimals")
        if initial_balance > MAX_INITIAL_BALANCE:
            raise InvalidAmountError("initial_balance exceeds the allowed limit")

        name = (display_name or "").strip()
        if not name:
            raise BankingError("display_name must not be empty")
        if len(name) > 64:
            raise BankingError("display_name must be at most 64 characters")

        with self._lock:
            # Collision with existing keys is practically impossible but the
            # loop keeps the invariant exact.
            while True:
                user_id = "user-" + uuid.uuid4().hex[:12]
                if user_id not in self._users:
                    break
            self._users[user_id] = {
                "display_name": name,
                "balance": initial_balance,
                "payees": {k: dict(v) for k, v in KNOWN_PAYEE_DIRECTORY.items()},
            }
        return {"user_id": user_id, "display_name": name, "balance": initial_balance}

    def execute_transfer(
        self,
        user_id: str,
        recipient: str,
        amount: Decimal,
        memo: Optional[str] = None,
    ) -> Dict:
        """Execute a simulated transfer after independent safety re-checks.

        Raises a :class:`BankingError` subclass on any problem. The caller
        (API layer) must convert that into a BLOCK with no side effects.
        """
        if not isinstance(amount, Decimal):
            raise InvalidAmountError("amount must be a Decimal")
        if amount.is_nan() or not amount.is_finite():
            raise InvalidAmountError("amount must be finite")
        if amount <= 0:
            raise InvalidAmountError("amount must be positive")
        if amount.as_tuple().exponent < -2:
            raise InvalidAmountError("amount must have at most 2 decimals")
        if amount > MAX_TRANSACTION_AMOUNT:
            raise InvalidAmountError("amount exceeds per-transaction cap")
        if memo is not None and len(memo) > 140:
            raise InvalidAmountError("memo too long")

        with self._lock:
            uid = (user_id or "").strip().lower()
            if uid not in self._users:
                raise UnknownUserError("unknown user")
            payees = self._users[uid]["payees"]
            payee = payees.get((recipient or "").strip().lower())
            if payee is None:
                raise UnknownPayeeError("unknown payee")

            balance = self._users[uid]["balance"]
            if amount > balance:
                raise InsufficientFundsError("insufficient funds")

            new_balance = balance - amount
            self._users[uid]["balance"] = new_balance
            txn = {
                "transaction_id": f"TXN-{next(self._counter):06d}",
                "user_id": uid,
                "recipient": payee["name"],
                "recipient_account": payee["account"],
                "amount": str(amount.quantize(Decimal("0.01"))),
                "currency": CURRENCY,
                "memo": memo,
                "balance_after": str(new_balance.quantize(Decimal("0.01"))),
                "simulated": True,
            }
            self._transactions.append(txn)
            return dict(txn)


# --------------------------------------------------------------------------- #
# Module-level singleton + dependency injection helpers
# --------------------------------------------------------------------------- #
_SERVICE = BankingService()


def reset_demo_state() -> None:
    """Reset the module singleton to seeded demo state (used by test fixtures)."""
    _SERVICE.reset()


def get_banking_service() -> BankingService:
    """FastAPI dependency. Tests override this with a fresh instance."""
    return _SERVICE
