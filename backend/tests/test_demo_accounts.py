"""Tests for the demo account endpoints (POST /api/v1/demo/users and
GET /api/v1/demo/account/{user_id}).

Covers creation, id uniqueness, firewall interoperability of created accounts,
balance validation, schema hardening, balance lookup and isolation from the
seeded demo users.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

ALICE_BALANCE = Decimal("25000.00")


def create_user(client, display_name="Test User", initial_balance="1000"):
    return client.post(
        "/api/v1/demo/users",
        json={"display_name": display_name, "initial_balance": initial_balance},
    )


# --------------------------------------------------------------------------- #
# Creation
# --------------------------------------------------------------------------- #
def test_create_account_returns_200_with_expected_shape(client):
    response = create_user(client, "Nisha", "1000")
    assert response.status_code == 200
    body = response.json()
    assert body["user_id"].startswith("user-")
    assert body["display_name"] == "Nisha"
    assert body["simulated"] is True
    assert body["currency"] == "INR"
    assert body["balance"] == "1000.00"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("1000", "1000.00"), ("0", "0.00"), ("100.5", "100.50")],
)
def test_create_account_balance_quantized_to_two_decimals(client, raw, expected):
    response = create_user(client, "Nisha", raw)
    assert response.status_code == 200
    assert response.json()["balance"] == expected


def test_two_creations_generate_distinct_ids(client):
    first = create_user(client, "First", "1000").json()
    second = create_user(client, "Second", "1000").json()
    assert first["user_id"] != second["user_id"]
    assert first["display_name"] == "First"
    assert second["display_name"] == "Second"


def test_created_account_works_with_evaluate_and_payees(client):
    user_id = create_user(client, "Renter", "1000").json()["user_id"]

    balance_check = client.post(
        "/api/v1/evaluate", json={"message": "check my balance", "user_id": user_id}
    )
    assert balance_check.status_code == 200
    assert balance_check.json()["decision"] == "APPROVE"

    transfer = client.post(
        "/api/v1/evaluate", json={"message": "send 500 to Priya", "user_id": user_id}
    )
    assert transfer.status_code == 200
    assert transfer.json()["decision"] == "APPROVE"


def test_zero_starting_balance_is_accepted(client):
    response = create_user(client, "Broke", "0")
    assert response.status_code == 200
    assert response.json()["balance"] == "0.00"


# --------------------------------------------------------------------------- #
# Balance validation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "bad_balance",
    ["-5", "1e3", "NaN", "Infinity", "10.999", "abc", "", "1000000.01"],
)
def test_invalid_initial_balances_rejected(client, bad_balance):
    response = create_user(client, "Bad", bad_balance)
    assert response.status_code == 422


def test_max_initial_balance_accepted(client):
    response = create_user(client, "Max", "1000000.00")
    assert response.status_code == 200
    assert response.json()["balance"] == "1000000.00"


# --------------------------------------------------------------------------- #
# Schema hardening
# --------------------------------------------------------------------------- #
def test_extra_field_in_create_body_rejected(client):
    response = client.post(
        "/api/v1/demo/users",
        json={
            "display_name": "Sneaky",
            "initial_balance": "100",
            "user_id": "admin",  # client-supplied id must not be accepted
            "balance": "999999.00",
        },
    )
    assert response.status_code == 422


# --------------------------------------------------------------------------- #
# Account lookup
# --------------------------------------------------------------------------- #
def test_get_account_returns_matching_balance(client):
    created = create_user(client, "Saver", "1000").json()
    response = client.get(f"/api/v1/demo/account/{created['user_id']}")
    assert response.status_code == 200
    body = response.json()
    assert body["user_id"] == created["user_id"]
    assert body["display_name"] == "Saver"
    assert body["simulated"] is True
    assert body["currency"] == "INR"
    assert body["balance"] == "1000.00"


def test_get_account_balance_reflects_executed_transfer(client):
    user_id = create_user(client, "Renter", "1000").json()["user_id"]

    processed = client.post(
        "/api/v1/process",
        json={"message": "send 500 to Priya", "memo": "rent", "user_id": user_id},
    )
    assert processed.status_code == 200
    assert processed.json()["action_executed"] is True

    response = client.get(f"/api/v1/demo/account/{user_id}")
    assert response.status_code == 200
    assert response.json()["balance"] == "500.00"


def test_get_account_unknown_id_returns_404(client):
    response = client.get("/api/v1/demo/account/nobody")
    assert response.status_code == 404
    assert response.json()["detail"] == "unknown demo account"


# --------------------------------------------------------------------------- #
# Isolation from seeded users
# --------------------------------------------------------------------------- #
def test_created_account_does_not_affect_other_accounts(client, banking):
    user_id = create_user(client, "Newcomer", "1000").json()["user_id"]

    # Seeded users keep their balances and payees.
    assert banking.get_balance("alice") == ALICE_BALANCE
    assert banking.get_balance("bob") == Decimal("12000.00")
    assert banking.get_balance("carol") == Decimal("8000.00")
    assert set(banking.list_payees("alice")) == {"priya", "rahul", "meera", "arjun"}

    # Transacting with the new account does not touch seeded balances.
    client.post(
        "/api/v1/process",
        json={"message": "send 500 to Priya", "user_id": user_id},
    )
    assert banking.get_balance("alice") == ALICE_BALANCE
    assert banking.get_balance("bob") == Decimal("12000.00")
    assert banking.get_balance("carol") == Decimal("8000.00")

    # Seeded identities still evaluate normally.
    response = client.post(
        "/api/v1/evaluate", json={"message": "check my balance", "user_id": "alice"}
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "APPROVE"
