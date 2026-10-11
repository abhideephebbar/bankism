"""Shared pytest fixtures.

Every test gets a clean simulated bank and a TestClient wired to that same
instance, so balance/transaction assertions are deterministic.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.banking import BankingService, get_banking_service, reset_demo_state
from app.firewall import Firewall, HeuristicThreatAnalyzer
from app.main import app


@pytest.fixture()
def banking() -> BankingService:
    """A fresh simulated bank, independent of the module singleton."""
    reset_demo_state()
    return BankingService()


@pytest.fixture()
def client(banking: BankingService) -> TestClient:
    """TestClient whose endpoints use the fresh ``banking`` instance."""
    app.dependency_overrides[get_banking_service] = lambda: banking
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture()
def firewall(banking: BankingService) -> Firewall:
    """Firewall with the deterministic heuristic analyzer."""
    return Firewall(banking=banking, analyzer=HeuristicThreatAnalyzer())


@pytest.fixture()
def firewall_factory(banking: BankingService):
    """Return a callable that builds a firewall with a custom analyzer."""

    def _factory(analyzer) -> Firewall:
        return Firewall(banking=banking, analyzer=analyzer)

    return _factory
