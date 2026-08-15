from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from claimjumper.app import create_app
from claimjumper.auth import SecureVerifier
from claimjumper.config import fixed_clock

NOW = datetime(2030, 1, 2, 12, 0, tzinfo=UTC)
TEST_KEY = b"FICTIONAL-LOCAL-DEMO-KEY-32-BYTES!"


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    application = create_app(
        database_url=f"sqlite:///{tmp_path / 'claimjumper.db'}",
        clock=fixed_clock(NOW),
        verification_key=TEST_KEY,
    )
    with TestClient(application) as test_client:
        yield test_client


@pytest.fixture
def vulnerable_client(tmp_path: Path) -> Iterator[TestClient]:
    application = create_app(
        database_url=f"sqlite:///{tmp_path / 'vulnerable.db'}",
        clock=fixed_clock(NOW),
        mode="vulnerable",
        allow_vulnerable=True,
    )
    with TestClient(application) as test_client:
        yield test_client


def verifier(client: TestClient) -> SecureVerifier:
    application = cast(FastAPI, client.app)
    return cast(SecureVerifier, application.state.verifier)
