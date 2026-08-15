from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from datetime import timedelta
from typing import cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from claimjumper.auth import SecureVerifier
from claimjumper.domain import Role
from tests.conftest import NOW, verifier
from tests.test_secure_api import bearer


@pytest.mark.parametrize("fixture_name", ["unsigned_dispatcher", "expired_dispatcher"])
def test_vulnerable_impact_and_secure_rejection_use_fresh_state(
    client: TestClient,
    vulnerable_client: TestClient,
    fixture_name: str,
) -> None:
    secure_before = client.get("/state").content
    vulnerable_before = vulnerable_client.get("/state").content
    assert secure_before == vulnerable_before

    secure_token = client.get("/demo/fixtures").json()["tokens"][fixture_name]
    vulnerable_token = vulnerable_client.get("/demo/fixtures").json()["tokens"][fixture_name]
    secure_response = client.post("/parcels/NPE-204/release", headers=bearer(secure_token))
    vulnerable_response = vulnerable_client.post(
        "/parcels/NPE-204/release", headers=bearer(vulnerable_token)
    )

    assert secure_response.status_code == 401
    assert client.get("/state").content == secure_before
    assert vulnerable_response.status_code == 200
    assert vulnerable_response.json()["authenticated"] == {
        "sub": "mara",
        "role": "dispatcher",
    }
    assert vulnerable_client.get("/state").json()["parcels"] == [
        {"id": "NPE-204", "status": "released"}
    ]


@pytest.mark.parametrize("offset", [1, 0, -1])
def test_vulnerable_expiration_boundary_deliberately_accepts(
    vulnerable_client: TestClient, offset: int
) -> None:
    token = verifier(vulnerable_client).issue_token(
        "mara",
        Role.DISPATCHER,
        expires_at=NOW + timedelta(seconds=offset),
    )
    response = vulnerable_client.post("/parcels/NPE-204/release", headers=bearer(token))
    assert response.status_code == 200


def test_legitimate_behavior_is_identical_across_apps(
    client: TestClient, vulnerable_client: TestClient
) -> None:
    for current in (client, vulnerable_client):
        courier = verifier(current).fixtures().courier
        before = current.get("/state").content
        forbidden = current.post("/parcels/NPE-204/release", headers=bearer(courier))
        assert forbidden.status_code == 403
        assert forbidden.json() == {"detail": "forbidden"}
        assert current.get("/state").content == before

        dispatcher = verifier(current).fixtures().dispatcher
        released = current.post("/parcels/NPE-204/release", headers=bearer(dispatcher))
        assert released.status_code == 200
        assert released.json()["authenticated"] == {"sub": "mara", "role": "dispatcher"}
        assert released.json()["parcel"] == {"id": "NPE-204", "status": "released"}


def test_secure_and_vulnerable_apps_expose_the_same_routes(
    client: TestClient, vulnerable_client: TestClient
) -> None:
    secure_app = cast(FastAPI, client.app)
    vulnerable_app = cast(FastAPI, vulnerable_client.app)
    assert set(secure_app.openapi()["paths"]) == set(vulnerable_app.openapi()["paths"])


@pytest.mark.parametrize(
    "token_factory",
    [
        lambda current: current.issue_token(
            "mara", Role.DISPATCHER, signing_key=b"other-fictional-local-key-32-byte"
        ),
        lambda current: current.issue_token("mara", Role.DISPATCHER, issuer="wrong.invalid"),
        lambda current: current.issue_token("mara", Role.DISPATCHER, audience="wrong-audience"),
        lambda current: current.issue_token(
            "mara", Role.DISPATCHER, not_before=NOW + timedelta(seconds=1)
        ),
        lambda current: current.issue_token("nobody", Role.DISPATCHER),
        lambda current: current.issue_token("river", Role.DISPATCHER),
    ],
)
def test_vulnerable_verifier_retains_shared_safeguards(
    vulnerable_client: TestClient, token_factory: Callable[[SecureVerifier], str]
) -> None:
    current = verifier(vulnerable_client)
    token = token_factory(current)
    before = vulnerable_client.get("/state").content
    response = vulnerable_client.post("/parcels/NPE-204/release", headers=bearer(token))
    assert response.status_code == 401
    assert vulnerable_client.get("/state").content == before


@pytest.mark.parametrize("value", [None, "TRUE", "true ", "1"])
def test_vulnerable_entrypoint_fails_closed_without_exact_opt_in(value: str | None) -> None:
    environment = os.environ.copy()
    if value is None:
        environment.pop("ALLOW_VULNERABLE_DEMO", None)
    else:
        environment["ALLOW_VULNERABLE_DEMO"] = value
    result = subprocess.run(
        [sys.executable, "-c", "import claimjumper.vulnerable_app"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.returncode != 0
    assert "vulnerable demo disabled" in result.stderr


def test_vulnerable_entrypoint_accepts_exact_opt_in() -> None:
    environment = {**os.environ, "ALLOW_VULNERABLE_DEMO": "true"}
    result = subprocess.run(
        [sys.executable, "-c", "import claimjumper.vulnerable_app"],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert result.returncode == 0, result.stderr
