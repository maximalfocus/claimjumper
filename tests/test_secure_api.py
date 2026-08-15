from __future__ import annotations

import json
import logging
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from claimjumper.auth import SecureVerifier
from claimjumper.domain import Role
from tests.conftest import NOW, verifier

REJECTION_CASE_NAMES = (
    "malformed",
    "unsigned",
    "expired",
    "invalid_signature",
    "wrong_issuer",
    "wrong_audience",
    "not_yet_valid",
    "issued_in_future",
    "missing_claim",
    "unknown_subject",
    "inconsistent_role",
)


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def rejection_cases(secure: SecureVerifier) -> dict[str, str]:
    return {
        "malformed": "not-a-jwt",
        "unsigned": secure.fixtures().unsigned_dispatcher,
        "expired": secure.issue_token(
            "mara", Role.DISPATCHER, expires_at=NOW - timedelta(seconds=1)
        ),
        "invalid_signature": secure.issue_token(
            "mara", Role.DISPATCHER, signing_key=b"another-fictional-test-key-32bytes"
        ),
        "wrong_issuer": secure.issue_token("mara", Role.DISPATCHER, issuer="wrong.invalid"),
        "wrong_audience": secure.issue_token("mara", Role.DISPATCHER, audience="wrong-audience"),
        "not_yet_valid": secure.issue_token(
            "mara", Role.DISPATCHER, not_before=NOW + timedelta(seconds=1)
        ),
        "issued_in_future": secure.issue_token(
            "mara", Role.DISPATCHER, issued_at=NOW + timedelta(seconds=1)
        ),
        "missing_claim": secure.issue_token("mara", Role.DISPATCHER, omit="jti"),
        "unknown_subject": secure.issue_token("nobody", Role.DISPATCHER),
        "inconsistent_role": secure.issue_token("river", Role.DISPATCHER),
    }


@pytest.mark.parametrize("case", REJECTION_CASE_NAMES)
def test_secure_rejections_are_uniform_and_preserve_state(
    client: TestClient,
    caplog: pytest.LogCaptureFixture,
    case: str,
) -> None:
    secure = verifier(client)
    token = rejection_cases(secure)[case]
    before = client.get("/state").content
    caplog.set_level(logging.WARNING, logger="claimjumper.audit")

    response = client.post("/parcels/NPE-204/release", headers=bearer(token))

    assert response.status_code == 401
    assert response.json() == {"detail": "authentication failed"}
    assert response.headers["www-authenticate"] == "Bearer"
    request_id = response.headers["x-request-id"]
    assert len(request_id) == 24
    assert client.get("/state").content == before
    events = [json.loads(record.message) for record in caplog.records]
    audit_evidence = client.get("/demo/audit-events").json()
    assert audit_evidence == {"label": "FICTIONAL LOCAL DEMO", "count": 1}
    assert events == [
        {
            "event": "token_rejected",
            "outcome": "rejected",
            "reason": events[0]["reason"],
            "request_id": request_id,
        }
    ]
    rendered_logs = caplog.text
    assert token not in rendered_logs
    assert "Authorization" not in rendered_logs
    assert "FICTIONAL-LOCAL-DEMO-KEY" not in rendered_logs


def test_missing_bearer_uses_same_rejection_contract(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="claimjumper.audit")
    before = client.get("/state").content
    response = client.post("/parcels/NPE-204/release")
    assert response.status_code == 401
    assert response.json() == {"detail": "authentication failed"}
    assert response.headers["www-authenticate"] == "Bearer"
    assert client.get("/state").content == before
    assert len(caplog.records) == 1


def test_valid_courier_is_authenticated_then_forbidden(client: TestClient) -> None:
    token = verifier(client).fixtures().courier
    before = client.get("/state").content
    response = client.post("/parcels/NPE-204/release", headers=bearer(token))
    assert response.status_code == 403
    assert response.json() == {"detail": "forbidden"}
    assert client.get("/state").content == before


def test_valid_dispatcher_releases_once_and_conflicts_deterministically(
    client: TestClient,
) -> None:
    token = verifier(client).fixtures().dispatcher
    first = client.post("/parcels/NPE-204/release", headers=bearer(token))
    assert first.status_code == 200
    assert first.json()["authenticated"] == {"sub": "mara", "role": "dispatcher"}
    assert first.json()["parcel"] == {"id": "NPE-204", "status": "released"}
    assert client.get("/state").json()["parcels"] == [{"id": "NPE-204", "status": "released"}]

    second = client.post("/parcels/NPE-204/release", headers=bearer(token))
    assert second.status_code == 409
    assert second.json() == {"detail": "parcel already released"}


def test_injected_precommit_failure_rolls_back(client: TestClient) -> None:
    token = verifier(client).fixtures().dispatcher
    before = client.get("/state").content
    response = client.post(
        "/parcels/NPE-204/release",
        headers={**bearer(token), "X-Demo-Fail-Before-Commit": "true"},
    )
    assert response.status_code == 500
    assert response.json() == {"detail": "transaction failed"}
    assert client.get("/state").content == before


@pytest.mark.parametrize(
    ("offset", "expected"),
    [(1, 200), (0, 401), (-1, 401)],
)
def test_expiration_boundary_has_zero_leeway(
    client: TestClient, offset: int, expected: int
) -> None:
    token = verifier(client).issue_token(
        "mara",
        Role.DISPATCHER,
        expires_at=NOW + timedelta(seconds=offset),
    )
    response = client.post("/parcels/NPE-204/release", headers=bearer(token))
    assert response.status_code == expected


def test_demo_fixtures_are_process_local_and_labeled(client: TestClient) -> None:
    response = client.get("/demo/fixtures")
    assert response.status_code == 200
    payload = response.json()
    assert payload["label"] == "FICTIONAL LOCAL DEMO"
    assert set(payload["tokens"]) == {
        "courier",
        "dispatcher",
        "expired_dispatcher",
        "unsigned_dispatcher",
    }
    assert client.get("/demo/fixtures").json() == payload
    assert verifier(client).verify(payload["tokens"]["dispatcher"]).subject == "mara"


def test_reset_restores_canonical_snapshot(client: TestClient) -> None:
    token = verifier(client).fixtures().dispatcher
    client.post("/parcels/NPE-204/release", headers=bearer(token))
    reset = client.post("/demo/reset")
    assert reset.status_code == 200
    assert reset.json()["parcels"] == [{"id": "NPE-204", "status": "held"}]
