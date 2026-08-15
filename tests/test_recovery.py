from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from claimjumper import recovery as recovery_module
from claimjumper.bounded_fixtures import (
    FICTIONAL_CANDIDATES,
    FIXED_FORGED_DISPATCHER_TOKEN,
    FIXED_VULNERABLE_COURIER_TOKEN,
)
from claimjumper.recovery import (
    RecoveryBoundaryError,
    fixed_list_has_no_match_for_secure_fixture,
    recover_fixed_vulnerable_fixture,
)
from tests.conftest import verifier
from tests.test_secure_api import bearer

ROOT = Path(__file__).resolve().parents[1]
RECOVERY_SCRIPT = ROOT / "scripts" / "recovery_case.py"

FORBIDDEN_ENVIRONMENT_INPUTS = {
    "CLAIMJUMPER_RECOVERY_TOKEN",
    "CLAIMJUMPER_RECOVERY_CANDIDATES",
    "CLAIMJUMPER_RECOVERY_KEY",
    "CLAIMJUMPER_RECOVERY_PATH",
    "CLAIMJUMPER_RECOVERY_URL",
    "CLAIMJUMPER_RECOVERY_OUTPUT",
}


def altered_fixed_token() -> str:
    replacement = "B" if FIXED_VULNERABLE_COURIER_TOKEN[-1] != "B" else "C"
    return FIXED_VULNERABLE_COURIER_TOKEN[:-1] + replacement


def test_recovery_accepts_only_the_checked_in_courier_token() -> None:
    result = recover_fixed_vulnerable_fixture(FIXED_VULNERABLE_COURIER_TOKEN)
    assert result.candidate_count == len(FICTIONAL_CANDIDATES)
    assert "FICTIONAL LOCAL DEMO" in result.fictional_match
    assert result.forged_dispatcher_token == FIXED_FORGED_DISPATCHER_TOKEN


@pytest.mark.parametrize(
    "external_token",
    [altered_fixed_token(), "not-a-jwt", FIXED_FORGED_DISPATCHER_TOKEN],
)
def test_recovery_refuses_altered_or_external_tokens_before_candidate_testing(
    external_token: str,
) -> None:
    with pytest.raises(RecoveryBoundaryError) as excinfo:
        recover_fixed_vulnerable_fixture(external_token)
    assert excinfo.value.attempted_candidates == 0


def test_each_built_in_candidate_is_attempted_at_most_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    original = recovery_module._signature_matches

    def counting(compact_token: str, candidate: bytearray) -> bool:
        nonlocal calls
        calls += 1
        return original(compact_token, candidate)

    monkeypatch.setattr(recovery_module, "_signature_matches", counting)
    result = recover_fixed_vulnerable_fixture(FIXED_VULNERABLE_COURIER_TOKEN)
    assert calls == len(FICTIONAL_CANDIDATES)
    assert result.candidate_count == len(FICTIONAL_CANDIDATES)

    calls = 0
    with pytest.raises(RecoveryBoundaryError):
        recover_fixed_vulnerable_fixture(altered_fixed_token())
    assert calls == 0


def test_fixed_candidate_list_finds_no_match_for_the_secure_courier_fixture(
    client: TestClient,
) -> None:
    secure_courier = verifier(client).fixtures().courier
    assert fixed_list_has_no_match_for_secure_fixture(secure_courier) is True


def test_weak_key_forgery_is_rejected_by_the_secure_app(client: TestClient) -> None:
    before = client.get("/state").content
    response = client.post(
        "/parcels/NPE-204/release", headers=bearer(FIXED_FORGED_DISPATCHER_TOKEN)
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "authentication failed"}
    assert response.headers["www-authenticate"] == "Bearer"
    assert client.get("/state").content == before
    assert client.get("/demo/audit-events").json() == {
        "label": "FICTIONAL LOCAL DEMO",
        "count": 1,
    }


def test_weak_key_forgery_releases_the_parcel_in_the_vulnerable_app(
    vulnerable_client: TestClient,
) -> None:
    response = vulnerable_client.post(
        "/parcels/NPE-204/release", headers=bearer(FIXED_FORGED_DISPATCHER_TOKEN)
    )
    assert response.status_code == 200
    assert vulnerable_client.get("/state").json()["parcels"] == [
        {"id": "NPE-204", "status": "released"}
    ]


def test_vulnerable_courier_fixture_is_byte_identical_to_the_fixed_recovery_token(
    vulnerable_client: TestClient,
) -> None:
    assert verifier(vulnerable_client).fixtures().courier == FIXED_VULNERABLE_COURIER_TOKEN


def run_recovery_cli(
    *arguments: str,
    environment: dict[str, str] | None = None,
    stdin_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    clean_environment = {
        key: value for key, value in os.environ.items() if key not in FORBIDDEN_ENVIRONMENT_INPUTS
    }
    command = [sys.executable, str(RECOVERY_SCRIPT), *arguments]
    if stdin_text is None:
        return subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            env=environment or clean_environment,
            stdin=subprocess.DEVNULL,
        )
    return subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=environment or clean_environment,
        input=stdin_text,
    )


def test_recovery_cli_prints_only_candidate_count_and_a_labeled_match() -> None:
    result = run_recovery_cli()
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert set(payload) == {"candidate_count", "match"}
    assert payload["candidate_count"] == len(FICTIONAL_CANDIDATES)
    assert "FICTIONAL LOCAL DEMO" in payload["match"]
    assert FIXED_VULNERABLE_COURIER_TOKEN not in result.stdout
    assert FIXED_FORGED_DISPATCHER_TOKEN not in result.stdout


@pytest.mark.parametrize("arguments", [("--help",), ("extra",), ("/tmp/candidates.txt",)])
def test_recovery_cli_rejects_command_line_inputs(arguments: tuple[str, ...]) -> None:
    result = run_recovery_cli(*arguments)
    assert result.returncode != 0
    assert "no command-line arguments" in result.stderr


@pytest.mark.parametrize("variable", sorted(FORBIDDEN_ENVIRONMENT_INPUTS))
def test_recovery_cli_rejects_environment_overrides(variable: str) -> None:
    environment = {
        key: value for key, value in os.environ.items() if key not in FORBIDDEN_ENVIRONMENT_INPUTS
    }
    environment[variable] = "fictional-override"
    result = run_recovery_cli(environment=environment)
    assert result.returncode != 0
    assert "no environment overrides" in result.stderr


def test_recovery_cli_rejects_stdin_input() -> None:
    result = run_recovery_cli(stdin_text="fictional-candidate")
    assert result.returncode != 0
    assert "no stdin" in result.stderr
