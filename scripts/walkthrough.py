from __future__ import annotations

import json
import sys
import time
from typing import Any

from contrast_case import APPS, decode_segment, request, run_case, wait_until_ready

from claimjumper.recovery import (
    fixed_list_has_no_match_for_secure_fixture,
    recover_fixed_vulnerable_fixture,
)


def token_view(compact_token: str) -> dict[str, Any]:
    header, claims, _redacted_signature = compact_token.split(".")
    return {
        "header": decode_segment(header),
        "claims": decode_segment(claims),
        "compact_token": "[REDACTED]",
        "signature": "[REDACTED]",
    }


def fixed_fixture(app_name: str, fixture_name: str) -> str:
    _, payload, _ = request(APPS[app_name], "/demo/fixtures")
    return str(json.loads(payload)["tokens"][fixture_name])


def reset(app_name: str) -> bytes:
    request(APPS[app_name], "/demo/reset", method="POST")
    _, state, _ = request(APPS[app_name], "/state")
    return state


def contrast(case_name: str, fixture_name: str) -> dict[str, Any]:
    results = [run_case("vulnerable", fixture_name), run_case("secure", fixture_name)]
    passed = (
        results[0]["http"]["status"] == 200
        and results[0]["after"]["parcels"] == [{"id": "NPE-204", "status": "released"}]
        and results[1]["http"]["status"] == 401
        and results[1]["audit_event"]["count"] == 1
        and results[1]["state_unchanged"] is True
    )
    return {"case": case_name, "results": results, "summary": "PASS" if passed else "FAIL"}


def weak_secret_case() -> dict[str, Any]:
    vulnerable_before = reset("vulnerable")
    secure_before = reset("secure")
    vulnerable_courier = fixed_fixture("vulnerable", "courier")
    secure_courier = fixed_fixture("secure", "courier")

    recovery = recover_fixed_vulnerable_fixture(vulnerable_courier)
    strong_counterproof = fixed_list_has_no_match_for_secure_fixture(secure_courier)
    forged = recovery.forged_dispatcher_token
    vulnerable_status, vulnerable_body, _ = request(
        APPS["vulnerable"],
        "/parcels/NPE-204/release",
        method="POST",
        token=forged,
    )
    secure_status, secure_body, secure_headers = request(
        APPS["secure"],
        "/parcels/NPE-204/release",
        method="POST",
        token=forged,
    )
    _, vulnerable_after, _ = request(APPS["vulnerable"], "/state")
    _, secure_after, _ = request(APPS["secure"], "/state")
    _, secure_audit, _ = request(APPS["secure"], "/demo/audit-events")
    secure_audit_count = json.loads(secure_audit)["count"]

    passed = (
        recovery.candidate_count == 4
        and strong_counterproof
        and vulnerable_status == 200
        and json.loads(vulnerable_after)["parcels"] == [{"id": "NPE-204", "status": "released"}]
        and secure_status == 401
        and secure_headers.get("www-authenticate") == "Bearer"
        and secure_before == secure_after
        and secure_audit_count == 1
    )
    return {
        "case": "weak_secret",
        "recovery": {
            "candidate_count": recovery.candidate_count,
            "match": recovery.fictional_match,
            "network_requests": 0,
            "forged_token": "[REDACTED]",
        },
        "strong_key_counterproof": {"candidate_match": not strong_counterproof},
        "received": token_view(forged),
        "results": [
            {
                "application": "vulnerable",
                "http": {"status": vulnerable_status, "body": json.loads(vulnerable_body)},
                "before": json.loads(vulnerable_before),
                "after": json.loads(vulnerable_after),
            },
            {
                "application": "secure",
                "http": {"status": secure_status, "body": json.loads(secure_body)},
                "audit_event": {"count": secure_audit_count, "present": secure_audit_count == 1},
                "state_unchanged": secure_before == secure_after,
                "before": json.loads(secure_before),
                "after": json.loads(secure_after),
            },
        ],
        "summary": "PASS" if passed else "FAIL",
    }


def legitimate_case(case_name: str, fixture_name: str, expected_status: int) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    passed = True
    for app_name in ("vulnerable", "secure"):
        before = reset(app_name)
        token = fixed_fixture(app_name, fixture_name)
        status, body, _ = request(
            APPS[app_name], "/parcels/NPE-204/release", method="POST", token=token
        )
        _, after, _ = request(APPS[app_name], "/state")
        expected_unchanged = expected_status == 403
        current_pass = status == expected_status and (before == after) is expected_unchanged
        passed = passed and current_pass
        results.append(
            {
                "application": app_name,
                "received": token_view(token),
                "authentication": "accepted",
                "authorization": "denied" if status == 403 else "allowed",
                "http": {"status": status, "body": json.loads(body)},
                "before": json.loads(before),
                "after": json.loads(after),
            }
        )
    return {"case": case_name, "results": results, "summary": "PASS" if passed else "FAIL"}


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("integrated walkthrough accepts no arguments")
    started = time.monotonic()
    for base_url in APPS.values():
        wait_until_ready(base_url)

    cases = [
        contrast("unsigned", "unsigned_dispatcher"),
        contrast("expired", "expired_dispatcher"),
        weak_secret_case(),
        legitimate_case("valid_courier", "courier", 403),
        legitimate_case("valid_dispatcher", "dispatcher", 200),
    ]
    elapsed = time.monotonic() - started
    passed = all(case["summary"] == "PASS" for case in cases) and elapsed < 300
    print(
        json.dumps(
            {
                "label": "FICTIONAL LOCAL DEMO",
                "fixed_order": [case["case"] for case in cases],
                "cases": cases,
                "elapsed_seconds": round(elapsed, 3),
                "overall": "PASS" if passed else "FAIL",
            },
            indent=2,
            sort_keys=True,
        )
    )
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
