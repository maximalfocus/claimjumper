from __future__ import annotations

import argparse
import base64
import json
import time
import urllib.error
import urllib.request
from typing import Any

APPS = {
    "secure": "http://secure:8000",
    "vulnerable": "http://vulnerable:8000",
}


def request(
    base_url: str, path: str, *, method: str = "GET", token: str | None = None
) -> tuple[int, bytes, dict[str, str]]:
    headers: dict[str, str] = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    outgoing = urllib.request.Request(  # noqa: S310 - fixed internal demo URL
        f"{base_url}{path}", method=method, headers=headers
    )
    try:
        with urllib.request.urlopen(outgoing) as response:  # noqa: S310 - fixed demo URL
            return (
                response.status,
                response.read(),
                {key.lower(): value for key, value in response.headers.items()},
            )
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), {key.lower(): value for key, value in exc.headers.items()}


def wait_until_ready(base_url: str) -> None:
    for _ in range(100):
        try:
            status, _, _ = request(base_url, "/health")
            if status == 200:
                return
        except urllib.error.URLError:
            pass
        time.sleep(0.05)
    raise RuntimeError("fixed local demo service did not become ready")


def decode_segment(segment: str) -> dict[str, Any]:
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


def run_case(app_name: str, fixture_name: str) -> dict[str, Any]:
    base_url = APPS[app_name]
    wait_until_ready(base_url)
    request(base_url, "/demo/reset", method="POST")
    _, fixture_bytes, _ = request(base_url, "/demo/fixtures")
    token = json.loads(fixture_bytes)["tokens"][fixture_name]
    header_segment, claim_segment, _redacted_signature = token.split(".")
    _, before_bytes, _ = request(base_url, "/state")
    status, outcome_bytes, response_headers = request(
        base_url, "/parcels/NPE-204/release", method="POST", token=token
    )
    _, audit_bytes, _ = request(base_url, "/demo/audit-events")
    _, after_bytes, _ = request(base_url, "/state")
    audit_evidence = json.loads(audit_bytes)
    return {
        "application": app_name,
        "received": {
            "header": decode_segment(header_segment),
            "claims": decode_segment(claim_segment),
            "compact_token": "[REDACTED]",
            "signature": "[REDACTED]",
        },
        "verifier_verdict": "accepted" if status == 200 else "rejected",
        "http": {"status": status, "body": json.loads(outcome_bytes)},
        "audit_event": {
            "present": audit_evidence["count"] == 1,
            "count": audit_evidence["count"],
        },
        "bearer_challenge": response_headers.get("www-authenticate"),
        "state_unchanged": before_bytes == after_bytes,
        "before": json.loads(before_bytes),
        "after": json.loads(after_bytes),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one fixed fictional JWT contrast")
    parser.add_argument("case", choices=("unsigned", "expired"))
    selected = parser.parse_args().case
    fixture_name = {
        "unsigned": "unsigned_dispatcher",
        "expired": "expired_dispatcher",
    }[selected]

    results = [run_case("vulnerable", fixture_name), run_case("secure", fixture_name)]
    passed = (
        results[0]["http"]["status"] == 200
        and results[0]["after"]["parcels"] == [{"id": "NPE-204", "status": "released"}]
        and results[0]["audit_event"]["count"] == 0
        and results[1]["http"]["status"] == 401
        and results[1]["bearer_challenge"] == "Bearer"
        and results[1]["audit_event"]["count"] == 1
        and results[1]["state_unchanged"] is True
    )
    print(
        json.dumps(
            {
                "label": "FICTIONAL LOCAL DEMO",
                "case": selected,
                "configured_difference": (
                    "vulnerable verifier omits signature verification for alg:none"
                    if selected == "unsigned"
                    else "vulnerable verifier omits expiration enforcement"
                ),
                "results": results,
                "summary": "PASS" if passed else "FAIL",
            },
            indent=2,
            sort_keys=True,
        )
    )
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
