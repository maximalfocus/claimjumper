from __future__ import annotations

import argparse
import base64
import json
import urllib.error
import urllib.request
from typing import Any

BASE_URL = "http://127.0.0.1:8000"


def request(path: str, *, method: str = "GET", token: str | None = None) -> tuple[int, Any]:
    headers: dict[str, str] = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    outgoing = urllib.request.Request(  # noqa: S310 - fixed loopback URL
        f"{BASE_URL}{path}", method=method, headers=headers
    )
    try:
        with urllib.request.urlopen(outgoing) as response:  # noqa: S310 - fixed loopback URL
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, json.load(exc)


def decode_segment(segment: str) -> dict[str, Any]:
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run one fixed fictional secure-API case")
    parser.add_argument(
        "case",
        choices=("courier", "dispatcher", "expired_dispatcher", "unsigned_dispatcher"),
    )
    case = parser.parse_args().case

    request("/demo/reset", method="POST")
    _, fixture_payload = request("/demo/fixtures")
    token = fixture_payload["tokens"][case]
    header_segment, claim_segment, _redacted_signature = token.split(".")
    _, before = request("/state")
    status, outcome = request("/parcels/NPE-204/release", method="POST", token=token)
    _, after = request("/state")
    print(
        json.dumps(
            {
                "label": "FICTIONAL LOCAL DEMO",
                "case": case,
                "received": {
                    "header": decode_segment(header_segment),
                    "claims": decode_segment(claim_segment),
                    "compact_token": "[REDACTED]",
                    "signature": "[REDACTED]",
                },
                "configured_policy": {
                    "algorithm": "HS256",
                    "issuer": "https://issuer.northstar.invalid",
                    "audience": "northstar-parcel-api",
                    "leeway_seconds": 0,
                },
                "verifier_verdict": "accepted" if status in {200, 403} else "rejected",
                "http": {"status": status, "body": outcome},
                "before": before,
                "after": after,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
