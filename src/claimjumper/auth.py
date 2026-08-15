from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final, Literal, cast

import jwt
from pydantic import BaseModel, ConfigDict, ValidationError

from claimjumper.config import AUDIENCE, ISSUER, Clock
from claimjumper.domain import USERS, Identity, Role

ALGORITHM: Final = "HS256"
REQUIRED_CLAIMS: Final = ("iss", "aud", "sub", "role", "iat", "nbf", "exp", "jti")


class TokenClaims(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    iss: str
    aud: str
    sub: str
    role: Literal["courier", "dispatcher"]
    iat: int
    nbf: int
    exp: int
    jti: str


class AuthenticationError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__("token rejected")
        self.reason = reason


@dataclass(frozen=True)
class FixtureTokens:
    courier: str
    dispatcher: str
    expired_dispatcher: str
    unsigned_dispatcher: str


class SecureVerifier:
    """Strict verifier; token parsing is never treated as authentication."""

    def __init__(self, clock: Clock, key: bytes | None = None) -> None:
        self._clock = clock
        self._key = key if key is not None else secrets.token_bytes(32)
        if len(self._key) < 32:
            raise ValueError("secure verification key must contain at least 256 bits")

    @staticmethod
    def _header(compact_token: str) -> dict[str, Any]:
        try:
            return jwt.get_unverified_header(compact_token)
        except jwt.PyJWTError as exc:
            raise AuthenticationError("malformed") from exc

    def _decode_signed(self, compact_token: str) -> dict[str, Any]:
        try:
            return cast(
                dict[str, Any],
                jwt.decode(
                    compact_token,
                    self._key,
                    algorithms=[ALGORITHM],
                    audience=AUDIENCE,
                    issuer=ISSUER,
                    options={
                        "require": list(REQUIRED_CLAIMS),
                        "verify_exp": False,
                        "verify_nbf": False,
                        "verify_iat": False,
                    },
                ),
            )
        except jwt.MissingRequiredClaimError as exc:
            raise AuthenticationError("missing_claim") from exc
        except jwt.InvalidIssuerError as exc:
            raise AuthenticationError("wrong_issuer") from exc
        except jwt.InvalidAudienceError as exc:
            raise AuthenticationError("wrong_audience") from exc
        except jwt.InvalidSignatureError as exc:
            raise AuthenticationError("invalid_signature") from exc
        except jwt.PyJWTError as exc:
            raise AuthenticationError("invalid_token") from exc

    def _identity(self, raw_claims: dict[str, Any], *, enforce_expiration: bool) -> Identity:
        if any(claim not in raw_claims for claim in REQUIRED_CLAIMS):
            raise AuthenticationError("missing_claim")
        try:
            claims = TokenClaims.model_validate(raw_claims)
        except ValidationError as exc:
            raise AuthenticationError("claim_schema") from exc

        if claims.iss != ISSUER:
            raise AuthenticationError("wrong_issuer")
        if claims.aud != AUDIENCE:
            raise AuthenticationError("wrong_audience")
        now = int(self._clock().timestamp())
        if claims.iat > now:
            raise AuthenticationError("issued_in_future")
        if claims.nbf > now:
            raise AuthenticationError("not_yet_valid")
        if enforce_expiration and claims.exp <= now:
            raise AuthenticationError("expired")

        user = USERS.get(claims.sub)
        if user is None:
            raise AuthenticationError("unknown_subject")
        if user.role.value != claims.role:
            raise AuthenticationError("inconsistent_role")
        return Identity(subject=user.subject, role=user.role)

    def verify(self, compact_token: str) -> Identity:
        header = self._header(compact_token)
        if header.get("alg") != ALGORITHM:
            raise AuthenticationError("algorithm_not_allowed")
        return self._identity(self._decode_signed(compact_token), enforce_expiration=True)

    def issue_token(
        self,
        subject: str,
        role: Role | str,
        *,
        issued_at: datetime | None = None,
        not_before: datetime | None = None,
        expires_at: datetime | None = None,
        issuer: str = ISSUER,
        audience: str = AUDIENCE,
        jti: str | None = None,
        omit: str | None = None,
        signing_key: bytes | None = None,
    ) -> str:
        now = issued_at or self._clock()
        claims: dict[str, Any] = {
            "iss": issuer,
            "aud": audience,
            "sub": subject,
            "role": role.value if isinstance(role, Role) else role,
            "iat": int(now.timestamp()),
            "nbf": int((not_before or now).timestamp()),
            "exp": int((expires_at or now + timedelta(minutes=10)).timestamp()),
            "jti": jti or f"fixture-{subject}",
        }
        if omit is not None:
            claims.pop(omit, None)
        resolved_key = self._key if signing_key is None else signing_key
        return jwt.encode(claims, resolved_key, algorithm=ALGORITHM)

    def fixtures(self) -> FixtureTokens:
        now = self._clock()
        courier = self.issue_token("river", Role.COURIER, jti="fixture-courier")
        unsigned_claims = jwt.decode(courier, options={"verify_signature": False})
        unsigned_claims.update(
            {"sub": "mara", "role": "dispatcher", "jti": "fixture-unsigned-dispatcher"}
        )
        return FixtureTokens(
            courier=courier,
            dispatcher=self.issue_token("mara", Role.DISPATCHER, jti="fixture-dispatcher"),
            expired_dispatcher=self.issue_token(
                "mara",
                Role.DISPATCHER,
                issued_at=now - timedelta(hours=1),
                not_before=now - timedelta(hours=1),
                expires_at=now - timedelta(seconds=1),
                jti="fixture-expired-dispatcher",
            ),
            unsigned_dispatcher=jwt.encode(unsigned_claims, key="", algorithm="none"),
        )


class VulnerableVerifier(SecureVerifier):
    """Deliberately incomplete local-only verifier for two fixed teaching cases."""

    def verify(self, compact_token: str) -> Identity:
        header = self._header(compact_token)
        algorithm = header.get("alg")
        if algorithm == "none":
            try:
                raw_claims = jwt.decode(compact_token, options={"verify_signature": False})
            except jwt.PyJWTError as exc:
                raise AuthenticationError("invalid_token") from exc
        elif algorithm == ALGORITHM:
            raw_claims = self._decode_signed(compact_token)
        else:
            raise AuthenticationError("algorithm_not_allowed")

        # INTENTIONALLY VULNERABLE: signature verification is absent for alg:none and
        # expiration is not enforced. All shared schema, identity, and authorization
        # checks remain active so these are the only contrasts in this slice.
        return self._identity(raw_claims, enforce_expiration=False)
