from __future__ import annotations

from typing import Final

import jwt

from claimjumper.config import AUDIENCE, ISSUER

# Every value in this module is a conspicuously fictional, local-only teaching fixture.
FICTIONAL_WEAK_SECRET: Final = "FICTIONAL-NORTHSTAR-PARCEL"  # noqa: S105 - fictional demo secret
FICTIONAL_WEAK_SECRET_BYTES: Final = FICTIONAL_WEAK_SECRET.encode()
FICTIONAL_CANDIDATES: Final = (
    "FICTIONAL-BLUE-KITE",
    FICTIONAL_WEAK_SECRET,
    "FICTIONAL-MOONLIT-CRATE",
    "FICTIONAL-RAINBOW-DEPOT",
)

FIXED_VULNERABLE_COURIER_CLAIMS: Final = {
    "iss": ISSUER,
    "aud": AUDIENCE,
    "sub": "river",
    "role": "courier",
    "iat": 1893585600,
    "nbf": 1893585600,
    "exp": 1893586200,
    "jti": "fixture-courier",
}
FIXED_FORGED_DISPATCHER_CLAIMS: Final = {
    **FIXED_VULNERABLE_COURIER_CLAIMS,
    "sub": "mara",
    "role": "dispatcher",
    "jti": "fixture-recovered-dispatcher",
}

FIXED_VULNERABLE_COURIER_TOKEN: Final = jwt.encode(
    FIXED_VULNERABLE_COURIER_CLAIMS,
    FICTIONAL_WEAK_SECRET_BYTES,
    algorithm="HS256",
)
FIXED_FORGED_DISPATCHER_TOKEN: Final = jwt.encode(
    FIXED_FORGED_DISPATCHER_CLAIMS,
    FICTIONAL_WEAK_SECRET_BYTES,
    algorithm="HS256",
)
