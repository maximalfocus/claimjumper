from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

ISSUER = "https://issuer.northstar.invalid"
AUDIENCE = "northstar-parcel-api"
PARCEL_ID = "NPE-204"
DEMO_LABEL = "FICTIONAL LOCAL DEMO"


Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)


def fixed_clock(value: datetime) -> Clock:
    normalized = value.astimezone(UTC)
    return lambda: normalized


@dataclass(frozen=True)
class Settings:
    database_url: str
    clock: Clock

    @classmethod
    def from_environment(cls) -> Settings:
        database_url = os.getenv("CLAIMJUMPER_DATABASE_URL", "sqlite:////data/claimjumper.db")
        fixed_now = os.getenv("CLAIMJUMPER_NOW")
        if fixed_now is None:
            return cls(database_url=database_url, clock=utc_now)
        parsed = datetime.fromisoformat(fixed_now.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("CLAIMJUMPER_NOW must include a timezone")
        return cls(database_url=database_url, clock=fixed_clock(parsed))
