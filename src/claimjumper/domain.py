from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Role(StrEnum):
    COURIER = "courier"
    DISPATCHER = "dispatcher"


@dataclass(frozen=True)
class UserRecord:
    subject: str
    role: Role


@dataclass(frozen=True)
class Identity:
    subject: str
    role: Role


USERS: dict[str, UserRecord] = {
    "river": UserRecord(subject="river", role=Role.COURIER),
    "mara": UserRecord(subject="mara", role=Role.DISPATCHER),
}
