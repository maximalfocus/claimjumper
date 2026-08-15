from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from sqlalchemy import String, create_engine, delete, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from claimjumper.config import DEMO_LABEL, PARCEL_ID
from claimjumper.domain import USERS


class Base(DeclarativeBase):
    pass


class ParcelRow(Base):
    __tablename__ = "parcels"

    parcel_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)


class ParcelNotFoundError(Exception):
    pass


class ParcelConflictError(Exception):
    pass


class InjectedTransactionError(Exception):
    pass


@dataclass(frozen=True)
class Parcel:
    parcel_id: str
    status: Literal["held", "released"]


class ParcelRepository:
    def __init__(self, database_url: str) -> None:
        connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
        self.engine = create_engine(database_url, connect_args=connect_args)
        self.sessions = sessionmaker(self.engine, expire_on_commit=False)

    def initialize_fresh(self) -> None:
        Base.metadata.create_all(self.engine)
        with self.sessions.begin() as session:
            session.execute(delete(ParcelRow))
            session.add(ParcelRow(parcel_id=PARCEL_ID, status="held"))

    def snapshot(self) -> dict[str, object]:
        with self.sessions() as session:
            parcels = session.scalars(select(ParcelRow).order_by(ParcelRow.parcel_id)).all()
        return {
            "label": DEMO_LABEL,
            "users": [
                {"sub": user.subject, "role": user.role.value}
                for user in sorted(USERS.values(), key=lambda item: item.subject)
            ],
            "parcels": [{"id": parcel.parcel_id, "status": parcel.status} for parcel in parcels],
        }

    def release(self, parcel_id: str, *, fail_before_commit: bool = False) -> Parcel:
        with self.sessions() as session:
            with session.begin():
                row = session.get(ParcelRow, parcel_id)
                if row is None:
                    raise ParcelNotFoundError(parcel_id)
                if row.status == "released":
                    raise ParcelConflictError(parcel_id)
                row.status = "released"
                session.flush()
                if fail_before_commit:
                    raise InjectedTransactionError(parcel_id)
            return Parcel(parcel_id=row.parcel_id, status="released")
