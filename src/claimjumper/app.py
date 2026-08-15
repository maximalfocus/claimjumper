from __future__ import annotations

import json
import logging
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse

from claimjumper.auth import AuthenticationError, SecureVerifier
from claimjumper.config import DEMO_LABEL, Clock, Settings
from claimjumper.database import (
    InjectedTransactionError,
    ParcelConflictError,
    ParcelNotFoundError,
    ParcelRepository,
)
from claimjumper.domain import Role

audit_logger = logging.getLogger("claimjumper.audit")
AUTH_FAILURE_BODY = {"detail": "authentication failed"}


def _request_id() -> str:
    return secrets.token_hex(12)


def _rejection(reason: str, request_id: str) -> JSONResponse:
    audit_logger.warning(
        json.dumps(
            {
                "event": "token_rejected",
                "outcome": "rejected",
                "reason": reason,
                "request_id": request_id,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return JSONResponse(
        status_code=401,
        content=AUTH_FAILURE_BODY,
        headers={"WWW-Authenticate": "Bearer", "X-Request-ID": request_id},
    )


def create_app(
    *,
    database_url: str | None = None,
    clock: Clock | None = None,
    verification_key: bytes | None = None,
) -> FastAPI:
    settings = Settings.from_environment()
    resolved_clock = clock or settings.clock
    repository = ParcelRepository(database_url or settings.database_url)
    verifier = SecureVerifier(resolved_clock, verification_key)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        repository.initialize_fresh()
        yield
        repository.engine.dispose()

    application = FastAPI(
        title="Northstar Parcel Exchange — secure API",
        version="0.1.0",
        lifespan=lifespan,
    )
    application.state.repository = repository
    application.state.verifier = verifier

    @application.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "label": DEMO_LABEL}

    @application.get("/state")
    def state() -> dict[str, object]:
        return repository.snapshot()

    @application.post("/demo/reset")
    def reset() -> dict[str, object]:
        repository.initialize_fresh()
        return repository.snapshot()

    @application.get("/demo/fixtures")
    def fixtures() -> dict[str, object]:
        issued = verifier.fixtures()
        return {
            "label": DEMO_LABEL,
            "tokens": {
                "courier": issued.courier,
                "dispatcher": issued.dispatcher,
                "expired_dispatcher": issued.expired_dispatcher,
                "unsigned_dispatcher": issued.unsigned_dispatcher,
            },
        }

    @application.post("/parcels/{parcel_id}/release", response_model=None)
    def release(
        parcel_id: str,
        authorization: Annotated[str | None, Header()] = None,
        x_demo_fail_before_commit: Annotated[str | None, Header()] = None,
    ) -> JSONResponse | dict[str, object]:
        correlation_id = _request_id()
        if authorization is None or not authorization.startswith("Bearer "):
            return _rejection("missing_bearer", correlation_id)
        compact_token = authorization.removeprefix("Bearer ")
        if not compact_token or " " in compact_token:
            return _rejection("malformed", correlation_id)
        try:
            identity = verifier.verify(compact_token)
        except AuthenticationError as exc:
            return _rejection(exc.reason, correlation_id)

        if identity.role is not Role.DISPATCHER:
            return JSONResponse(
                status_code=403,
                content={"detail": "forbidden"},
                headers={"X-Request-ID": correlation_id},
            )

        try:
            parcel = repository.release(
                parcel_id,
                fail_before_commit=x_demo_fail_before_commit == "true",
            )
        except ParcelNotFoundError:
            return JSONResponse(status_code=404, content={"detail": "parcel not found"})
        except ParcelConflictError:
            return JSONResponse(status_code=409, content={"detail": "parcel already released"})
        except InjectedTransactionError:
            return JSONResponse(status_code=500, content={"detail": "transaction failed"})
        return {
            "label": DEMO_LABEL,
            "authenticated": {"sub": identity.subject, "role": identity.role.value},
            "authorization": "allowed",
            "parcel": {"id": parcel.parcel_id, "status": parcel.status},
            "request_id": correlation_id,
        }

    return application


app = create_app()
