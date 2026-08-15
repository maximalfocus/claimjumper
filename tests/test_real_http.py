from __future__ import annotations

import socket
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
import uvicorn

from claimjumper.app import create_app
from claimjumper.config import fixed_clock
from tests.conftest import TEST_KEY


def available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def test_secure_service_over_real_loopback_http(tmp_path: Path) -> None:
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'http.db'}",
        clock=fixed_clock(datetime(2030, 1, 2, 12, 0, tzinfo=UTC)),
        verification_key=TEST_KEY,
    )
    port = available_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.01)
    assert server.started

    try:
        with httpx.Client(base_url=f"http://127.0.0.1:{port}") as client:
            assert client.get("/health").json()["status"] == "ok"
            fixtures = client.get("/demo/fixtures").json()["tokens"]
            before = client.get("/state").content
            forbidden = client.post(
                "/parcels/NPE-204/release",
                headers={"Authorization": f"Bearer {fixtures['courier']}"},
            )
            assert forbidden.status_code == 403
            assert client.get("/state").content == before
            released = client.post(
                "/parcels/NPE-204/release",
                headers={"Authorization": f"Bearer {fixtures['dispatcher']}"},
            )
            assert released.status_code == 200
            assert released.json()["parcel"]["status"] == "released"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        assert not thread.is_alive()
