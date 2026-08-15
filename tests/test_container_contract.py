from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml

ROOT = Path(__file__).resolve().parents[1]


def service(config: dict[str, Any], name: str) -> dict[str, Any]:
    return cast(dict[str, Any], config["services"][name])


def test_secure_service_is_the_only_default_and_is_hardened() -> None:
    config = yaml.safe_load((ROOT / "compose.yaml").read_text())
    assert set(config["services"]) == {"secure", "verify"}
    assert "profiles" not in service(config, "secure")
    assert service(config, "verify")["profiles"] == ["tools"]

    secure = service(config, "secure")
    assert secure["ports"] == ["127.0.0.1:8000:8000"]
    assert secure["read_only"] is True
    assert secure["user"] == "65532:65532"
    assert secure["cap_drop"] == ["ALL"]
    assert secure["security_opt"] == ["no-new-privileges:true"]
    assert secure["pids_limit"] == 128
    assert any(item.startswith("/data:rw,noexec,nosuid") for item in secure["tmpfs"])
    assert any(item.startswith("/tmp:rw,noexec,nosuid") for item in secure["tmpfs"])
    assert config["networks"]["demo"]["internal"] is True


def test_image_is_version_and_digest_pinned_and_runs_nonroot() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "python:3.13.7-slim-bookworm@sha256:" in dockerfile
    assert "uv==0.12.4" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert "--no-access-log" in dockerfile
