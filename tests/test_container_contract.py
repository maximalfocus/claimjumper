from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import yaml

ROOT = Path(__file__).resolve().parents[1]


def service(config: dict[str, Any], name: str) -> dict[str, Any]:
    return cast(dict[str, Any], config["services"][name])


def test_secure_service_is_the_only_default_and_is_hardened() -> None:
    config = yaml.safe_load((ROOT / "compose.yaml").read_text())
    assert set(config["services"]) == {"secure", "vulnerable", "walkthrough", "verify"}
    assert "profiles" not in service(config, "secure")
    assert service(config, "verify")["profiles"] == ["tools"]
    assert service(config, "vulnerable")["profiles"] == ["vulnerable"]
    assert service(config, "walkthrough")["profiles"] == ["vulnerable"]

    secure = service(config, "secure")
    assert secure["ports"] == ["127.0.0.1:8000:8000"]
    assert secure["read_only"] is True
    assert secure["user"] == "65532:65532"
    assert secure["cap_drop"] == ["ALL"]
    assert secure["security_opt"] == ["no-new-privileges:true"]
    assert secure["pids_limit"] == 128
    assert any(item.startswith("/data:rw,noexec,nosuid") for item in secure["tmpfs"])
    assert any(item.startswith("/tmp:rw,noexec,nosuid") for item in secure["tmpfs"])
    assert config["networks"]["secure"]["internal"] is True


def test_vulnerable_service_requires_two_opt_ins_and_has_no_external_egress() -> None:
    config = yaml.safe_load((ROOT / "compose.yaml").read_text())
    vulnerable = service(config, "vulnerable")
    assert vulnerable["profiles"] == ["vulnerable"]
    assert vulnerable["environment"]["ALLOW_VULNERABLE_DEMO"] == ("${ALLOW_VULNERABLE_DEMO:-}")
    assert "claimjumper.vulnerable_app:app" in vulnerable["command"]
    assert vulnerable["ports"] == ["127.0.0.1:8001:8000"]
    assert vulnerable["networks"] == ["vulnerable"]
    assert config["networks"]["vulnerable"]["internal"] is True
    assert vulnerable["read_only"] is True
    assert vulnerable["user"] == "65532:65532"
    assert vulnerable["cap_drop"] == ["ALL"]
    assert vulnerable["security_opt"] == ["no-new-privileges:true"]


def test_image_is_version_and_digest_pinned_and_runs_nonroot() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "python:3.13.7-slim-bookworm@sha256:" in dockerfile
    assert "uv==0.12.4" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert "--no-access-log" in dockerfile
