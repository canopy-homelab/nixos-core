"""Unit tests for Pydantic v2 workload capability grants loader (ADR-0005)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from workload_grants import (
    GrantsRegistry,
    WorkloadGrant,
    WorkloadGrantsError,
    load_workload_grants,
)


def test_load_workload_grants_absent_file_returns_empty(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.json"
    assert load_workload_grants(missing) == {}


def test_load_workload_grants_honors_env_var_when_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    grants_path = tmp_path / "grants.json"
    grants_path.write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "workloads": {
                    "media": {
                        "devices": ["/dev/dri/renderD128"],
                        "groups": ["render", "303"],
                        "readOnlyPaths": ["/mnt/media"],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("HOMELAB_GRANTS_FILE", str(grants_path))
    loaded = load_workload_grants(verify_permissions=False)
    assert "media" in loaded
    assert loaded["media"].devices == ["/dev/dri/renderD128"]
    assert loaded["media"].groups == ["render", "303"]
    assert loaded["media"].readOnlyPaths == ["/mnt/media"]


@pytest.mark.parametrize("bad_group", ["0", "root", "wheel", "docker", "ROOT", " wheel "])
def test_workload_grant_rejects_privileged_groups(bad_group: str) -> None:
    with pytest.raises(ValidationError):
        WorkloadGrant(groups=[bad_group])


@pytest.mark.parametrize(
    "bad_path",
    [
        "dev/dri/renderD128",
        "../etc/passwd",
        "/dev/../etc/shadow",
        "/mnt/media/..",
        "",
    ],
)
def test_workload_grant_rejects_relative_and_traversal_paths(bad_path: str) -> None:
    with pytest.raises(ValidationError):
        WorkloadGrant(devices=[bad_path])
    with pytest.raises(ValidationError):
        WorkloadGrant(readOnlyPaths=[bad_path])


def test_grants_registry_rejects_extra_fields_and_bad_schema_version() -> None:
    with pytest.raises(ValidationError):
        GrantsRegistry.model_validate(
            {
                "schemaVersion": "1.0",
                "workloads": {"app": {"devices": [], "extra_field": True}},
            }
        )
    with pytest.raises(ValidationError):
        GrantsRegistry.model_validate({"schemaVersion": "2.0", "workloads": {}})


def test_load_workload_grants_malformed_json_fails_closed(tmp_path: Path) -> None:
    grants_path = tmp_path / "grants.json"
    grants_path.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(WorkloadGrantsError):
        load_workload_grants(grants_path)


def test_load_workload_grants_unreadable_file_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    grants_path = tmp_path / "grants.json"
    grants_path.write_text('{"schemaVersion": "1.0", "workloads": {}}', encoding="utf-8")

    def raise_perm_error(self: Path, *args: object, **kwargs: object) -> str:
        raise PermissionError("Permission denied")

    monkeypatch.setattr(Path, "read_text", raise_perm_error)
    with pytest.raises(WorkloadGrantsError, match="read"):
        load_workload_grants(grants_path)


def test_load_workload_grants_verify_permissions_rejects_symlink(tmp_path: Path) -> None:
    real_file = tmp_path / "real.json"
    real_file.write_text('{"schemaVersion": "1.0", "workloads": {}}', encoding="utf-8")
    link_file = tmp_path / "grants.json"
    link_file.symlink_to(real_file)

    with pytest.raises(WorkloadGrantsError, match="symlink"):
        load_workload_grants(link_file, verify_permissions=True)


def test_load_workload_grants_verify_permissions_rejects_non_root_and_writable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    grants_path = tmp_path / "grants.json"
    grants_path.write_text('{"schemaVersion": "1.0", "workloads": {}}', encoding="utf-8")

    # Non-root owner
    monkeypatch.setattr(
        os,
        "lstat",
        lambda _p: SimpleNamespace(st_mode=0o100640, st_uid=1000),
    )
    with pytest.raises(WorkloadGrantsError, match="root"):
        load_workload_grants(grants_path, verify_permissions=True)

    # Group/world writable even if root-owned
    monkeypatch.setattr(
        os,
        "lstat",
        lambda _p: SimpleNamespace(st_mode=0o100664, st_uid=0),
    )
    with pytest.raises(WorkloadGrantsError, match="writable"):
        load_workload_grants(grants_path, verify_permissions=True)

    # Valid root-owned 0640 regular file
    monkeypatch.setattr(
        os,
        "lstat",
        lambda _p: SimpleNamespace(st_mode=0o100640, st_uid=0),
    )
    assert load_workload_grants(grants_path, verify_permissions=True) == {}
