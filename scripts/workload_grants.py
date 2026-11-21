"""
workload_grants.py — Host-Granted Workload Capability Loader & Schema (ADR-0005)

Loads and validates /etc/homelab/grants.json (or HOMELAB_GRANTS_FILE) using strict
Pydantic v2 models (ConfigDict(extra="forbid")).
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

DEFAULT_GRANTS_FILE = Path("/etc/homelab/grants.json")
PRIVILEGED_GROUPS: frozenset[str] = frozenset({"0", "root", "wheel", "docker"})


class WorkloadGrantsError(Exception):
    """Raised when the host capability grants file fails integrity or schema checks."""


class WorkloadGrant(BaseModel):
    """Explicit host-granted capabilities for a single workload."""

    model_config = ConfigDict(extra="forbid")

    devices: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    readOnlyPaths: list[str] = Field(default_factory=list)

    @field_validator("groups")
    @classmethod
    def _validate_groups(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw in values:
            group = raw.strip()
            if not group:
                raise ValueError("Granted group entry cannot be empty.")
            if group.lower() in PRIVILEGED_GROUPS:
                raise ValueError(
                    f"Privileged group '{group}' cannot be granted to workloads."
                )
            cleaned.append(group)
        return cleaned

    @field_validator("devices", "readOnlyPaths")
    @classmethod
    def _validate_absolute_paths(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw in values:
            path_str = raw.strip()
            if not path_str:
                raise ValueError("Granted path entry cannot be empty.")
            posix = PurePosixPath(path_str)
            if not posix.is_absolute():
                raise ValueError(
                    f"Granted path '{path_str}' must be an absolute path."
                )
            if ".." in posix.parts:
                raise ValueError(
                    f"Granted path '{path_str}' must not contain '..' traversal."
                )
            cleaned.append(path_str)
        return cleaned


class GrantsRegistry(BaseModel):
    """Root schema for /etc/homelab/grants.json."""

    model_config = ConfigDict(extra="forbid")

    schemaVersion: Literal["1.0"] = "1.0"
    workloads: dict[str, WorkloadGrant] = Field(default_factory=dict)


def load_workload_grants(
    grants_file: Path | None = None,
    *,
    verify_permissions: bool | None = None,
) -> dict[str, WorkloadGrant]:
    """
    Load host-granted workload capabilities from grants_file or HOMELAB_GRANTS_FILE.

    - If the target file does not exist (and is not a symlink), returns {} (zero grants).
    - If the file is present (or is a symlink) and fails permission/integrity checks,
      is unreadable, or fails JSON/Pydantic validation, raises WorkloadGrantsError.
    """
    if grants_file is None:
        env_path = os.environ.get("HOMELAB_GRANTS_FILE", "").strip()
        target_path = Path(env_path) if env_path else DEFAULT_GRANTS_FILE
    else:
        target_path = grants_file

    should_verify = (
        (target_path == DEFAULT_GRANTS_FILE)
        if verify_permissions is None
        else verify_permissions
    )

    if not target_path.exists() and not target_path.is_symlink():
        return {}

    if should_verify:
        try:
            st = os.lstat(target_path)
        except OSError as exc:
            raise WorkloadGrantsError(
                f"Failed to stat grants file '{target_path}': {exc}"
            ) from exc

        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise WorkloadGrantsError(
                f"Grants file '{target_path}' must be a regular non-symlink file."
            )
        if st.st_uid != 0:
            raise WorkloadGrantsError(
                f"Grants file '{target_path}' must be owned by root (uid 0)."
            )
        if (st.st_mode & 0o022) != 0:
            raise WorkloadGrantsError(
                f"Grants file '{target_path}' must not be group- or world-writable."
            )

    try:
        raw_text = target_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise WorkloadGrantsError(
            f"Failed to read grants file '{target_path}': {exc}"
        ) from exc

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise WorkloadGrantsError(
            f"Malformed JSON in grants file '{target_path}': {exc}"
        ) from exc

    try:
        registry = GrantsRegistry.model_validate(payload)
    except ValidationError as exc:
        raise WorkloadGrantsError(
            f"Invalid schema in grants file '{target_path}': {exc}"
        ) from exc

    return registry.workloads
