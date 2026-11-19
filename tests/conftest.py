"""Shared pytest fixtures for Canopy NixOS Core test suites."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Protocol

import pytest

_STRIPPED_WORKLOAD_ENV_VARS = frozenset(
    {"HOMELAB_DEPLOYMENTS_FILE", "WORKLOADS_DIR", "SITES_DIR"}
)
_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"


class IsolatedScriptRunner(Protocol):
    """Callable protocol for executing a Python expression in an isolated env."""

    def __call__(
        self, expr: str, extra_env: dict[str, str] | None = None
    ) -> str: ...


@pytest.fixture
def run_isolated_script_expr(tmp_path: Path) -> IsolatedScriptRunner:
    """
    Execute a Python expression in a clean subprocess with workload env vars stripped.

    Strips ``HOMELAB_DEPLOYMENTS_FILE``, ``WORKLOADS_DIR``, and ``SITES_DIR``,
    sets ``HOME`` to ``tmp_path`` and ``PYTHONPATH`` to ``scripts/``, and
    merges any optional ``extra_env`` overrides.
    """

    def _run(expr: str, extra_env: dict[str, str] | None = None) -> str:
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in _STRIPPED_WORKLOAD_ENV_VARS
        }
        env["HOME"] = str(tmp_path)
        env["PYTHONPATH"] = str(_SCRIPTS_DIR)
        if extra_env:
            env.update(extra_env)
        return subprocess.check_output(
            [sys.executable, "-c", expr],
            env=env,
            text=True,
        ).strip()

    return _run
