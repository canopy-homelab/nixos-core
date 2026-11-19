"""
Security and structural tests for the read-only `agents` SSH user,
`ForceCommand` allowlist wrapper, and loopback-only `socket-proxy` binding.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

CORE_ROOT = Path(__file__).resolve().parent.parent.parent
NIXOS_CONFIG = CORE_ROOT / "nixos" / "configuration.nix"
COMPOSE_FILE = CORE_ROOT / "docker-compose.yml"
FORCE_COMMAND_SCRIPT = CORE_ROOT / "nixos" / "scripts" / "agents-force-command.sh"

EXPECTED_AGENT_PUBKEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIE1pxTdygG5696q0jT7clfJZWtx48ugfUjpzvkHzovVd "
    "canopy-agents"
)


def _extract_nix_block(content: str, header_pattern: str) -> str:
    """Extract a brace-delimited Nix attribute block starting at header_pattern."""
    match = re.search(header_pattern, content)
    assert match is not None, f"Missing Nix block matching: {header_pattern}"
    pos = match.end()
    # Skip `let ... in` bindings if present before the attribute set `{ ... }`
    tail = content[pos:]
    if re.match(r"\s*let\b", tail):
        in_match = re.search(r"\bin\s*\{", tail)
        assert in_match is not None, f"Missing 'in {{' for let-block: {header_pattern}"
        start = pos + in_match.end() - 1
    else:
        start = content.find("{", pos)
    assert start != -1, f"Opening brace not found for: {header_pattern}"
    depth = 0
    for idx in range(start, len(content)):
        ch = content[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return content[start : idx + 1]
    raise AssertionError(f"Unclosed Nix block for: {header_pattern}")


def _setup_mock_bin(tmp_path: Path) -> tuple[Path, Path]:
    """Create mock docker, journalctl, and appctl binaries that log invocations."""
    mock_bin = tmp_path / "mock_bin"
    mock_bin.mkdir()
    invocations_log = tmp_path / "invocations.log"
    bash_bin = shutil.which("bash") or "/bin/bash"

    for cmd in ("docker", "journalctl", "appctl"):
        stub = mock_bin / cmd
        stub.write_text(
            f"#!{bash_bin}\n"
            f'printf "%s|%s|%s|%s|%s\\n" '
            f'"{cmd}" "$*" "${{CORE_DIR:-}}" "${{WORKLOADS_DIR:-}}" "${{DOCKER_HOST:-}}" '
            f'>> "{invocations_log}"\n',
            encoding="utf-8",
        )
        stub.chmod(0o755)

    return mock_bin, invocations_log


def _run_force_command(
    ssh_original_command: str | None,
    tmp_path: Path,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Execute agents-force-command.sh with isolated mock PATH and SSH_ORIGINAL_COMMAND."""
    assert FORCE_COMMAND_SCRIPT.exists(), (
        f"ForceCommand script not found at {FORCE_COMMAND_SCRIPT}"
    )
    mock_bin, invocations_log = _setup_mock_bin(tmp_path)
    env = {
        "PATH": f"{mock_bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
        "HOME": str(tmp_path),
    }
    if ssh_original_command is not None:
        env["SSH_ORIGINAL_COMMAND"] = ssh_original_command

    bash_bin = shutil.which("bash") or "/bin/bash"
    proc = subprocess.run(
        [bash_bin, str(FORCE_COMMAND_SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc, invocations_log


def test_socket_proxy_binds_loopback_only():
    """Ensure socket-proxy publishes port 2375 strictly on 127.0.0.1."""
    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    services = compose.get("services", {})
    assert "socket-proxy" in services, "socket-proxy service must exist"

    ports = services["socket-proxy"].get("ports", [])
    assert isinstance(ports, list) and len(ports) > 0, (
        "socket-proxy must declare non-empty ports list"
    )
    assert all(isinstance(p, str) and p.startswith("127.0.0.1:") for p in ports), (
        f"Every socket-proxy port must bind strictly to 127.0.0.1, got: {ports!r}"
    )
    assert "127.0.0.1:2375:2375" in ports, (
        "socket-proxy must bind 127.0.0.1:2375:2375"
    )


def test_nixos_agents_user_least_privilege():
    """Verify users.users.agents has read-only groups and excludes wheel/docker."""
    content = NIXOS_CONFIG.read_text(encoding="utf-8")
    agents_block = _extract_nix_block(content, r"users\.users\.agents\s*=")

    assert re.search(r"isNormalUser\s*=\s*true\s*;", agents_block), (
        "users.users.agents must set isNormalUser = true"
    )
    assert EXPECTED_AGENT_PUBKEY in agents_block, (
        "users.users.agents must configure the canopy-agents SSH public key"
    )

    groups_match = re.search(r"extraGroups\s*=\s*\[(.*?)\]\s*;", agents_block, re.DOTALL)
    assert groups_match is not None, "users.users.agents must declare extraGroups"
    groups_text = groups_match.group(1)

    actual_groups = set(re.findall(r'"([^"]+)"', groups_text))
    assert actual_groups == {"homelab-operators", "systemd-journal"}, (
        f"agents extraGroups must be strictly {{'homelab-operators', 'systemd-journal'}}, got: {actual_groups!r}"
    )


def test_nixos_openssh_match_user_agents_hardening():
    """Verify services.openssh configures Match User agents with ForceCommand and hardening."""
    content = NIXOS_CONFIG.read_text(encoding="utf-8")
    ssh_block = _extract_nix_block(content, r"services\.openssh\s*=")

    assert "Match User agents" in ssh_block, (
        "services.openssh must configure Match User agents"
    )
    match_section = ssh_block[ssh_block.index("Match User agents") :]

    required_directives = [
        r"ForceCommand\s+\S*agents-force-command\b",
        r"AllowTcpForwarding\s+no",
        r"X11Forwarding\s+no",
        r"AllowAgentForwarding\s+no",
        r"PermitTTY\s+no",
        r"PasswordAuthentication\s+no",
    ]
    for pattern in required_directives:
        assert re.search(pattern, match_section), (
            f"Match User agents must include directive matching: {pattern}"
        )


def test_force_command_script_has_no_eval_or_sh_c():
    """Ensure agents-force-command.sh never uses eval or subshell invocation."""
    assert FORCE_COMMAND_SCRIPT.exists(), (
        f"ForceCommand script not found at {FORCE_COMMAND_SCRIPT}"
    )
    content = FORCE_COMMAND_SCRIPT.read_text(encoding="utf-8")
    assert "eval " not in content, "Dangerous 'eval' detected in ForceCommand script"
    assert "sh -c" not in content, "Dangerous 'sh -c' detected in ForceCommand script"
    assert "bash -c" not in content, "Dangerous 'bash -c' detected in ForceCommand script"


def test_force_command_exports_expected_environment(tmp_path: Path):
    """Verify ForceCommand exports CORE_DIR, WORKLOADS_DIR, and loopback DOCKER_HOST."""
    proc, invocations_log = _run_force_command("docker ps", tmp_path)
    assert proc.returncode == 0, f"Unexpected failure: {proc.stderr}"
    lines = invocations_log.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    cmd, args, core_dir, workloads_dir, docker_host = lines[0].split("|")
    assert cmd == "docker"
    assert args == "ps"
    assert core_dir == "/home/operator/Core"
    assert workloads_dir == "/home/operator/Workloads"
    assert docker_host == "tcp://127.0.0.1:2375"


@pytest.mark.parametrize(
    ("command", "expected_bin", "expected_args"),
    [
        ("docker ps", "docker", "ps"),
        ("docker ps -a --format {{.Names}}", "docker", "ps -a --format {{.Names}}"),
        ("docker logs --tail 50 traefik", "docker", "logs --tail 50 traefik"),
        ("docker inspect traefik", "docker", "inspect traefik"),
        (
            "journalctl -u homelab-appctl -n 50 --no-pager",
            "journalctl",
            "-u homelab-appctl -n 50 --no-pager",
        ),
        ("appctl list --core", "appctl", "list --core"),
        ("appctl status", "appctl", "status"),
        ("appctl info traefik", "appctl", "info traefik"),
        ("appctl logs traefik", "appctl", "logs traefik"),
        ("appctl ssl --all", "appctl", "ssl --all"),
        ("appctl health", "appctl", "health"),
        ("appctl resolve traefik", "appctl", "resolve traefik"),
    ],
)
def test_force_command_allows_read_only_commands(
    tmp_path: Path, command: str, expected_bin: str, expected_args: str
):
    """Verify allowlisted read-only commands execute cleanly with exact arguments."""
    proc, invocations_log = _run_force_command(command, tmp_path)
    assert proc.returncode == 0, f"Allowed command '{command}' failed: {proc.stderr}"
    lines = invocations_log.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    cmd, args, *_ = lines[0].split("|")
    assert cmd == expected_bin
    assert args == expected_args


@pytest.mark.parametrize(
    "bad_command",
    [
        None,
        "",
        "   ",
        "docker ps; id",
        "docker ps && id",
        "docker ps || id",
        "docker ps | cat",
        "docker ps `id`",
        "docker ps $(id)",
        "docker ps > /tmp/pwn",
        "docker ps < /etc/passwd",
        "docker ps\nid",
        "docker ps\rid",
        "docker ps 'traefik'",
        'docker ps "traefik"',
        "docker ps \\ id",
    ],
)
def test_force_command_rejects_empty_and_metacharacters(
    tmp_path: Path, bad_command: str | None
):
    """Verify empty commands and shell metacharacters are rejected without execution."""
    proc, invocations_log = _run_force_command(bad_command, tmp_path)
    assert proc.returncode != 0, f"Dangerous input was unexpectedly allowed: {bad_command!r}"
    assert not invocations_log.exists(), (
        f"Command stub should not have been executed for: {bad_command!r}"
    )


@pytest.mark.parametrize(
    "disallowed_command",
    [
        "sudo id",
        "su root",
        "sh",
        "bash",
        "cat /etc/shadow",
        "rm -rf /tmp/foo",
        "systemctl restart docker",
        "docker",
        "docker run alpine",
        "docker exec -it traefik sh",
        "docker rm traefik",
        "docker build .",
        "docker stop traefik",
        "docker start traefik",
        "docker restart traefik",
        "docker kill traefik",
        "docker compose up -d",
        "docker -H unix:///var/run/docker.sock ps",
        "journalctl --flush",
        "journalctl --rotate",
        "journalctl --vacuum-size=1M",
        "journalctl --vacuum-time=1d",
        "journalctl --vacuum-files=1",
        "journalctl --relinquish-var",
        "journalctl --sync",
        "journalctl --setup-keys",
        "journalctl --update-catalog",
        "appctl",
        "appctl up traefik",
        "appctl down traefik",
        "appctl restart traefik",
        "appctl update traefik",
        "appctl pull traefik",
        "appctl sync",
        "appctl config",
        "appctl deploy traefik",
        "appctl complete services",
    ],
)
def test_force_command_rejects_disallowed_commands_and_subcommands(
    tmp_path: Path, disallowed_command: str
):
    """Verify disallowed binaries, mutating subcommands, and mutating flags are rejected."""
    proc, invocations_log = _run_force_command(disallowed_command, tmp_path)
    assert proc.returncode != 0, (
        f"Disallowed command was unexpectedly allowed: {disallowed_command!r}"
    )
    assert not invocations_log.exists(), (
        f"Command stub should not have been executed for: {disallowed_command!r}"
    )


@pytest.mark.parametrize("subcmd", ["ps", "logs", "inspect"])
@pytest.mark.parametrize(
    "override_flag",
    [
        "-H unix:///var/run/docker.sock",
        "-H=unix:///var/run/docker.sock",
        "--host unix:///var/run/docker.sock",
        "--host=unix:///var/run/docker.sock",
        "--context default",
        "--context=default",
        "-c default",
        "-c=default",
        "--config /tmp",
        "--config=/tmp",
    ],
)
def test_force_command_rejects_post_subcommand_docker_override_flags(
    tmp_path: Path, subcmd: str, override_flag: str
):
    """Verify Docker connection/context/config override flags are rejected after valid subcommands."""
    command = f"docker {subcmd} {override_flag}"
    proc, invocations_log = _run_force_command(command, tmp_path)
    assert proc.returncode != 0, (
        f"Docker override flag was unexpectedly allowed: {command!r}"
    )
    assert not invocations_log.exists(), (
        f"Command stub should not have been executed for: {command!r}"
    )
