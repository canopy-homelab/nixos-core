"""
Security invariant tests for homelab GitOps execution and admission.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import gitops_dispatcher
import pytest

# Add Core to path so scripts can be imported
# Comment-out reason: testing pyproject-level pythonpath definition
# CORE_ROOT = Path(__file__).resolve().parent.parent.parent
# sys.path.insert(0, str(CORE_ROOT / "scripts"))


def test_custom_shell_action_is_rejected_without_execution(tmp_path: Path):
    """Ensure that arbitrary 'custom' actions fail closed and never invoke a shell."""
    deployment_config = {"branch": "main", "actions": [{"custom": "touch /tmp/pwned"}]}

    with patch("subprocess.run") as mock_run:
        success = gitops_dispatcher.execute_deployment(
            tmp_path, deployment_config, branch="main"
        )

        assert success is False, (
            "execute_deployment must fail closed on 'custom' action"
        )
        mock_run.assert_not_called()


def test_unknown_action_is_rejected(tmp_path: Path):
    """Ensure that unknown action strings fail closed and abort deployment."""
    deployment_config = {"branch": "main", "actions": ["malicious_or_unknown_action"]}

    with patch("subprocess.run") as mock_run:
        success = gitops_dispatcher.execute_deployment(
            tmp_path, deployment_config, branch="main"
        )

        assert success is False, "execute_deployment must reject unknown actions"
        mock_run.assert_not_called()


def test_allowed_actions_use_safe_argument_lists(tmp_path: Path):
    """Ensure that allowed actions execute safely via argument lists without shell=True."""
    deployment_config = {"branch": "main", "actions": ["git_pull"]}

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        success = gitops_dispatcher.execute_deployment(
            tmp_path, deployment_config, branch="main"
        )

        assert success is True
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert isinstance(args[0], list), "Command must be passed as an argument list"
        assert kwargs.get("shell") is not True, "shell=True must never be set"


def test_resolve_repository_rejects_path_traversal(tmp_path: Path, monkeypatch):
    """Ensure that path traversal payloads are strictly rejected before filesystem lookup."""
    sites_dir = tmp_path / "Sites"
    sites_dir.mkdir()
    monkeypatch.setattr(gitops_dispatcher, "SITES_DIR", sites_dir)

    traversal_payloads = [
        "../../foo",
        "../",
        "../../../etc/passwd",
        "/etc",
        "/home/foo",
        "foo/bar",
        "foo\\bar",
        "app/../../secret",
    ]

    for payload in traversal_payloads:
        assert gitops_dispatcher.resolve_repository(payload) is None, (
            f"Expected {payload} to be rejected"
        )


def test_resolve_repository_rejects_unknown_repositories(tmp_path: Path, monkeypatch):
    """Ensure that unknown repositories cannot be resolved."""
    sites_dir = tmp_path / "Sites"
    sites_dir.mkdir()
    monkeypatch.setattr(gitops_dispatcher, "SITES_DIR", sites_dir)

    assert gitops_dispatcher.resolve_repository("unregistered-repo") is None
    assert gitops_dispatcher.resolve_repository("evil-service") is None


def test_resolve_repository_rejects_symlink_escapes(tmp_path: Path, monkeypatch):
    """Ensure that symlinks inside Sites pointing outside are rejected as escapes."""
    sites_dir = tmp_path / "Sites"
    sites_dir.mkdir()
    secret_dir = tmp_path / "outside_root" / "sneaky-app"
    secret_dir.mkdir(parents=True)
    (secret_dir / "app.yaml").write_text("name: sneaky\n", encoding="utf-8")

    # Create a symlink inside Sites pointing outside Sites
    escape_link = sites_dir / "sneaky-link"
    escape_link.symlink_to(secret_dir)

    monkeypatch.setattr(gitops_dispatcher, "SITES_DIR", sites_dir)

    # Resolution should catch the escape and refuse to resolve
    assert gitops_dispatcher.resolve_repository("sneaky") is None
    assert gitops_dispatcher.resolve_repository("sneaky-link") is None


def test_resolve_repository_resolves_valid_manifest(tmp_path: Path, monkeypatch):
    """Ensure valid registered apps resolve by folder name, manifest name, and aliases."""
    sites_dir = tmp_path / "Sites"
    app_dir = sites_dir / "homelab-docs"
    app_dir.mkdir(parents=True)
    (app_dir / "app.yaml").write_text(
        "name: docs\naliases:\n  - doc2site\n  - notes\n", encoding="utf-8"
    )

    registry = tmp_path / "deployments.yaml"
    registry.write_text(
        f'schemaVersion: "1.0"\nrepositories:\n  homelab-docs:\n    path: "{app_dir}"\n    aliases:\n      - docs\n      - doc2site\n      - notes\n',
        encoding="utf-8",
    )

    monkeypatch.setattr(gitops_dispatcher, "SITES_DIR", sites_dir)
    monkeypatch.setattr(gitops_dispatcher, "DEPLOYMENTS_FILE", registry)

    canonical = app_dir.resolve()
    assert gitops_dispatcher.resolve_repository("homelab-docs") == canonical
    assert gitops_dispatcher.resolve_repository("docs") == canonical
    assert gitops_dispatcher.resolve_repository("doc2site") == canonical
    assert gitops_dispatcher.resolve_repository("notes") == canonical


def test_resolve_repository_rejects_vault(tmp_path: Path, monkeypatch):
    """Ensure data vault identities (Brain / second-brain) are not recognized by GitOps."""
    sites_dir = tmp_path / "Sites"
    sites_dir.mkdir()
    brain_dir = tmp_path / "Brain"
    brain_dir.mkdir()
    monkeypatch.setattr(gitops_dispatcher, "SITES_DIR", sites_dir)

    assert gitops_dispatcher.resolve_repository("second-brain") is None
    assert gitops_dispatcher.resolve_repository("Brain") is None
    assert gitops_dispatcher.resolve_repository("brain") is None


def test_get_trusted_repository_mapping_from_registry(tmp_path: Path, monkeypatch):
    """Ensure authoritative Core registry (deployments.yaml) is loaded with containment checks."""
    sites_dir = tmp_path / "Sites"
    sites_dir.mkdir()
    app_dir = sites_dir / "my-app"
    app_dir.mkdir()

    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()

    deployments_content = f"""
schemaVersion: "1.0"
repositories:
  my-app:
    path: "{app_dir}"
    aliases:
      - "app-alias"
  escaped-app:
    path: "{outside_dir}"
"""
    deployments_file = tmp_path / "deployments.yaml"
    deployments_file.write_text(deployments_content, encoding="utf-8")

    monkeypatch.setattr(gitops_dispatcher, "SITES_DIR", sites_dir)
    monkeypatch.setattr(gitops_dispatcher, "DEPLOYMENTS_FILE", deployments_file)

    mapping = gitops_dispatcher.get_trusted_repository_mapping()
    assert "my-app" in mapping
    assert mapping["my-app"] == app_dir.resolve()
    assert "app-alias" in mapping
    assert mapping["app-alias"] == app_dir.resolve()
    # Out-of-bounds path must be rejected
    assert "escaped-app" not in mapping


def test_unregistered_sites_directory_rejected_when_registry_active(
    tmp_path: Path, monkeypatch
):
    """Ensure unregistered directories in ~/Sites cannot be resolved when deployments.yaml is active."""
    sites_dir = tmp_path / "Sites"
    registered_dir = sites_dir / "homelab-docs"
    unregistered_dir = sites_dir / "rogue-workload"
    registered_dir.mkdir(parents=True)
    unregistered_dir.mkdir(parents=True)
    (registered_dir / "app.yaml").write_text("name: docs\n", encoding="utf-8")
    (unregistered_dir / "app.yaml").write_text("name: rogue\n", encoding="utf-8")

    registry = tmp_path / "deployments.yaml"
    registry.write_text(
        f'schemaVersion: "1.0"\nrepositories:\n  docs:\n    path: "{registered_dir}"\n',
        encoding="utf-8",
    )

    monkeypatch.setattr(gitops_dispatcher, "SITES_DIR", sites_dir)
    monkeypatch.setattr(gitops_dispatcher, "DEPLOYMENTS_FILE", registry)

    assert gitops_dispatcher.resolve_repository("docs") == registered_dir.resolve()
    # Unregistered workload must be rejected despite having app.yaml in Sites
    assert gitops_dispatcher.resolve_repository("rogue") is None
    assert gitops_dispatcher.resolve_repository("rogue-workload") is None


def test_missing_or_corrupt_registry_fails_closed(tmp_path: Path, monkeypatch):
    """Ensure missing or corrupted deployments.yaml fails closed without falling back to directory scanning."""
    sites_dir = tmp_path / "Sites"
    app_dir = sites_dir / "valid-app"
    app_dir.mkdir(parents=True)
    (app_dir / "app.yaml").write_text("name: valid\n", encoding="utf-8")

    missing_registry = tmp_path / "nonexistent-deployments.yaml"
    monkeypatch.setattr(gitops_dispatcher, "SITES_DIR", sites_dir)
    monkeypatch.setattr(gitops_dispatcher, "DEPLOYMENTS_FILE", missing_registry)
    monkeypatch.setattr(
        gitops_dispatcher, "CONFIG_DIR", tmp_path / "nonexistent-config"
    )

    # Missing registry must fail closed: empty mapping, no resolution
    assert gitops_dispatcher.get_trusted_repository_mapping() == {}


def test_registry_resolves_workloads_and_sites_tilde_prefixes(
    tmp_path: Path, monkeypatch
):
    """Ensure ~/Workloads/<app> and legacy ~/Sites/<app> paths resolve cleanly inside SITES_DIR."""
    workloads_dir = tmp_path / "Workloads"
    app_a = workloads_dir / "snappymail"
    app_b = workloads_dir / "legacy-app"
    app_a.mkdir(parents=True)
    app_b.mkdir(parents=True)

    registry = tmp_path / "deployments.yaml"
    registry.write_text(
        'schemaVersion: "1.0"\n'
        "repositories:\n"
        "  snappymail:\n"
        '    path: "~/Workloads/snappymail"\n'
        "  legacy:\n"
        '    path: "~/Sites/legacy-app"\n',
        encoding="utf-8",
    )

    monkeypatch.setattr(gitops_dispatcher, "SITES_DIR", workloads_dir)
    monkeypatch.setattr(gitops_dispatcher, "DEPLOYMENTS_FILE", registry)

    assert gitops_dispatcher.resolve_repository("snappymail") == app_a.resolve()
    assert gitops_dispatcher.resolve_repository("legacy") == app_b.resolve()
    assert gitops_dispatcher.resolve_repository("valid") is None

    # Corrupt YAML registry must also fail closed
    corrupt_registry = tmp_path / "corrupt-deployments.yaml"
    corrupt_registry.write_text(
        "schemaVersion: 1.0\nrepositories: [bad list syntax", encoding="utf-8"
    )
    monkeypatch.setattr(gitops_dispatcher, "DEPLOYMENTS_FILE", corrupt_registry)

    assert gitops_dispatcher.get_trusted_repository_mapping() == {}
    assert gitops_dispatcher.resolve_repository("valid") is None


def test_deployments_file_defaults_to_workloads(
    tmp_path: Path, run_isolated_script_expr
):
    """Ensure DEPLOYMENTS_FILE defaults to ~/Workloads/deployments.yaml."""
    resolved_default = run_isolated_script_expr(
        "import gitops_dispatcher; print(gitops_dispatcher.DEPLOYMENTS_FILE)"
    )
    assert Path(resolved_default) == tmp_path / "Workloads" / "deployments.yaml"


def test_deployments_file_fails_closed_without_config_dir_fallback(
    tmp_path: Path, monkeypatch
):
    """Ensure missing DEPLOYMENTS_FILE fails closed even when CONFIG_DIR/deployments.yaml exists."""
    config_dir = tmp_path / "config-fallback"
    config_dir.mkdir()
    (config_dir / "deployments.yaml").write_text(
        'schemaVersion: "1.0"\n'
        "repositories:\n"
        "  docs:\n"
        '    path: "~/Workloads/docs"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(
        gitops_dispatcher, "DEPLOYMENTS_FILE", tmp_path / "Workloads" / "deployments.yaml"
    )
    monkeypatch.setattr(gitops_dispatcher, "CONFIG_DIR", config_dir)
    assert gitops_dispatcher.get_trusted_repository_mapping() == {}


def test_deployments_file_honors_workloads_dir_override(
    tmp_path: Path, run_isolated_script_expr
):
    """Ensure DEPLOYMENTS_FILE honors WORKLOADS_DIR override when HOMELAB_DEPLOYMENTS_FILE is unset."""
    custom_workloads = tmp_path / "CustomWorkloads"
    resolved_override = run_isolated_script_expr(
        "import gitops_dispatcher; print(gitops_dispatcher.DEPLOYMENTS_FILE)",
        extra_env={"WORKLOADS_DIR": str(custom_workloads)},
    )
    assert Path(resolved_override) == custom_workloads / "deployments.yaml"


def test_webhook_verification_valid_signature():
    """Ensure valid HMAC-SHA256 signature passes verification."""
    import hashlib
    import hmac

    secret = b"supersecrettoken123"
    body = b'{"repository": {"name": "docs"}, "ref": "refs/heads/main"}'
    expected_hex = hmac.new(secret, body, hashlib.sha256).hexdigest()

    assert gitops_dispatcher.verify_signature(body, expected_hex, secret) is True
    # Support sha256= prefix as well
    assert (
        gitops_dispatcher.verify_signature(body, f"sha256={expected_hex}", secret)
        is True
    )


def test_webhook_verification_invalid_signature():
    """Ensure incorrect signature is rejected."""
    secret = b"supersecrettoken123"
    body = b'{"repository": {"name": "docs"}}'
    bad_sig = "a" * 64

    assert gitops_dispatcher.verify_signature(body, bad_sig, secret) is False


def test_webhook_verification_missing_signature():
    """Ensure missing signature header is rejected."""
    secret = b"supersecrettoken123"
    body = b'{"repository": {"name": "docs"}}'

    assert gitops_dispatcher.verify_signature(body, None, secret) is False
    assert gitops_dispatcher.verify_signature(body, "", secret) is False


def test_webhook_verification_modified_body():
    """Ensure signature mismatch from tampered body fails verification."""
    import hashlib
    import hmac

    secret = b"supersecrettoken123"
    body_original = b'{"repository": {"name": "docs"}}'
    sig = hmac.new(secret, body_original, hashlib.sha256).hexdigest()

    body_tampered = b'{"repository": {"name": "evil-app"}}'
    assert gitops_dispatcher.verify_signature(body_tampered, sig, secret) is False


def test_webhook_verification_modified_signature():
    """Ensure single-character flip in signature fails verification."""
    import hashlib
    import hmac

    secret = b"supersecrettoken123"
    body = b'{"repository": {"name": "docs"}}'
    sig = list(hmac.new(secret, body, hashlib.sha256).hexdigest())
    sig[0] = "0" if sig[0] != "0" else "1"
    flipped_sig = "".join(sig)

    assert gitops_dispatcher.verify_signature(body, flipped_sig, secret) is False


def test_webhook_verification_empty_secret_fails_closed():
    """Ensure empty or missing shared secret fails closed."""
    import hashlib
    import hmac

    secret = b""
    body = b'{"repository": {"name": "docs"}}'
    sig = hmac.new(b"somekey", body, hashlib.sha256).hexdigest()

    assert gitops_dispatcher.verify_signature(body, sig, secret) is False


def test_webhook_verification_malformed_signature():
    """Ensure non-hex or invalid length signatures fail closed."""
    secret = b"supersecrettoken123"
    body = b'{"repository": {"name": "docs"}}'

    assert (
        gitops_dispatcher.verify_signature(body, "not-a-valid-hex-digest", secret)
        is False
    )
    assert gitops_dispatcher.verify_signature(body, "deadbeef", secret) is False
    assert gitops_dispatcher.verify_signature(body, "z" * 64, secret) is False


def test_admission_rejects_non_push_events(tmp_path: Path):
    """Ensure non-push events such as pull_request or release are rejected."""
    payload_pr = {
        "ref": "refs/heads/main",
        "repository": {"name": "docs"},
        "pull_request": {"id": 1},
    }
    admitted, _, _, _, reason = gitops_dispatcher.admit_deployment(
        payload_pr, event_type="push"
    )
    assert admitted is False
    assert "non-push event" in reason

    payload_normal = {"ref": "refs/heads/main", "repository": {"name": "docs"}}
    admitted, _, _, _, reason = gitops_dispatcher.admit_deployment(
        payload_normal, event_type="pull_request"
    )
    assert admitted is False
    assert "Only 'push' is allowed" in reason


def test_admission_rejects_tags_and_invalid_refs():
    """Ensure tags or invalid ref structures are rejected from deployment."""
    tag_payload = {"ref": "refs/tags/v1.0.0", "repository": {"name": "docs"}}
    admitted, _, _, _, reason = gitops_dispatcher.admit_deployment(
        tag_payload, event_type="push"
    )
    assert admitted is False
    assert "Tag push" in reason

    non_head_payload = {"ref": "refs/pull/42/head", "repository": {"name": "docs"}}
    admitted, _, _, _, reason = gitops_dispatcher.admit_deployment(
        non_head_payload, event_type="push"
    )
    assert admitted is False
    assert "not a head branch" in reason


def test_admission_rejects_unknown_repository(tmp_path: Path, monkeypatch):
    """Ensure unknown repositories cannot be admitted."""
    sites_dir = tmp_path / "Sites"
    sites_dir.mkdir()
    monkeypatch.setattr(gitops_dispatcher, "SITES_DIR", sites_dir)

    payload = {"ref": "refs/heads/main", "repository": {"name": "unregistered-app"}}
    admitted, _, _, _, reason = gitops_dispatcher.admit_deployment(
        payload, event_type="push"
    )
    assert admitted is False
    assert "not recognized" in reason


def test_admission_rejects_branch_mismatch(tmp_path: Path, monkeypatch):
    """Ensure push to branch different from declared deployment branch is rejected."""
    sites_dir = tmp_path / "Sites"
    app_dir = sites_dir / "homelab-docs"
    app_dir.mkdir(parents=True)
    (app_dir / "app.yaml").write_text(
        "name: docs\ndeployment:\n  branch: production\n", encoding="utf-8"
    )
    registry = tmp_path / "deployments.yaml"
    registry.write_text(
        f'schemaVersion: "1.0"\nrepositories:\n  docs:\n    path: "{app_dir}"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(gitops_dispatcher, "SITES_DIR", sites_dir)
    monkeypatch.setattr(gitops_dispatcher, "DEPLOYMENTS_FILE", registry)

    payload = {"ref": "refs/heads/staging", "repository": {"name": "docs"}}
    admitted, _, _, _, reason = gitops_dispatcher.admit_deployment(
        payload, event_type="push"
    )
    assert admitted is False
    assert "Branch mismatch" in reason


def test_admission_rejects_unsupported_strategy(tmp_path: Path, monkeypatch):
    """Ensure unsupported deployment strategy in app.yaml is rejected."""
    sites_dir = tmp_path / "Sites"
    app_dir = sites_dir / "homelab-docs"
    app_dir.mkdir(parents=True)
    (app_dir / "app.yaml").write_text(
        "name: docs\ndeployment:\n  branch: main\n  strategy: kubernetes\n",
        encoding="utf-8",
    )
    registry = tmp_path / "deployments.yaml"
    registry.write_text(
        f'schemaVersion: "1.0"\nrepositories:\n  docs:\n    path: "{app_dir}"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(gitops_dispatcher, "SITES_DIR", sites_dir)
    monkeypatch.setattr(gitops_dispatcher, "DEPLOYMENTS_FILE", registry)

    payload = {"ref": "refs/heads/main", "repository": {"name": "docs"}}
    admitted, _, _, _, reason = gitops_dispatcher.admit_deployment(
        payload, event_type="push"
    )
    assert admitted is False
    assert "Unsupported deployment strategy" in reason


def test_admission_rejects_unsupported_actions(tmp_path: Path, monkeypatch):
    """Ensure unsupported deployment action in app.yaml is rejected."""
    sites_dir = tmp_path / "Sites"
    app_dir = sites_dir / "homelab-docs"
    app_dir.mkdir(parents=True)
    (app_dir / "app.yaml").write_text(
        "name: docs\ndeployment:\n  branch: main\n  actions:\n    - git_pull\n    - evil_action\n",
        encoding="utf-8",
    )
    registry = tmp_path / "deployments.yaml"
    registry.write_text(
        f'schemaVersion: "1.0"\nrepositories:\n  docs:\n    path: "{app_dir}"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(gitops_dispatcher, "SITES_DIR", sites_dir)
    monkeypatch.setattr(gitops_dispatcher, "DEPLOYMENTS_FILE", registry)

    payload = {"ref": "refs/heads/main", "repository": {"name": "docs"}}
    admitted, _, _, _, reason = gitops_dispatcher.admit_deployment(
        payload, event_type="push"
    )
    assert admitted is False
    assert "Unsupported deployment action" in reason


def test_admission_admits_valid_push(tmp_path: Path, monkeypatch):
    """Ensure valid push to declared branch on registered repo passes admission."""
    sites_dir = tmp_path / "Sites"
    app_dir = sites_dir / "homelab-docs"
    app_dir.mkdir(parents=True)
    (app_dir / "app.yaml").write_text(
        "name: docs\ndeployment:\n  branch: main\n  actions:\n    - git_pull\n    - compose_up\n",
        encoding="utf-8",
    )
    registry = tmp_path / "deployments.yaml"
    registry.write_text(
        f'schemaVersion: "1.0"\nrepositories:\n  docs:\n    path: "{app_dir}"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(gitops_dispatcher, "SITES_DIR", sites_dir)
    monkeypatch.setattr(gitops_dispatcher, "DEPLOYMENTS_FILE", registry)

    payload = {"ref": "refs/heads/main", "repository": {"name": "docs"}}
    admitted, target_dir, config, branch, reason = gitops_dispatcher.admit_deployment(
        payload, event_type="push"
    )
    assert admitted is True

    assert "Admitted" in reason
    assert target_dir == app_dir.resolve()
    assert branch == "main"
    assert config["actions"] == ["git_pull", "compose_up"]


def test_enqueue_supersedes_pending_revision(tmp_path: Path, monkeypatch):
    """Ensure newer pending deployment overwrites older pending deployment."""
    state_dir = tmp_path / "state"
    monkeypatch.setattr(gitops_dispatcher, "STATE_DIR", state_dir)

    target_dir = tmp_path / "app"
    target_dir.mkdir()

    # Enqueue revision A
    gitops_dispatcher.enqueue_deployment(
        target_dir, {"branch": "main", "rev": "A"}, "main"
    )
    pending_file = gitops_dispatcher.get_pending_file("app")
    assert json.loads(pending_file.read_text())["deployment_config"]["rev"] == "A"

    # Enqueue revision B (supersedes A)
    gitops_dispatcher.enqueue_deployment(
        target_dir, {"branch": "main", "rev": "B"}, "main"
    )
    assert json.loads(pending_file.read_text())["deployment_config"]["rev"] == "B"

    # Enqueue revision C (supersedes B)
    gitops_dispatcher.enqueue_deployment(
        target_dir, {"branch": "main", "rev": "C"}, "main"
    )
    assert json.loads(pending_file.read_text())["deployment_config"]["rev"] == "C"


def test_serialized_worker_race_superseding(tmp_path: Path, monkeypatch):
    """
    Simulate race condition:
    A starts
    B arrives (enqueued)
    C arrives (supersedes B)
    A finishes
    Verify: B is skipped, C is deployed.
    """
    import threading

    state_dir = tmp_path / "state"
    monkeypatch.setattr(gitops_dispatcher, "STATE_DIR", state_dir)

    target_dir = tmp_path / "app"
    target_dir.mkdir()

    executed_revisions = []
    a_started_event = threading.Event()
    b_and_c_enqueued_event = threading.Event()

    def mock_execute(target, config, branch):
        rev = config.get("rev", "unknown")
        executed_revisions.append(rev)
        if rev == "A":
            a_started_event.set()
            # Wait until B and C are enqueued
            b_and_c_enqueued_event.wait(timeout=2.0)
        return True

    monkeypatch.setattr(gitops_dispatcher, "execute_deployment", mock_execute)

    # 1. Enqueue A
    gitops_dispatcher.enqueue_deployment(
        target_dir, {"branch": "main", "rev": "A"}, "main"
    )

    # Start worker in thread (takes A)
    worker_thread = threading.Thread(
        target=gitops_dispatcher.run_target_worker, args=("app",)
    )
    worker_thread.start()

    # Wait for A to start executing
    assert a_started_event.wait(timeout=2.0) is True

    # 2. B arrives while A is running
    gitops_dispatcher.enqueue_deployment(
        target_dir, {"branch": "main", "rev": "B"}, "main"
    )

    # 3. C arrives while A is running (supersedes B)
    gitops_dispatcher.enqueue_deployment(
        target_dir, {"branch": "main", "rev": "C"}, "main"
    )

    # Let A complete
    b_and_c_enqueued_event.set()

    worker_thread.join(timeout=3.0)

    # Verification: A was executed, B was superseded/skipped, C was executed!
    assert executed_revisions == ["A", "C"], (
        f"Expected ['A', 'C'] but got {executed_revisions}"
    )


def test_post_pull_manifest_validation_rejects_unsupported_action(tmp_path: Path):
    """
    Ensure that if a pulled revision introduces an unsupported action in app.yaml,
    the post-pull validation detects it and fails closed before any compose actions run.
    """
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    manifest_file = app_dir / "app.yaml"
    manifest_file.write_text(
        "name: app\ndeployment:\n  branch: main\n  actions:\n    - git_pull\n    - compose_up\n"
    )
    (app_dir / "docker-compose.yml").write_text(
        "version: '3'\nservices:\n  web:\n    image: nginx\n"
    )

    initial_config = {"branch": "main", "actions": ["git_pull", "compose_up"]}

    def mock_pull(cmd, check=True):
        if "pull" in cmd:
            # Simulate git pull bringing in an invalid action in app.yaml
            manifest_file.write_text(
                "name: app\ndeployment:\n  branch: main\n  actions:\n    - git_pull\n    - evil_action\n"
            )
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=mock_pull) as mock_run:
        success = gitops_dispatcher.execute_deployment(
            app_dir, initial_config, branch="main"
        )

        assert success is False, (
            "Deployment must fail closed when pulled revision has invalid actions"
        )
        # Only git pull was called; compose_up was never reached!
        calls = [c[0][0] for c in mock_run.call_args_list]
        assert len(calls) == 1
        assert "pull" in calls[0]


def test_post_pull_manifest_validation_rejects_branch_policy_mismatch(tmp_path: Path):
    """
    Ensure that if a pulled revision modifies app.yaml to target a different branch,
    post-pull branch validation catches the mismatch and aborts deployment.
    """
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    manifest_file = app_dir / "app.yaml"
    manifest_file.write_text(
        "name: app\ndeployment:\n  branch: main\n  actions:\n    - git_pull\n    - compose_up\n"
    )
    (app_dir / "docker-compose.yml").write_text(
        "version: '3'\nservices:\n  web:\n    image: nginx\n"
    )

    initial_config = {"branch": "main", "actions": ["git_pull", "compose_up"]}

    def mock_pull(cmd, check=True):
        if "pull" in cmd:
            # Simulate git pull bringing in an app.yaml that targets 'staging', not 'main'
            manifest_file.write_text(
                "name: app\ndeployment:\n  branch: staging\n  actions:\n    - git_pull\n    - compose_up\n"
            )
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=mock_pull) as mock_run:
        success = gitops_dispatcher.execute_deployment(
            app_dir, initial_config, branch="main"
        )

        assert success is False, (
            "Deployment must fail closed on post-pull branch mismatch"
        )
        calls = [c[0][0] for c in mock_run.call_args_list]
        assert len(calls) == 1
        assert "pull" in calls[0]


def test_post_pull_manifest_adopts_updated_actions(tmp_path: Path):
    """
    Ensure that when a pulled revision declares different valid actions (e.g. compose_build),
    post-pull manifest validation adopts and executes the new revision's actions.
    """
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    manifest_file = app_dir / "app.yaml"
    manifest_file.write_text(
        "name: app\ndeployment:\n  branch: main\n  actions:\n    - git_pull\n    - compose_up\n"
    )
    (app_dir / "docker-compose.yml").write_text(
        "version: '3'\nservices:\n  web:\n    image: nginx\n"
    )

    initial_config = {"branch": "main", "actions": ["git_pull", "compose_up"]}

    def mock_pull(cmd, check=True):
        if "pull" in cmd:
            # Revision updates action to compose_build
            manifest_file.write_text(
                "name: app\ndeployment:\n  branch: main\n  actions:\n    - git_pull\n    - compose_build\n"
            )
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=mock_pull) as mock_run:
        success = gitops_dispatcher.execute_deployment(
            app_dir, initial_config, branch="main"
        )

        assert success is True
        calls = [c[0][0] for c in mock_run.call_args_list]
        # Should call pull, then build, then up
        assert any("pull" in c for c in calls)
        assert any("build" in c for c in calls)


def test_worker_records_status_file(tmp_path: Path, monkeypatch):
    """Ensure worker writes intentional execution status file on completion."""
    state_dir = tmp_path / "state"
    monkeypatch.setattr(gitops_dispatcher, "STATE_DIR", state_dir)

    target_dir = tmp_path / "app"
    target_dir.mkdir()

    monkeypatch.setattr(gitops_dispatcher, "execute_deployment", lambda t, c, b: True)

    gitops_dispatcher.enqueue_deployment(
        target_dir, {"branch": "main"}, "main", commit_sha="abcdef123456"
    )

    success = gitops_dispatcher.run_target_worker("app")
    assert success is True

    status_file = state_dir / "app.status.json"
    assert status_file.is_file()
    status = json.loads(status_file.read_text())
    assert status["target"] == "app"
    assert status["branch"] == "main"
    assert status["commit_sha"] == "abcdef123456"
    assert status["success"] is True
    assert "timestamp" in status


def test_validate_compose_security_rejects_privileged(tmp_path: Path):
    """Ensure docker-compose with privileged: true fails pre-flight validation."""
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(
        """
services:
  app:
    image: alpine:latest
    privileged: true
""",
        encoding="utf-8",
    )
    valid, err = gitops_dispatcher.validate_compose_security(compose_file, tmp_path)
    assert valid is False
    assert err is not None and "privileged: true" in err


def test_validate_compose_security_rejects_docker_socket_mount(tmp_path: Path):
    """Ensure docker-compose with /var/run/docker.sock mount fails validation."""
    # Test string syntax
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(
        """
services:
  app:
    image: alpine:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
""",
        encoding="utf-8",
    )
    valid, err = gitops_dispatcher.validate_compose_security(compose_file, tmp_path)
    assert valid is False
    assert err is not None and "Docker socket" in err

    # Test dict / long syntax
    compose_file.write_text(
        """
services:
  app:
    image: alpine:latest
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
""",
        encoding="utf-8",
    )
    valid, err = gitops_dispatcher.validate_compose_security(compose_file, tmp_path)
    assert valid is False
    assert err is not None and "Docker socket" in err


def test_validate_compose_security_rejects_host_network(tmp_path: Path):
    """Ensure docker-compose with network_mode: host fails pre-flight validation."""
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(
        """
services:
  app:
    image: alpine:latest
    network_mode: host
""",
        encoding="utf-8",
    )
    valid, err = gitops_dispatcher.validate_compose_security(compose_file, tmp_path)
    assert valid is False
    assert err is not None and "network_mode: host" in err


def test_validate_compose_security_rejects_out_of_bounds_host_bind(tmp_path: Path):
    """Ensure host bind mounts outside workload directory or state root are rejected."""
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(
        """
services:
  app:
    image: alpine:latest
    volumes:
      - /etc/shadow:/etc/shadow:ro
""",
        encoding="utf-8",
    )
    valid, err = gitops_dispatcher.validate_compose_security(compose_file, tmp_path)
    assert valid is False
    assert err is not None and "prohibited host bind mount" in err


def test_validate_compose_security_allows_safe_compose(tmp_path: Path):
    """Ensure safe compose definitions with relative binds and named volumes pass validation."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(
        f"""
services:
  app:
    image: alpine:latest
    volumes:
      - {data_dir}:/data
      - named_vol:/var/log
volumes:
  named_vol:
""",
        encoding="utf-8",
    )
    valid, err = gitops_dispatcher.validate_compose_security(compose_file, tmp_path)
    assert valid is True
    assert err is None


def test_validate_compose_security_nonexistent_file(tmp_path: Path):
    """Ensure validation passes when compose file is absent."""
    compose_file = tmp_path / "nonexistent.yml"
    valid, err = gitops_dispatcher.validate_compose_security(compose_file, tmp_path)
    assert valid is True
    assert err is None


@pytest.mark.parametrize(
    "malicious_volume",
    [
        "../../etc/passwd:/mnt/passwd:ro",
        "./../../Core/nixos/secrets.yaml:/secrets.yaml",
        "../other-workload/data:/data",
    ],
)
def test_validate_compose_security_blocks_relative_traversal(
    tmp_path: Path, malicious_volume: str
):
    """Ensure relative path traversals in volume mounts cannot escape workload root."""
    app_dir = tmp_path / "my-app"
    app_dir.mkdir(parents=True)

    compose_file = app_dir / "docker-compose.yml"
    compose_file.write_text(
        f"services:\n  web:\n    image: nginx\n    volumes:\n      - '{malicious_volume}'\n",
        encoding="utf-8",
    )

    valid, err = gitops_dispatcher.validate_compose_security(
        compose_file, app_dir, app_name="my-app"
    )
    assert valid is False, (
        f"Expected relative traversal '{malicious_volume}' to be rejected!"
    )
    assert err is not None and "prohibited host bind mount" in err


def test_validate_compose_security_blocks_cross_tenant_state_mounts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Ensure workload 'my-app' cannot mount another workload's state directory ('other-app')."""
    sites_dir = tmp_path / "Sites"
    app_dir = sites_dir / "my-app"
    app_dir.mkdir(parents=True)

    state_root = tmp_path / "var/lib/homelab"
    (state_root / "my-app").mkdir(parents=True)
    (state_root / "other-app").mkdir(parents=True)
    monkeypatch.setenv("HOMELAB_STATE_ROOT", str(state_root))

    # Cross-tenant state mount
    compose_file = app_dir / "docker-compose.yml"
    compose_file.write_text(
        f"services:\n  web:\n    image: nginx\n    volumes:\n      - '{state_root}/other-app:/data'\n",
        encoding="utf-8",
    )

    valid, err = gitops_dispatcher.validate_compose_security(
        compose_file, app_dir, app_name="my-app"
    )
    assert valid is False, "Expected cross-tenant state mount to be rejected!"
    assert err is not None and (
        "prohibited host bind mount" in err or "cross-tenant" in err.lower()
    )

    # Authorized own state mount must pass
    compose_file.write_text(
        f"services:\n  web:\n    image: nginx\n    volumes:\n      - '{state_root}/my-app:/data'\n",
        encoding="utf-8",
    )
    valid_own, err_own = gitops_dispatcher.validate_compose_security(
        compose_file, app_dir, app_name="my-app"
    )
    assert valid_own is True, (
        f"Own state mount should be permitted, got error: {err_own}"
    )


@pytest.mark.parametrize(
    "unsafe_directive",
    [
        "cap_add:\n      - SYS_ADMIN",
        "pid: host",
        "ipc: host",
        "userns_mode: host",
        "devices:\n      - /dev/sda:/dev/sda",
        "security_opt:\n      - apparmor:unconfined",
    ],
)
def test_validate_compose_security_blocks_privilege_escalation_primitives(
    tmp_path: Path, unsafe_directive: str
):
    """Ensure dangerous container breakout capabilities and host namespaces are blocked."""
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(
        f"services:\n  app:\n    image: alpine\n    {unsafe_directive}\n",
        encoding="utf-8",
    )
    valid, err = gitops_dispatcher.validate_compose_security(
        compose_file, tmp_path, app_name="app"
    )
    assert valid is False, f"Directive should be blocked:\n{unsafe_directive}"
    assert err is not None


def test_validate_compose_security_rejects_top_level_include(tmp_path: Path):
    """Ensure top-level Compose include directives are rejected to prevent out-of-tree includes."""
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(
        """
include:
  - /etc/shadow
services:
  app:
    image: alpine
""",
        encoding="utf-8",
    )
    valid, err = gitops_dispatcher.validate_compose_security(
        compose_file, tmp_path, app_name="app"
    )
    assert valid is False
    assert err is not None and "include" in err.lower()


def test_validate_compose_security_rejects_symlink_escape(tmp_path: Path):
    """Ensure docker-compose.yml cannot be a symlink escaping the workload directory."""
    app_dir = tmp_path / "my-app"
    app_dir.mkdir(parents=True)
    outside_file = tmp_path / "outside-compose.yml"
    outside_file.write_text("services:\n  app:\n    image: alpine\n", encoding="utf-8")

    compose_link = app_dir / "docker-compose.yml"
    compose_link.symlink_to(outside_file)

    valid, err = gitops_dispatcher.validate_compose_security(
        compose_link, app_dir, app_name="my-app"
    )
    assert valid is False
    assert err is not None and "symlink" in err.lower()


def test_validate_compose_security_rejects_escaping_env_file(tmp_path: Path):
    """Ensure services cannot use env_file to read secrets outside the workload root."""
    app_dir = tmp_path / "my-app"
    app_dir.mkdir(parents=True)
    (app_dir / "valid.env").write_text("A=1\n", encoding="utf-8")

    # 1. Escaping absolute path
    compose_file = app_dir / "docker-compose.yml"
    compose_file.write_text(
        """
services:
  app:
    image: alpine
    env_file: /run/secrets/homeserver.env
""",
        encoding="utf-8",
    )
    valid, err = gitops_dispatcher.validate_compose_security(
        compose_file, app_dir, app_name="my-app"
    )
    assert valid is False
    assert err is not None and "env_file" in err.lower()

    # 2. Escaping relative path in list
    compose_file.write_text(
        """
services:
  app:
    image: alpine
    env_file:
      - valid.env
      - ../../Core/.env
""",
        encoding="utf-8",
    )
    valid, err = gitops_dispatcher.validate_compose_security(
        compose_file, app_dir, app_name="my-app"
    )
    assert valid is False
    assert err is not None and "env_file" in err.lower()

    # 3. Valid local env_file
    compose_file.write_text(
        """
services:
  app:
    image: alpine
    env_file: valid.env
""",
        encoding="utf-8",
    )
    valid, err = gitops_dispatcher.validate_compose_security(
        compose_file, app_dir, app_name="my-app"
    )
    assert valid is True
    assert err is None


def test_validate_compose_security_rejects_undeclared_named_volumes(tmp_path: Path):
    """Ensure ambiguous volume paths not declared in top-level volumes are rejected."""
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(
        """
services:
  app:
    image: alpine
    volumes:
      - rogue_named_volume:/data
""",
        encoding="utf-8",
    )
    valid, err = gitops_dispatcher.validate_compose_security(
        compose_file, tmp_path, app_name="my-app"
    )
    assert valid is False
    assert err is not None and "undeclared" in err.lower()


def test_validate_compose_security_handles_string_security_opt(tmp_path: Path):
    """Ensure security_opt specified as string instead of list is strictly checked."""
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(
        """
services:
  app:
    image: alpine
    security_opt: "apparmor:unconfined"
""",
        encoding="utf-8",
    )
    valid, err = gitops_dispatcher.validate_compose_security(
        compose_file, tmp_path, app_name="my-app"
    )
    assert valid is False
    assert err is not None and "security_opt" in err.lower()


def test_validate_compose_security_rejects_dict_volume_without_type_bind(
    tmp_path: Path,
):
    """Ensure dictionary volume declarations without explicit type: bind enforce host containment (CR-DI-01)."""
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(
        """
services:
  app:
    image: alpine
    volumes:
      - source: /etc/shadow
        target: /app/shadow
""",
        encoding="utf-8",
    )
    valid, err = gitops_dispatcher.validate_compose_security(
        compose_file, tmp_path, app_name="my-app"
    )
    assert valid is False
    assert err is not None and "prohibited host bind mount" in err.lower()


def test_validate_compose_security_rejects_variable_interpolation_in_volume_host_path(
    tmp_path: Path,
):
    """Ensure volume host paths containing variable interpolation (${...}) fail closed (CR-DI-02)."""
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(
        """
services:
  app:
    image: alpine
    volumes:
      - "${HOST_DIR}/data:/data"
""",
        encoding="utf-8",
    )
    valid, err = gitops_dispatcher.validate_compose_security(
        compose_file, tmp_path, app_name="my-app"
    )
    assert valid is False
    assert err is not None and "variable interpolation" in err.lower()


def test_validate_compose_security_rejects_variable_interpolation_in_dict_volume_source(
    tmp_path: Path,
):
    """Ensure dictionary volume source containing variable interpolation (${...}) fails closed (CR-DI-02)."""
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(
        """
services:
  app:
    image: alpine
    volumes:
      - source: "${HOST_DIR}/data"
        target: /data
""",
        encoding="utf-8",
    )
    valid, err = gitops_dispatcher.validate_compose_security(
        compose_file, tmp_path, app_name="my-app"
    )
    assert valid is False
    assert err is not None and "variable interpolation" in err.lower()


def test_validate_compose_security_allows_valid_dict_volume_within_workload(
    tmp_path: Path,
):
    """Ensure valid dictionary volume within workload root is accepted even without type: bind."""
    (tmp_path / "data").mkdir()
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(
        """
services:
  app:
    image: alpine
    volumes:
      - source: ./data
        target: /data
""",
        encoding="utf-8",
    )
    valid, err = gitops_dispatcher.validate_compose_security(
        compose_file, tmp_path, app_name="my-app"
    )
    assert valid is True
    assert err is None


def test_validate_compose_security_allows_remote_git_build_urls(tmp_path: Path):
    """Ensure validate_compose_security permits remote Git/HTTP build URLs (#33)."""
    compose_file = tmp_path / "docker-compose.yml"
    compose_file.write_text(
        """
services:
  https_app:
    build: https://git.example.com/operator/app.git#main
  ssh_dict_app:
    build:
      context: ssh://git@git.example.com:2223/operator/app.git
      dockerfile: Dockerfile
  scp_git_app:
    build: git@git.example.com:operator/app.git
  local_app:
    build:
      context: ./docker
""",
        encoding="utf-8",
    )
    (tmp_path / "docker").mkdir()
    valid, err = gitops_dispatcher.validate_compose_security(
        compose_file, tmp_path, app_name="my-app"
    )
    assert valid is True
    assert err is None


@pytest.mark.parametrize(
    "build_yaml,expected_substr",
    [
        ("build: /etc", "escaping workload root"),
        ("build:\n      context: ../../outside", "escaping workload root"),
        ('build: "${BUILD_CTX}/app"', "variable interpolation"),
        ('build:\n      context: "${BUILD_CTX}/app"', "variable interpolation"),
    ],
)
def test_validate_compose_security_rejects_unsafe_build_contexts(
    tmp_path: Path, build_yaml: str, expected_substr: str
):
    """Ensure validate_compose_security blocks local build host-path escapes and ${...} interpolation (#33)."""
    app_dir = tmp_path / "Workloads" / "my-app"
    app_dir.mkdir(parents=True)
    compose_file = app_dir / "docker-compose.yml"
    compose_file.write_text(
        f"services:\n  app:\n    {build_yaml}\n",
        encoding="utf-8",
    )
    valid, err = gitops_dispatcher.validate_compose_security(
        compose_file, app_dir, app_name="my-app"
    )
    assert valid is False
    assert err is not None and expected_substr in err.lower()


def test_monorepo_webhook_dispatch_pulls_once_and_deploys_only_admitted_changed_subdirs(
    tmp_path: Path, monkeypatch
):
    """Ensure canopy-workloads push pulls ~/Workloads once and dispatches only admitted changed subdirs (#33)."""
    workloads_dir = tmp_path / "Workloads"
    (workloads_dir / ".git").mkdir(parents=True)
    snappymail_dir = workloads_dir / "snappymail"
    gitea_dir = workloads_dir / "homelab-gitea"
    rogue_dir = workloads_dir / "rogue-app"
    for d in (snappymail_dir, gitea_dir, rogue_dir):
        d.mkdir(parents=True)
        (d / "app.yaml").write_text(f"name: {d.name}\n", encoding="utf-8")

    registry = tmp_path / "deployments.yaml"
    registry.write_text(
        'schemaVersion: "1.0"\n'
        "repositories:\n"
        "  snappymail:\n"
        '    path: "~/Workloads/snappymail"\n'
        "  gitea:\n"
        '    path: "~/Workloads/homelab-gitea"\n',
        encoding="utf-8",
    )

    monkeypatch.setattr(gitops_dispatcher, "SITES_DIR", workloads_dir)
    monkeypatch.setattr(gitops_dispatcher, "DEPLOYMENTS_FILE", registry)
    monkeypatch.setattr(gitops_dispatcher, "STATE_DIR", tmp_path / "state")

    payload = {
        "ref": "refs/heads/main",
        "after": "deadbeef1234",
        "repository": {"name": "canopy-workloads"},
        "commits": [
            {
                "added": ["rogue-app/app.yaml", "README.md"],
                "modified": ["snappymail/docker-compose.yml"],
                "removed": ["../Core/scripts/appctl"],
            }
        ],
    }

    git_calls: list[list[str]] = []
    enqueued: list[Path] = []
    spawned: list[str] = []

    def mock_run(cmd, *args, **kwargs):
        git_calls.append(cmd)
        return MagicMock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(gitops_dispatcher.subprocess, "run", mock_run)
    monkeypatch.setattr(
        gitops_dispatcher,
        "enqueue_deployment",
        lambda target_dir, cfg, branch, commit_sha="": enqueued.append(target_dir),
    )
    monkeypatch.setattr(
        gitops_dispatcher,
        "spawn_worker_async",
        lambda target_name: spawned.append(target_name),
    )

    assert gitops_dispatcher.is_monorepo_push(payload) is True
    ok, dispatched, _ = gitops_dispatcher.dispatch_monorepo_push(payload, "push")
    assert ok is True
    assert dispatched == [snappymail_dir.resolve()]
    assert enqueued == [snappymail_dir.resolve()]
    assert spawned == ["snappymail"]
    # Pulled ~/Workloads exactly once
    pull_calls = [c for c in git_calls if "pull" in c]
    assert len(pull_calls) == 1
    assert str(workloads_dir) in pull_calls[0]


# ---------------------------------------------------------------------------
# ADR-0005 Host-Granted Workload Capabilities ("Compose Requests, Nix Grants")
# ---------------------------------------------------------------------------


def _write_grants(path: Path, workloads: dict) -> Path:
    import json

    path.write_text(
        json.dumps({"schemaVersion": "1.0", "workloads": workloads}),
        encoding="utf-8",
    )
    return path


def _fake_group_lookup(key: str | int) -> tuple[str, int]:
    table = {
        "render": ("render", 303),
        303: ("render", 303),
        "video": ("video", 44),
        44: ("video", 44),
        "docker": ("docker", 998),
        998: ("docker", 998),
        "wheel": ("wheel", 10),
        10: ("wheel", 10),
        "root": ("root", 0),
        0: ("root", 0),
    }
    lookup_key = int(key) if isinstance(key, str) and key.isdigit() else key
    if lookup_key in table:
        return table[lookup_key]
    raise KeyError(key)


def test_validate_compose_security_permits_granted_stack(tmp_path: Path):
    """Positive ADR-0005 grants: render<->303, existing device, short & long :ro readOnlyPaths."""
    app_dir = tmp_path / "Workloads" / "media"
    app_dir.mkdir(parents=True)

    dev_dir = tmp_path / "dev" / "dri"
    dev_dir.mkdir(parents=True)
    render_node = dev_dir / "renderD128"
    render_node.write_text("", encoding="utf-8")

    media_dir = tmp_path / "mnt" / "media"
    media_sub = media_dir / "movies"
    media_sub.mkdir(parents=True)

    grants_file = _write_grants(
        tmp_path / "grants.json",
        {
            "media": {
                "devices": [str(render_node)],
                "groups": ["render"],
                "readOnlyPaths": [str(media_dir)],
            }
        },
    )

    compose_file = app_dir / "docker-compose.yml"
    compose_file.write_text(
        f"""
services:
  jellyfin:
    image: jellyfin/jellyfin:latest
    user: "1000:303"
    group_add:
      - "303"
    devices:
      - "{render_node}:/dev/dri/renderD128:rw"
    volumes:
      - "{media_sub}:/media/movies:ro"
      - type: bind
        source: "{media_dir}"
        target: /media/all
        read_only: true
""",
        encoding="utf-8",
    )

    ok, err = gitops_dispatcher.validate_compose_security(
        compose_file,
        app_dir,
        app_name="media",
        grants_file=grants_file,
        group_lookup=_fake_group_lookup,
    )
    assert ok is True, f"Expected granted capabilities to pass, got: {err}"
    assert err is None


def test_capability_grants_evaluates_resolved_env_interpolation(tmp_path: Path):
    """Post-interpolation values from resolved_env are evaluated and permitted when granted."""
    app_dir = tmp_path / "Workloads" / "media"
    app_dir.mkdir(parents=True)
    media_dir = tmp_path / "mnt" / "media"
    media_dir.mkdir(parents=True)

    grants_file = _write_grants(
        tmp_path / "grants.json",
        {"media": {"groups": ["303"], "readOnlyPaths": [str(media_dir)]}},
    )

    compose_file = app_dir / "docker-compose.yml"
    compose_file.write_text(
        """
services:
  app:
    image: alpine
    user: "${PUID:-1000}:${PGID:-1000}"
    group_add:
      - "${RENDER_GID}"
    volumes:
      - "${MEDIA_PATH}:/media:ro"
""",
        encoding="utf-8",
    )

    ok, err = gitops_dispatcher.validate_compose_security(
        compose_file,
        app_dir,
        app_name="media",
        resolved_env={
            "PUID": "1000",
            "PGID": "1000",
            "RENDER_GID": "render",
            "MEDIA_PATH": str(media_dir),
        },
        grants_file=grants_file,
        group_lookup=_fake_group_lookup,
    )
    assert ok is True, f"Expected resolved env capabilities to pass, got: {err}"


@pytest.mark.parametrize(
    "compose_body,expected_substr",
    [
        ("    user: '0:131'", "user"),
        ("    user: '00:1000'", "root"),
        ("    user: '1000:0'", "user"),
        ("    user: '1000:docker'", "docker"),
        ("    user: '1000:44'", "44"),
        ("    user: '1000:999'", "999"),
        ("    group_add:\n      - '303'", "group_add"),
        ("    network_mode: 'container:traefik'", "container:traefik"),
        ("    network_mode: 'service:web'", "service:web"),
        ("    device_cgroup_rules:\n      - 'c 226:* rmw'", "device_cgroup_rules"),
        ("    user: '${PUID}:1000'", "interpolation"),
    ],
)
def test_validate_compose_security_rejects_ungranted_capabilities(
    tmp_path: Path, compose_body: str, expected_substr: str
):
    """Ensure bypass vectors and ungranted capabilities fail closed."""
    app_dir = tmp_path / "Workloads" / "ungranted"
    app_dir.mkdir(parents=True)
    grants_file = _write_grants(tmp_path / "grants.json", {})

    compose_file = app_dir / "docker-compose.yml"
    compose_file.write_text(
        f"services:\n  app:\n    image: alpine\n{compose_body}\n",
        encoding="utf-8",
    )

    ok, err = gitops_dispatcher.validate_compose_security(
        compose_file,
        app_dir,
        app_name="ungranted",
        grants_file=grants_file,
        group_lookup=_fake_group_lookup,
    )
    assert ok is False
    assert err is not None
    assert expected_substr.lower() in err.lower()


def test_validate_compose_security_fails_closed_when_pyyaml_missing(
    tmp_path: Path, monkeypatch
):
    """Ensure validate_compose_security fails closed when PyYAML is unavailable."""
    app_dir = tmp_path / "Workloads" / "app"
    app_dir.mkdir(parents=True)
    compose_file = app_dir / "docker-compose.yml"
    compose_file.write_text("services:\n  app:\n    image: alpine\n", encoding="utf-8")

    monkeypatch.setattr(gitops_dispatcher, "yaml", None)
    ok, err = gitops_dispatcher.validate_compose_security(compose_file, app_dir)
    assert ok is False
    assert err is not None and "pyyaml" in err.lower()


def test_capability_grants_device_mknod_rejected(tmp_path: Path):
    """Ensure :rwm (mknod) is rejected even when the device node exists and is granted."""
    app_dir = tmp_path / "Workloads" / "media"
    app_dir.mkdir(parents=True)
    dev_dir = tmp_path / "dev" / "dri"
    dev_dir.mkdir(parents=True)
    render_node = dev_dir / "renderD128"
    render_node.write_text("", encoding="utf-8")

    grants_file = _write_grants(
        tmp_path / "grants.json",
        {"media": {"devices": [str(render_node)]}},
    )

    compose_file = app_dir / "docker-compose.yml"
    compose_file.write_text(
        f"""
services:
  app:
    image: alpine
    devices:
      - "{render_node}:/dev/dri/renderD128:rwm"
""",
        encoding="utf-8",
    )
    ok, err = gitops_dispatcher.validate_compose_security(
        compose_file, app_dir, app_name="media", grants_file=grants_file
    )
    assert ok is False
    assert err is not None and "mknod" in err.lower()


def test_capability_grants_missing_device_node_rejected(tmp_path: Path):
    """Ensure a granted device path that does not exist on the host fails closed."""
    app_dir = tmp_path / "Workloads" / "media"
    app_dir.mkdir(parents=True)
    missing_node = tmp_path / "dev" / "dri" / "renderD999"

    grants_file = _write_grants(
        tmp_path / "grants.json",
        {"media": {"devices": [str(missing_node)]}},
    )

    compose_file = app_dir / "docker-compose.yml"
    compose_file.write_text(
        f"""
services:
  app:
    image: alpine
    devices:
      - "{missing_node}:/dev/dri/renderD999:rw"
""",
        encoding="utf-8",
    )
    ok, err = gitops_dispatcher.validate_compose_security(
        compose_file, app_dir, app_name="media", grants_file=grants_file
    )
    assert ok is False
    assert err is not None and "does not exist" in err.lower()


def test_capability_grants_volumes_reject_rw_long_syntax(tmp_path: Path):
    """Ensure readOnlyPaths rejects long-syntax bind mounts without read_only: true."""
    app_dir = tmp_path / "Workloads" / "media"
    app_dir.mkdir(parents=True)
    media_dir = tmp_path / "mnt" / "media"
    media_dir.mkdir(parents=True)

    grants_file = _write_grants(
        tmp_path / "grants.json",
        {"media": {"readOnlyPaths": [str(media_dir)]}},
    )
    compose_file = app_dir / "docker-compose.yml"
    compose_file.write_text(
        f"""
services:
  app:
    image: alpine
    volumes:
      - type: bind
        source: "{media_dir}"
        target: /media
        read_only: false
""",
        encoding="utf-8",
    )
    ok, _ = gitops_dispatcher.validate_compose_security(
        compose_file, app_dir, app_name="media", grants_file=grants_file
    )
    assert ok is False


def test_capability_grants_volumes_reject_unsafe_propagation(tmp_path: Path):
    """Ensure readOnlyPaths rejects long-syntax bind mounts with unsafe propagation (rshared)."""
    app_dir = tmp_path / "Workloads" / "media"
    app_dir.mkdir(parents=True)
    media_dir = tmp_path / "mnt" / "media"
    media_dir.mkdir(parents=True)

    grants_file = _write_grants(
        tmp_path / "grants.json",
        {"media": {"readOnlyPaths": [str(media_dir)]}},
    )
    compose_file = app_dir / "docker-compose.yml"
    compose_file.write_text(
        f"""
services:
  app:
    image: alpine
    volumes:
      - type: bind
        source: "{media_dir}"
        target: /media
        read_only: true
        bind:
          propagation: rshared
""",
        encoding="utf-8",
    )
    ok, err = gitops_dispatcher.validate_compose_security(
        compose_file, app_dir, app_name="media", grants_file=grants_file
    )
    assert ok is False
    assert err is not None and "propagation" in err.lower()


def test_capability_grants_volumes_reject_symlink_escape(tmp_path: Path):
    """Ensure readOnlyPaths rejects symlinks resolving outside the granted directory."""
    app_dir = tmp_path / "Workloads" / "media"
    app_dir.mkdir(parents=True)
    media_dir = tmp_path / "mnt" / "media"
    media_dir.mkdir(parents=True)
    outside_dir = tmp_path / "etc"
    outside_dir.mkdir(parents=True)
    escaped_link = media_dir / "escape"
    escaped_link.symlink_to(outside_dir)

    grants_file = _write_grants(
        tmp_path / "grants.json",
        {"media": {"readOnlyPaths": [str(media_dir)]}},
    )
    compose_file = app_dir / "docker-compose.yml"
    compose_file.write_text(
        f"""
services:
  app:
    image: alpine
    volumes:
      - "{escaped_link}:/media:ro"
""",
        encoding="utf-8",
    )
    ok, _ = gitops_dispatcher.validate_compose_security(
        compose_file, app_dir, app_name="media", grants_file=grants_file
    )
    assert ok is False


def test_capability_grants_app_name_none_receives_zero_grants(tmp_path: Path):
    """Ensure app_name=None receives zero grants even when grants.json defines workloads."""
    app_dir = tmp_path / "Workloads" / "media"
    app_dir.mkdir(parents=True)
    media_dir = tmp_path / "mnt" / "media"
    media_dir.mkdir(parents=True)

    grants_file = _write_grants(
        tmp_path / "grants.json",
        {"media": {"readOnlyPaths": [str(media_dir)]}},
    )
    compose_file = app_dir / "docker-compose.yml"
    compose_file.write_text(
        f"""
services:
  app:
    image: alpine
    volumes:
      - "{media_dir}:/media:ro"
""",
        encoding="utf-8",
    )

    ok, _ = gitops_dispatcher.validate_compose_security(
        compose_file, app_dir, app_name=None, grants_file=grants_file
    )
    assert ok is False


def test_capability_grants_malformed_grants_fail_closed(tmp_path: Path):
    """Ensure malformed grants.json fails closed even on a plain compose file."""
    app_dir = tmp_path / "Workloads" / "media"
    app_dir.mkdir(parents=True)
    plain_compose = app_dir / "plain.yml"
    plain_compose.write_text("services:\n  app:\n    image: alpine\n", encoding="utf-8")
    bad_grants = tmp_path / "bad_grants.json"
    bad_grants.write_text("{corrupt", encoding="utf-8")
    ok, err = gitops_dispatcher.validate_compose_security(
        plain_compose, app_dir, app_name="media", grants_file=bad_grants
    )
    assert ok is False
    assert err is not None and "grants" in err.lower()


def test_validate_compose_security_allows_ungranted_gid_1000(tmp_path: Path):
    """Ensure unprivileged numeric GID >= 1000 (1000:1000) is allowed without a grant."""
    app_dir = tmp_path / "Workloads" / "ungranted"
    app_dir.mkdir(parents=True)
    grants_file = _write_grants(tmp_path / "grants.json", {})
    compose_file = app_dir / "docker-compose.yml"
    compose_file.write_text(
        "services:\n  app:\n    image: alpine\n    user: '1000:1000'\n",
        encoding="utf-8",
    )

    ok, err = gitops_dispatcher.validate_compose_security(
        compose_file,
        app_dir,
        app_name="ungranted",
        grants_file=grants_file,
        group_lookup=_fake_group_lookup,
    )
    assert ok is True
    assert err is None


def test_validate_compose_security_rejects_high_numeric_gid_for_privileged_group(
    tmp_path: Path,
):
    """Ensure numeric GID >= 1000 that resolves to a privileged group (docker) fails closed."""
    app_dir = tmp_path / "Workloads" / "ungranted"
    app_dir.mkdir(parents=True)
    grants_file = _write_grants(tmp_path / "grants.json", {})
    compose_file = app_dir / "docker-compose.yml"
    compose_file.write_text(
        "services:\n  app:\n    image: alpine\n    user: '1000:1998'\n",
        encoding="utf-8",
    )

    def lookup_with_high_docker(key: str | int) -> tuple[str, int]:
        if key in (1998, "1998"):
            return ("docker", 1998)
        return _fake_group_lookup(key)

    ok, err = gitops_dispatcher.validate_compose_security(
        compose_file,
        app_dir,
        app_name="ungranted",
        grants_file=grants_file,
        group_lookup=lookup_with_high_docker,
    )
    assert ok is False
    assert err is not None and "docker" in err.lower()


def test_validate_compose_security_rejects_sibling_prefix_paths(tmp_path: Path):
    """Ensure sibling directory prefixes (/dev/dri2, /mnt/media2) cannot bypass containment."""
    app_dir = tmp_path / "Workloads" / "media"
    app_dir.mkdir(parents=True)

    granted_dev = tmp_path / "dev" / "dri"
    granted_dev.mkdir(parents=True)
    sibling_dev_dir = tmp_path / "dev" / "dri2"
    sibling_dev_dir.mkdir(parents=True)
    sibling_node = sibling_dev_dir / "renderD128"
    sibling_node.write_text("", encoding="utf-8")

    granted_media = tmp_path / "mnt" / "media"
    granted_media.mkdir(parents=True)
    sibling_media = tmp_path / "mnt" / "media2"
    sibling_media.mkdir(parents=True)

    grants_file = _write_grants(
        tmp_path / "grants.json",
        {
            "media": {
                "devices": [str(granted_dev)],
                "readOnlyPaths": [str(granted_media)],
            }
        },
    )

    dev_compose = app_dir / "dev-compose.yml"
    dev_compose.write_text(
        f"services:\n  app:\n    image: alpine\n    devices:\n      - '{sibling_node}:/dev/dri/renderD128:rw'\n",
        encoding="utf-8",
    )
    ok_dev, _ = gitops_dispatcher.validate_compose_security(
        dev_compose, app_dir, app_name="media", grants_file=grants_file
    )
    assert ok_dev is False

    vol_compose = app_dir / "vol-compose.yml"
    vol_compose.write_text(
        f"services:\n  app:\n    image: alpine\n    volumes:\n      - '{sibling_media}:/media:ro'\n",
        encoding="utf-8",
    )
    ok_vol, _ = gitops_dispatcher.validate_compose_security(
        vol_compose, app_dir, app_name="media", grants_file=grants_file
    )
    assert ok_vol is False


