---
type: decision
status: accepted
project: homelab-core
date: 2026-11-20
tags: [architecture, security, nixos, workloads, appctl, gitops]
amends: 0002-appctl-control-plane-architecture.md
---

# ADR 0005: Host-Granted Workload Capabilities ("Compose Requests, Nix Grants")

## Context and Problem Statement

Under [ADR-0002](0002-appctl-control-plane-architecture.md) (`DEC-04`, `DEC-05`) and [ADR-0004](0004-unified-workloads-monorepo.md), `validate_compose_security()` in `scripts/gitops_dispatcher.py` enforces a uniform deny-all pre-flight policy on Tier 2 workload `docker-compose.yml` files:

* All `devices:` mounts are unconditionally blocked.
* All host bind mounts outside `~/Workloads/<app>` and `~/var/lib/homelab/<app>` are blocked.
* All host namespace sharing (`network_mode: host`, etc.) is blocked.

While this prevents a Tier 2 `git push` from escalating privileges on the host, it creates real friction for legitimate single-operator workloads:

1. **Hardware Acceleration (`jellyfin`)**: Using an integrated GPU (`/dev/dri`) for VAAPI transcoding and reading a dedicated media partition (`/media:ro`) are blocked unless the validator is relaxed globally or fragile host-level bind-mount workarounds are maintained.
2. **LAN Broadcast / Peer Services (e.g., `lg-smtv-mcp`)**: Workloads that send Wake-on-LAN broadcasts or discover LAN peers may require `network_mode: host` when bridged Docker networks cannot forward subnet broadcasts.
3. **Host-Agnostic Core Boundary**: Hardcoding `/dev/dri`, `/media`, or specific workload names inside `nixos-core` violates platform genericism and couples Core to one machine's hardware and app catalog.

The central architectural question is: **How should Canopy NixOS Core permit hardware devices, external read-only paths, and host networking for specific workloads without hardcoding personal infrastructure into `nixos-core` or weakening the Tier 2 -> Tier 3 trust boundary?**

## Decision Drivers

* **Preserve the Trust Split**: A push to Tier 2 (`canopy-workloads`) must never be able to grant itself root-equivalent host access; capability grants must originate from root-level Tier 3 NixOS host configuration (`nixos-rebuild switch`).
* **Keep `nixos-core` Generic**: Core defines the capability schema and enforcement logic only, with zero hardcoded personal app names, device nodes, or media paths.
* **Keep `app.yaml` Free of Host Paths**: Workload manifests remain declarative routing/provenance metadata; `docker-compose.yml` already declares the requested `devices`, `volumes`, `group_add`, and `network_mode`.
* **Documented Instance Schema**: Provide a tracked `nixos/instance.example.nix` template so new hosts (or a future setup wizard) can configure `homelab.domain`, `homelab.operatorUser`, and `homelab.workloadGrants` cleanly in `/etc/nixos/homelab-instance.nix` (or gitignored `nixos/instance.nix`).
* **Fail-Closed Validation**: Absent, unreadable, or malformed grant configuration must default to zero grants (identical to today's strict baseline), and `privileged: true` and `/var/run/docker.sock` mounts remain permanently prohibited for all workloads.

## Considered Options

* **Option 1: Relax `validate_compose_security()` Globally**: Allow `/dev/dri` and arbitrary `:ro` paths for all workloads.
* **Option 2: Store Grants in `~/Workloads/grants.yaml`**: Allow `canopy-workloads` to declare its own exceptions alongside `deployments.yaml`.
* **Option 3: "Compose Requests, Nix Grants" via `homelab.workloadGrants` (Adopted)**: Define a typed `homelab.workloadGrants` option in `nixos-core` rendered to root-owned `/etc/homelab/grants.json`, validated with Pydantic v2 (`extra="forbid"`), and checked by `validate_compose_security()`.

## Decision Outcome

Chosen option: **Option 3: "Compose Requests, Nix Grants" via `homelab.workloadGrants`**, because it keeps `nixos-core` 100% hardware- and workload-agnostic while preserving the security boundary between Tier 2 Git pushes and Tier 3 `sudo nixos-rebuild switch`.

### Summary of Architectural Commitments

This ADR formally amends [ADR-0002](0002-appctl-control-plane-architecture.md) (`DEC-04`, `DEC-05`) with the following commitments:

1. **Typed Host Grant Schema (`homelab.workloadGrants`)**:
   * `nixos/modules/homeserver.nix` defines `homelab.workloadGrants` as an attribute set keyed by workload name, supporting four explicit grant fields:
     * `devices` (list of exact device paths, e.g. `"/dev/dri"` or `"/dev/dri/renderD128"`).
     * `groups` (list of supplementary group names/GIDs permitted in `group_add`).
     * `readOnlyPaths` (list of host directories permitted for `:ro` bind mounts only).
     * `hostNetwork` (boolean permitting `network_mode: host`).
   * `privileged: true`, `/var/run/docker.sock`, `cap_add`, and `pid`/`ipc`/`uts`/`userns_mode: host` remain permanently prohibited and are not grantable.

2. **Immutable Host Projection (`/etc/homelab/grants.json`)**:
   * NixOS generates `/etc/homelab/grants.json` (root-owned, readable by `homelab-appctl` and `homelab-gitops`, configurable via `HOMELAB_GRANTS_FILE` for testing).
   * If the grants file is absent, `validate_compose_security()` defaults to zero grants. If present but malformed, validation fails closed.

3. **Exact-Match Pre-Flight Enforcement**:
   * Every capability requested in `<app>/docker-compose.yml` must match an explicit grant for `<app>` in `/etc/homelab/grants.json`:
     * `devices` entries must resolve canonically within the granted device path(s) (with no `..` traversal or container-side privilege escalation).
     * `readOnlyPaths` grants permit mounts **only** when `:ro` is specified and `Path.resolve()` remains contained within the granted directory.
     * `network_mode: host` is permitted **only** when `hostNetwork = true` for that workload.

4. **Tracked Instance Template (`nixos/instance.example.nix`)**:
   * `nixos-core` tracks `nixos/instance.example.nix` documenting `homelab.domain`, `homelab.operatorUser`, and `homelab.workloadGrants`.
   * Live hosts keep their concrete configuration in `/etc/nixos/homelab-instance.nix` (or gitignored `nixos/instance.nix`) without build-time file translation between the two.

## Pros and Cons of the Options

### Option 1: Relax `validate_compose_security()` Globally
* Good, because it requires minimal code.
* Bad, because it hardcodes host hardware assumptions into `nixos-core` and cannot safely express `network_mode: host`.

### Option 2: Store Grants in `~/Workloads/grants.yaml`
* Good, because grants live next to `deployments.yaml`.
* Bad, because Tier 2 would self-authorize Tier 3 host privileges on a single `git push`.

### Option 3: "Compose Requests, Nix Grants" via `homelab.workloadGrants` (Adopted)
* Good, because `nixos-core` stays generic, `canopy-workloads` stays clean, and privilege elevation requires explicit host-level `nixos-rebuild switch`.
* Bad, because adding a new privileged capability for a workload requires editing `/etc/nixos/homelab-instance.nix` and rebuilding NixOS before `appctl up`.
