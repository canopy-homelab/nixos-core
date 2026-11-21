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

Under [ADR-0001](0001-3tier-architecture-and-provenance.md), [ADR-0002](0002-appctl-control-plane-architecture.md) (`DEC-04`, `DEC-05`), and [ADR-0004](0004-unified-workloads-monorepo.md), `validate_compose_security()` in `scripts/gitops_dispatcher.py` enforces a uniform deny-all pre-flight policy on Tier 2 workload `docker-compose.yml` files:

* All `devices:` mounts are unconditionally blocked.
* All host bind mounts outside `~/Workloads/<app>` and `~/var/lib/homelab/<app>` are blocked.
* All host namespace sharing (`network_mode: host`, etc.) is blocked.

While this prevents a Tier 2 `git push` from escalating privileges on the host, it creates real friction for legitimate single-operator capability classes:

1. **Hardware-Accelerated & External-Storage Workloads**: Media transcoding or compute workloads requiring an integrated GPU (`/dev/dri`) must mount host device nodes, pass a supplementary device group (such as `render` / GID `303`), and read an external read-only storage partition (`/media:ro`). Currently, `devices:` and external bind mounts are completely blocked, while `group_add:` is unconstrained (risking arbitrary host GID elevation to groups like `docker` or `wheel` unless strictly governed).
2. **LAN Broadcast / Peer-Discovery Services**: Workloads that send Wake-on-LAN magic packets or discover LAN peers struggle across Docker bridge boundaries, prompting requests for `network_mode: host`. However, blanket host networking collapses network namespace isolation, exposing loopback control services (such as `homelab-appctl.service` on `127.0.0.1:9001`) and bypassing proxy network segmentation.
3. **Host-Agnostic Core Boundary**: Hardcoding `/dev/dri`, `/media`, or specific workload names inside `nixos-core` violates platform genericism and couples Core to one machine's hardware and app catalog.

The central architectural question is: **How should Canopy NixOS Core permit hardware devices, supplementary groups, and external read-only storage paths for specific workloads without hardcoding personal infrastructure into `nixos-core` or weakening the Tier 2 -> Tier 3 trust boundary?**

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
   * `nixos/modules/homeserver.nix` defines `homelab.workloadGrants` as an attribute set keyed by workload name, supporting three explicit grant fields:
     * `devices` (list of exact device paths, e.g. `"/dev/dri"` or `"/dev/dri/renderD128"`).
     * `groups` (list of supplementary group names/GIDs permitted in `group_add`, such as `"303"` or `"render"`).
     * `readOnlyPaths` (list of host directories permitted for `:ro` bind mounts only).
   * Note on `network_mode: host`: To preserve the `127.0.0.1:9001` daemon boundary and Traefik reverse-proxy segmentation, host networking is rejected and excluded from `workloadGrants`. Workloads requiring L2 broadcast/discovery should be provisioned on dedicated isolated Docker networks (`macvlan`/`ipvlan`) or host-side intermediaries.
   * `privileged: true`, `/var/run/docker.sock`, `cap_add`, and host namespaces (`pid`, `ipc`, `uts`, `userns_mode`, `network_mode: host`) remain permanently prohibited and are not grantable.

2. **Immutable Host Projection (`/etc/homelab/grants.json`)**:
   * NixOS generates `/etc/homelab/grants.json` (`root`-owned, group-owned by `homelab-operators` with mode `0640`, granting read access to both `homelab-appctl` and `operator` without POSIX ACLs; configurable via `HOMELAB_GRANTS_FILE` for testing).
   * If the grants file is absent, `validate_compose_security()` defaults to zero grants. If present but malformed, validation fails closed.

3. **Exact-Match Pre-Flight Enforcement**:
   * Every capability requested in `<app>/docker-compose.yml` must match an explicit grant for `<app>` in `/etc/homelab/grants.json`:
     * `devices` entries must have their host path resolve canonically strictly within the granted device node or directory, strictly disallowing directory traversal (`..`) or symlink escapes.
     * `groups` entries are canonicalized bidirectionally between group names and integer GIDs via the host group database (so a grant of `"render"` or `"303"` accepts either representation in `group_add`, while unknown or ungranted groups fail closed).
     * `readOnlyPaths` grants permit mounts **only** when `:ro` mode is specified and the canonical host path resolves strictly within the granted directory.
   * *Trade-off (Host Path Coupling)*: Workload Compose definitions declare physical host paths matching host grants; logical capability aliasing via environment variable injection remains an optional future refinement.

4. **Tracked Instance Template (`nixos/instance.example.nix`)**:
   * `nixos-core` tracks `nixos/instance.example.nix` documenting `homelab.domain`, `homelab.operatorUser`, and `homelab.workloadGrants`.
   * Live hosts keep their concrete configuration in `/etc/nixos/homelab-instance.nix` (loaded via `--impure` flake evaluation) or gitignored `nixos/instance.nix` without build-time file translation between the two.

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
