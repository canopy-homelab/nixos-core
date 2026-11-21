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

Under [ADR-0001](0001-3tier-architecture-and-provenance.md), [ADR-0002](0002-appctl-control-plane-architecture.md) (`DEC-04`, `DEC-05`), and [ADR-0004](0004-unified-workloads-monorepo.md), `validate_compose_security()` (shared pre-flight validator invoked authoritatively by `homelab-appctl.service` in `scripts/appctl_router.py` across CLI and GitOps paths) enforces a uniform deny-all policy on Tier 2 workload `docker-compose.yml` files:

* `devices:` mounts are blocked.
* Host bind mounts outside `~/Workloads/<app>` and `~/var/lib/homelab/<app>` are blocked.
* Host namespace sharing (`network_mode: host`, etc.) is blocked.

While this prevents a Tier 2 `git push` from escalating privileges on the host, it blocks required single-operator capability classes:

1. **Hardware-Accelerated & External-Storage Workloads**: Media transcoding or compute workloads requiring an integrated GPU (`/dev/dri/renderD128`) must mount host device nodes, pass a supplementary device group (such as `render` / GID `303`), and read an external read-only storage partition (`/media:ro`). Currently, `devices:` and external bind mounts are blocked, while `group_add:` and `user:` primary GIDs are unconstrained (risking arbitrary host GID elevation to groups such as `docker` or `wheel` unless constrained).
2. **LAN Broadcast / Peer-Discovery Services (Out of Scope for Host Networking)**: Workloads that send Wake-on-LAN magic packets or discover LAN peers cannot traverse Docker bridge L2 isolation, prompting requests for `network_mode: host`. Because blanket host networking collapses network namespace isolation—exposing loopback control services such as `homelab-appctl.service` on `127.0.0.1:9001`—host networking remains out of scope for workload grants and must be handled via isolated L2 Docker networks (`macvlan`/`ipvlan`) or host-side intermediaries.
3. **Host-Agnostic Core Boundary**: Hardcoding `/dev/dri`, `/media`, or specific workload names inside `nixos-core` violates platform portability and couples Core to one machine's hardware and app catalog.

The central architectural question is: **How should Canopy NixOS Core permit hardware devices, supplementary/primary GIDs, and external read-only storage paths for specific workloads without hardcoding personal infrastructure into `nixos-core` or weakening the Tier 2 -> Tier 3 trust boundary?**

## Decision Drivers

* **Preserve the Trust Split**: A push to Tier 2 (`canopy-workloads`) must never grant itself root-equivalent host access; capability grants must originate from root-level Tier 3 NixOS host configuration (`nixos-rebuild switch`).
* **Keep `nixos-core` Generic**: Core defines the capability schema and enforcement logic only, with zero hardcoded personal app names, device nodes, or media paths.
* **Keep `app.yaml` Free of Host Paths**: Workload manifests remain declarative routing/provenance metadata; `docker-compose.yml` already declares requested `devices`, `volumes`, `group_add`, and `user`.
* **Documented Instance Schema**: Provide a tracked `nixos/instance.example.nix` template so new hosts can configure `homelab.domain`, `homelab.operatorUser`, and `homelab.workloadGrants` in `/etc/nixos/homelab-instance.nix` (or gitignored `nixos/instance.nix`).
* **Fail-Closed Validation**: An absent grants file defaults to zero grants (current baseline); a present but unreadable, tampered, or malformed grants file fails closed across all workloads. `privileged: true`, `/var/run/docker.sock`, `cap_add`, `device_cgroup_rules:`, and host/container namespace sharing remain permanently prohibited.

## Considered Options

* **Option 1: Relax `validate_compose_security()` Globally**: Allow `/dev/dri` and arbitrary `:ro` paths for all workloads.
* **Option 2: Store Grants in `~/Workloads/grants.yaml`**: Allow `canopy-workloads` to declare its own exceptions alongside `deployments.yaml`.
* **Option 3: "Compose Requests, Nix Grants" via `homelab.workloadGrants` (Adopted)**: Define a typed `homelab.workloadGrants` option in `nixos-core` rendered to root-owned `/etc/homelab/grants.json`, validated with Pydantic v2 (`extra="forbid"`), and enforced by `validate_compose_security()`.

## Decision Outcome

Chosen option: **Option 3: "Compose Requests, Nix Grants" via `homelab.workloadGrants`**, because it keeps `nixos-core` hardware- and workload-agnostic while preserving the security boundary between Tier 2 Git pushes and Tier 3 `sudo nixos-rebuild switch`.

### Summary of Architectural Commitments

This ADR formally amends [ADR-0002](0002-appctl-control-plane-architecture.md) (`DEC-04`, `DEC-05`) with the following commitments:

1. **Typed Host Grant Schema (`homelab.workloadGrants`)**:
   * `nixos/modules/homeserver.nix` defines `homelab.workloadGrants` as an attribute set keyed by workload name, supporting three explicit grant fields:
     * `devices` (list of exact device paths; prefer specific nodes such as `"/dev/dri/renderD128"` over whole directories unless display control is required).
     * `groups` (list of supplementary/primary group names or GIDs permitted in `group_add` and `user:`, such as `"render"` or `"303"`; privileged host groups `0`/`root`, `wheel`, and `docker` are permanently rejected).
     * `readOnlyPaths` (list of host directories permitted for read-only bind mounts only).
   * `privileged: true`, `/var/run/docker.sock`, `cap_add`, `device_cgroup_rules:`, and namespace sharing (`network_mode: host`, `network_mode: container:*`, `network_mode: service:*`, `pid`, `ipc`, `uts`, `userns_mode: host`) remain permanently prohibited and are not grantable.

2. **Immutable Host Projection (`/etc/homelab/grants.json`)**:
   * NixOS generates `/etc/homelab/grants.json` (`root`-owned, group-owned by `homelab-operators` with mode `0640`, granting read access to both `homelab-appctl` and `operator` without POSIX ACLs; overridable via `HOMELAB_GRANTS_FILE`, which is reserved in `RESERVED_ENV_KEYS` so workload `.env` / `app.yaml` cannot override it).
   * In production, the loader verifies regular-file (non-symlink), root-owned, non-world/group-writable permissions before parsing.
   * If `/etc/homelab/grants.json` is **absent**, `validate_compose_security()` defaults to zero grants. If it is **present** but unreadable, fails permission checks, or fails Pydantic v2 (`extra="forbid"`) validation, pre-flight fails closed for all workloads.

3. **Exact-Match Pre-Flight Enforcement**:
   * `validate_compose_security()` evaluates resolved values (post-6-layer env assembly, or rejects uninterpolated `${...}` in `devices`, `volumes`, `group_add`, and `user`). When `app_name` is `None` or unknown, zero grants apply.
   * Every capability requested in `<app>/docker-compose.yml` must match an explicit grant for `<app>`:
     * `devices` entries support `host:container[:perms]`, forbid `m` (`mknod`) in permissions, and require the host path to exist and resolve canonically within the granted device node or directory, disallowing `..` traversal or symlink escapes.
     * `group_add` transitions from unconstrained to **default-deny** when no `groups` grant exists; `groups` entries canonicalize bidirectionally between group names and integer GIDs via the host group database. `user:` primary GIDs must either fall within granted `groups` or be unprivileged numeric IDs that do not map to privileged or host-sensitive groups.
     * `readOnlyPaths` validates both short (`host:container:ro[,opts]`) and long (`type: bind`, `read_only: true`) volume syntax, rejects unsafe bind propagation, and requires the host path to exist and resolve canonically within the granted directory.

4. **Tracked Instance Template (`nixos/instance.example.nix`)**:
   * `nixos-core` tracks `nixos/instance.example.nix` documenting `homelab.domain`, `homelab.operatorUser`, and `homelab.workloadGrants`.
   * Live hosts keep concrete values in `/etc/nixos/homelab-instance.nix` (loaded via `--impure` flake evaluation, taking precedence over gitignored `nixos/instance.nix` if both exist). Both paths remain optional so pure `nix flake check` CI passes with defaults.

## Pros and Cons of the Options

### Option 1: Relax `validate_compose_security()` Globally
* Good, because it requires minimal code.
* Bad, because it hardcodes host hardware assumptions into `nixos-core` and weakens tenant isolation for all workloads.

### Option 2: Store Grants in `~/Workloads/grants.yaml`
* Good, because grants live next to `deployments.yaml`.
* Bad, because Tier 2 would self-authorize Tier 3 host privileges on a single `git push`.

### Option 3: "Compose Requests, Nix Grants" via `homelab.workloadGrants` (Adopted)
* Good, because `nixos-core` stays generic, `canopy-workloads` remains free of host-privilege grants, and privilege elevation requires explicit host-level `nixos-rebuild switch`.
* Bad, because adding a new privileged capability requires editing `/etc/nixos/homelab-instance.nix` and rebuilding NixOS before `appctl up`.

## Consequences

### Positive Consequences
* **Hardware & Media Operability**: Workloads can use GPU acceleration and external `:ro` storage cleanly via standard `docker-compose.yml` syntax once authorized by the host.
* **Closed GID & Namespace Loopholes**: Transitions `group_add:`, `user:` primary GIDs, `device_cgroup_rules:`, and `network_mode: container:*` to fail-closed enforcement.
* **CI Compatibility**: Pure `nix flake check` evaluates cleanly with empty default grants.

### Negative Consequences & Accepted Trade-offs
* **Tier 2 / Tier 3 Deployment Ordering**: Pushing a Compose file requesting a new capability before running `nixos-rebuild switch` fails closed at pre-flight (surfaced clearly via a distinct capability-denial error/audit signal such as `ERR_CAPABILITY_NOT_GRANTED`).
* **Host Path Coupling**: Workload Compose files declare physical host paths matching host grants; logical capability aliasing via environment-variable injection remains an optional future refinement.

## More Information

* Amends [ADR-0002](0002-appctl-control-plane-architecture.md) (`DEC-04`, `DEC-05`).
* Related specifications: [docs/architecture.md](../architecture.md), [docs/appctl.md](../appctl.md), [docs/secrets-and-state.md](../secrets-and-state.md).
