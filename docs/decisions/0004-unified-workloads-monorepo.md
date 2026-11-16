---
type: decision
status: accepted
project: homelab-core
date: 2026-11-16
tags: [architecture, workloads, monorepo, gitops, state, nixos]
amends: 0001-3tier-architecture-and-provenance.md
---

# ADR 0004: Unified ~/Workloads Monorepo & State Isolation

## Context and Problem Statement

Under [ADR-0001](0001-3tier-architecture-and-provenance.md), Tier 2 deployment descriptors (`app.yaml` and `docker-compose.yml`) were hosted in `~/Sites/<app>` as one standalone Git repository per application. In practice, operating a fleet of 9+ Tier 2 workloads (including both Class A source-backed services and Class B off-the-shelf image-only tools) revealed structural friction:

1. **Per-App Repository Sprawl**: Every third-party tool (`jellyfin`, `snappymail`, `excalidraw`, `mermaid`) required its own Gitea repository, webhook configuration, and clone lifecycle just to version 2–3 declarative files.
2. **Naming Coupling (`~/Sites`)**: The directory name `~/Sites` implied web-only sites rather than general self-hosted workloads (mail, media, diagrams, internal tools).
3. **Cross-Workload Drift & Webhook Overhead**: Coordinating shared network, label, or manifest conventions across N separate deployment repositories required N separate commits and N separate Gitea webhook registrations.
4. **State Co-location Risk**: Moving to a unified monorepo increases the blast radius if any workload stores mutable runtime state inside its deployment directory instead of the isolated host state root (`~/var/lib/homelab/<app>/`).

The central architectural question is: **How should Canopy NixOS Core organize Tier 2 deployment descriptors to eliminate per-app repository sprawl while preserving independent per-workload deployment, backward-compatible migration, and strict runtime state isolation?**

## Decision Drivers

* **Eliminate Tier 2 Repository Sprawl**: Consolidate Tier 2 deployment descriptors (`<app>/app.yaml`, `<app>/docker-compose.yml`) into a single unified `canopy-workloads` monorepo at `~/Workloads`.
* **Preserve Per-Workload Independence**: Pushing to `canopy-workloads` must selectively deploy only the workload subdirectories modified in that push, without restarting unaffected services.
* **Zero-Downtime Migration Compatibility**: Support `WORKLOADS_DIR` as the canonical configuration variable with a clean `SITES_DIR` fallback, and support hybrid per-app `.git` checkouts alongside monorepo subdirectories during transition.
* **Strict State Isolation**: Enforce `~/var/lib/homelab/<app>/` as the sole persistent runtime state root so the `~/Workloads` Git working tree remains 100% declarative and clean.
* **Preserve 3-Tier & Security Boundaries**: Keep Tier 1 application source repositories independent, keep Core platform services in `~/Core`, and maintain `deployments.yaml` allowlisting and Compose AST security validation.

## Considered Options

* **Option 1: Keep Per-App Tier 2 Repositories in `~/Sites/<app>` (Status Quo)**: Maintain one Git repository per workload under `~/Sites`.
* **Option 2: Merge Tier 2 Workloads into `~/Core`**: Place all workload `app.yaml` and `docker-compose.yml` files directly inside `canopy-homelab/nixos-core`.
* **Option 3: Unified `~/Workloads` Monorepo (`canopy-workloads`) with Isolated Host State (Adopted)**: Amend ADR-0001 to rename Tier 2 from `~/Sites` to `~/Workloads`, consolidate Tier 2 manifests into `canopy-workloads`, and enforce `~/var/lib/homelab/<app>/` state isolation.

## Decision Outcome

Chosen option: **Option 3: Unified `~/Workloads` Monorepo (`canopy-workloads`) with Isolated Host State**, because it eliminates Tier 2 repository and webhook sprawl while preserving the 3-tier boundary between Tier 1 application source, Tier 2 deployment intent, and Tier 3 NixOS Core platform infrastructure.

### Summary of Architectural Commitments

This ADR formally amends [ADR-0001](0001-3tier-architecture-and-provenance.md) with the following commitments:

1. **Tier 2 Rename (`~/Sites` $\rightarrow$ `~/Workloads`)**:
   * The canonical Tier 2 deployment root is `~/Workloads` (configured via `homelab.workloadsDir` / `homelab.sitesDir` in NixOS and `WORKLOADS_DIR` in Core services).
   * Core Python modules (`appctl_engine.py`, `appctl_daemon.py`, `appctl_router.py`, `gitops_dispatcher.py`) default to `~/Workloads`, honoring `WORKLOADS_DIR` first and falling back to `SITES_DIR` for backward compatibility.
2. **Unified `canopy-workloads` Monorepo**:
   * Tier 2 workloads reside as subdirectories `~/Workloads/<app>/` inside the `canopy-workloads` monorepo, each owning its own `app.yaml` and `docker-compose.yml`.
   * During migration, `~/Workloads/<app>` may operate either as a monorepo subdirectory (sharing `~/Workloads/.git`) or as a standalone checkout (`~/Workloads/<app>/.git`).
3. **Mandatory State Isolation (`~/var/lib/homelab/<app>/`)**:
   * All mutable application data (databases, caches, uploads, dynamic configs) must reside under `~/var/lib/homelab/<app>/` (or named Docker volumes) and never inside `~/Workloads/<app>/`.
   * NixOS `systemd.tmpfiles.rules` provisions `~/Workloads` and `~/var/lib/homelab` with recursive `A+` POSIX ACLs for `homelab-appctl`.
4. **Core Registry & Safe Directory Containment**:
   * `config/deployments.yaml` maps admitted workload identities to canonical `~/Workloads/<app>` paths, enforced by strict containment inside `WORKLOADS_DIR`.
   * Host Git `safe.directory` configuration includes `~/Workloads` and `~/Workloads/*` (alongside `~/Core`).

## Pros and Cons of the Options

### Option 1: Keep Per-App Tier 2 Repositories in `~/Sites/<app>`
* Good, because each workload has an isolated Git history and independent webhook.
* Bad, because adding or updating a simple third-party service requires creating and maintaining a full Git repository.
* Bad, because fleet-wide manifest or Compose conventions require N separate PRs and commits.

### Option 2: Merge Tier 2 Workloads into `~/Core`
* Good, because only one repository exists for Core and Workloads.
* Bad, because it violates the 3-tier boundary (ADR-0001), mixing NixOS host/platform configuration with application deployment topologies.
* Bad, because `~/Core` changes would trigger NixOS evaluation/rebuild concerns alongside routine app updates.

### Option 3: Unified `~/Workloads` Monorepo (`canopy-workloads`) with Isolated Host State (Adopted)
* Good, because Tier 2 deployment descriptors are managed in one repository with atomic cross-workload changes and a single GitOps webhook.
* Good, because Tier 1 software repositories and Tier 3 NixOS Core remain strictly decoupled.
* Good, because `WORKLOADS_DIR` $\rightarrow$ `SITES_DIR` fallback allows incremental host cutover without breaking existing environments.
* Bad, because GitOps webhook dispatch and provenance inspection must distinguish monorepo-root `.git` from per-app `.git` checkouts (addressed in follow-up slices).
* Bad, because monorepo commits touching multiple subdirectories require changed-path filtering to avoid redeploying unaffected workloads.

## Consequences

### Positive Consequences
* **Single Tier 2 Control Surface**: One `canopy-workloads` repository versions all workload manifests and Compose topologies.
* **Clean Git Working Tree**: Enforcing `~/var/lib/homelab/<app>/` ensures runtime state never dirties the monorepo checkout.
* **Smooth Cutover**: Dual `WORKLOADS_DIR` / `SITES_DIR` environment support and `homelab.sitesDir` NixOS option compatibility prevent abrupt breakage.

### Negative Consequences & Accepted Trade-offs
* **Hybrid Provenance & Subpath Dispatch Complexity**: Core tooling (`provenance.py`, `gitops_dispatcher.py`) must handle both monorepo-level `.git` and legacy per-app `.git` directories, as well as selective changed-directory deployment on monorepo pushes.

## More Information

* **Amended Decision**: [`0001-3tier-architecture-and-provenance.md`](0001-3tier-architecture-and-provenance.md)
* **Architecture Specification**: [`docs/architecture.md`](../architecture.md)
* **Secrets & State Contract**: [`docs/secrets-and-state.md`](../secrets-and-state.md)
