# Example host-local instance configuration for Canopy NixOS Core.
# Copy to /etc/nixos/homelab-instance.nix (recommended, loaded with --impure)
# or gitignored nixos/instance.nix, and customize for your host.
{ ... }:

{
  homelab.domain = "example.com";
  homelab.operatorUser = "operator";

  # Host-granted workload capabilities ("Compose Requests, Nix Grants" — ADR-0005).
  # Keyed by workload name matching ~/Workloads/<app>.
  homelab.workloadGrants = {
    # Example hardware-accelerated media workload:
    # media-server = {
    #   devices = [ "/dev/dri/renderD128" ];
    #   groups = [ "render" ];
    #   readOnlyPaths = [ "/mnt/media" ];
    # };
  };
}
