#!/usr/bin/env bash
# Read-only ForceCommand allowlist wrapper for the `agents` SSH user.
set -euo pipefail

export CORE_DIR="${CORE_DIR:-/home/operator/Core}"
export WORKLOADS_DIR="${WORKLOADS_DIR:-/home/operator/Workloads}"
export DOCKER_HOST="${DOCKER_HOST:-tcp://127.0.0.1:2375}"

raw_cmd="${SSH_ORIGINAL_COMMAND:-}"

if [[ -z "${raw_cmd// }" ]]; then
  echo "Error: empty SSH_ORIGINAL_COMMAND is not permitted" >&2
  exit 1
fi

if [[ "$raw_cmd" == *$'\n'* || "$raw_cmd" == *$'\r'* ]]; then
  echo "Error: control characters are not permitted" >&2
  exit 1
fi

if [[ "$raw_cmd" == *[';&|`$()<>\\'\''"']* ]]; then
  echo "Error: shell metacharacters are not permitted" >&2
  exit 1
fi

# Word-split without globbing or shell evaluation
set -f
read -r -a args <<< "$raw_cmd"
set +f

if [[ ${#args[@]} -eq 0 ]]; then
  echo "Error: empty SSH_ORIGINAL_COMMAND is not permitted" >&2
  exit 1
fi

cmd="${args[0]}"

case "$cmd" in
  docker)
    if [[ ${#args[@]} -lt 2 ]]; then
      echo "Error: docker subcommand is required" >&2
      exit 1
    fi
    subcmd="${args[1]}"
    case "$subcmd" in
      ps|logs|inspect) ;;
      *)
        echo "Error: docker subcommand '$subcmd' is not permitted" >&2
        exit 1
        ;;
    esac
    for arg in "${args[@]:2}"; do
      case "$arg" in
        -H|-H=*|--host|--host=*|--context|--context=*|-c|-c=*|--config|--config=*)
          echo "Error: docker connection override flag '$arg' is not permitted" >&2
          exit 1
          ;;
      esac
    done
    exec docker "${args[@]:1}"
    ;;
  journalctl)
    for arg in "${args[@]:1}"; do
      case "$arg" in
        --flush|--rotate|--vacuum-*|--relinquish-var|--sync|--setup-keys|--update-catalog)
          echo "Error: mutating journalctl flag '$arg' is not permitted" >&2
          exit 1
          ;;
      esac
    done
    exec journalctl "${args[@]:1}"
    ;;
  appctl)
    if [[ ${#args[@]} -lt 2 ]]; then
      echo "Error: appctl subcommand is required" >&2
      exit 1
    fi
    subcmd="${args[1]}"
    case "$subcmd" in
      list|status|info|logs|ssl|health|resolve) ;;
      *)
        echo "Error: appctl subcommand '$subcmd' is not permitted" >&2
        exit 1
        ;;
    esac
    exec appctl "${args[@]:1}"
    ;;
  *)
    echo "Error: command '$cmd' is not permitted" >&2
    exit 1
    ;;
esac
