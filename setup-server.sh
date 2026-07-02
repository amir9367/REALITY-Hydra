#!/usr/bin/env bash
set -euo pipefail

# ─── DEPRECATED shim ────────────────────────────────────────────────
# Server setup now lives in the unified installer: `./setup.sh server`.
# This wrapper is kept so old invocations keep working; it forwards every
# argument to `setup.sh server`.
#
#   ./setup-server.sh                 →  ./setup.sh server
#   ./setup-server.sh --status        →  ./setup.sh status
#   ./setup-server.sh --rotate        →  ./setup.sh rotate
# ────────────────────────────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
echo "note: setup-server.sh is deprecated — use './setup.sh server'. Forwarding..." >&2

# Translate the few legacy flags that map to subcommands; pass the rest through.
case "${1:-}" in
    --status)    shift; exec "$REPO_ROOT/setup.sh" status "$@" ;;
    --rotate)    shift; exec "$REPO_ROOT/setup.sh" rotate "$@" ;;
    --uninstall) shift; exec "$REPO_ROOT/setup.sh" uninstall "$@" ;;
    *)           exec "$REPO_ROOT/setup.sh" server "$@" ;;
esac
