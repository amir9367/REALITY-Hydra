#!/usr/bin/env bash
set -euo pipefail

# ─── REALITY-Hydra setup ───────────────────────────────────────────
# Builds, tests, and installs both binaries:
#   hydra-client  (client SOCKS5 proxy)
#   hydra         (server-side epoch automation CLI)
# ───────────────────────────────────────────────────────────────────

VERSION="0.1.0"
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

# Defaults
INSTALL_DIR="$HOME/.local/bin"
CONFIG_DIR="/etc/hydra"
FEATURES="full"
ACTIONS=()

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}▸${NC} $*"; }
ok()    { echo -e "${GREEN}✔${NC} $*"; }
warn()  { echo -e "${YELLOW}⚠${NC} $*"; }
err()   { echo -e "${RED}✘${NC} $*" >&2; }
die()   { err "$@"; exit 1; }

# ─── Help ──────────────────────────────────────────────────────────

usage() {
    echo -e "${BOLD}REALITY-Hydra Setup${NC} ${CYAN}v${VERSION}${NC}"
    echo ""
    echo -e "${BOLD}USAGE:${NC}"
    echo "    ./setup.sh [ACTION...] [OPTIONS]"
    echo ""
    echo -e "${BOLD}ACTIONS:${NC}"
    echo "    (no action)     Run full pipeline: check → build → test → install → config"
    echo "    --check         Check prerequisites only (Rust toolchain)"
    echo "    --build         Build the workspace (release mode)"
    echo "    --test          Run tests, clippy, and fmt checks"
    echo "    --install       Install binaries to INSTALL_DIR"
    echo "    --config        Install sample config to CONFIG_DIR"
    echo "    --uninstall     Remove installed binaries and config"
    echo "    --status        Show installed binaries and config locations"
    echo ""
    echo -e "${BOLD}OPTIONS:${NC}"
    echo "    -f, --features=FEAT   Cargo features to enable (default: full)"
    echo "    -i, --install-dir=DIR Binary install directory (default: ~/.local/bin)"
    echo "    -c, --config-dir=DIR  Config install directory (default: /etc/hydra)"
    echo "    -s, --skip-tests      Skip test suite"
    echo "    -b, --skip-build      Skip build step"
    echo "    -n, --no-config       Skip config installation"
    echo "    -v, --verbose         Verbose output"
    echo "    -h, --help            Show this help"
    echo "    -V, --version         Show version"
    echo ""
    echo -e "${BOLD}EXAMPLES:${NC}"
    echo -e "    ${CYAN}# Full install (everything)${NC}"
    echo "    ./setup.sh"
    echo ""
    echo -e "    ${CYAN}# Build + test only (no install)${NC}"
    echo "    ./setup.sh --check --build --test"
    echo ""
    echo -e "    ${CYAN}# Install only (skip build and tests)${NC}"
    echo "    ./setup.sh --install --config --skip-build --skip-tests"
    echo ""
    echo -e "    ${CYAN}# Custom install dir${NC}"
    echo "    ./setup.sh --install-dir /usr/local/bin"
    echo ""
    echo -e "    ${CYAN}# Build with only live-dns feature${NC}"
    echo "    ./setup.sh --build --features live-dns"
    echo ""
    echo -e "    ${CYAN}# Check what's installed${NC}"
    echo "    ./setup.sh --status"
    echo ""
    echo -e "    ${CYAN}# Clean uninstall${NC}"
    echo "    ./setup.sh --uninstall"
    echo ""
    echo -e "${BOLD}ENVIRONMENT:${NC}"
    echo "    INSTALL_DIR     Same as --install-dir"
    echo "    CONFIG_DIR      Same as --config-dir"
    echo "    FEATURES        Same as --features"
    echo "    SKIP_TESTS      Set to 1 to skip tests"
    echo "    SKIP_BUILD      Set to 1 to skip build"
    echo ""
}

# ─── Arg parsing ───────────────────────────────────────────────────

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --check|--build|--test|--install|--config|--uninstall|--status)
                ACTIONS+=("$1")
                shift
                ;;
            -f|--features)
                [ -z "${2:-}" ] && die "Option $1 requires a value"
                FEATURES="$2"; shift 2
                ;;
            --features=*)
                FEATURES="${1#*=}"; shift
                ;;
            -i|--install-dir)
                [ -z "${2:-}" ] && die "Option $1 requires a value"
                INSTALL_DIR="$2"; shift 2
                ;;
            --install-dir=*)
                INSTALL_DIR="${1#*=}"; shift
                ;;
            -c|--config-dir)
                [ -z "${2:-}" ] && die "Option $1 requires a value"
                CONFIG_DIR="$2"; shift 2
                ;;
            --config-dir=*)
                CONFIG_DIR="${1#*=}"; shift
                ;;
            -s|--skip-tests)
                SKIP_TESTS=1; shift
                ;;
            -b|--skip-build)
                SKIP_BUILD=1; shift
                ;;
            -n|--no-config)
                NO_CONFIG=1; shift
                ;;
            -v|--verbose)
                VERBOSE=1; shift
                ;;
            -h|--help)
                usage; exit 0
                ;;
            -V|--version)
                echo "setup.sh v${VERSION}"; exit 0
                ;;
            -*)
                die "Unknown option: $1 (use --help for usage)"
                ;;
            *)
                die "Unexpected argument: $1 (use --help for usage)"
                ;;
        esac
    done
}

VERBOSE="${VERBOSE:-0}"
SKIP_TESTS="${SKIP_TESTS:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
NO_CONFIG="${NO_CONFIG:-0}"

# ─── Actions ───────────────────────────────────────────────────────

check_rust() {
    info "Checking Rust toolchain..."

    # Source cargo env if it exists (handles missing PATH entries)
    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env" 2>/dev/null || true
    fi

    # Install rustup if missing
    if ! command -v rustup &>/dev/null; then
        warn "Rust not found. Installing via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        if [ -f "$HOME/.cargo/env" ]; then
            # shellcheck disable=SC1091
            source "$HOME/.cargo/env"
        fi
        if ! command -v rustc &>/dev/null; then
            die "Rust installation failed"
        fi
        ok "installed $(rustc --version)"
    else
        ok "rustup $(rustup --version 2>/dev/null | head -1)"
    fi

    # Verify cargo actually works (not just that the binary exists)
    local cargo_ver=""
    if ! cargo_ver="$(cargo --version 2>/dev/null)"; then
        warn "cargo is broken or missing — repairing toolchain..."
        rustup default stable 2>/dev/null || rustup toolchain install stable -y
        if ! cargo_ver="$(cargo --version 2>/dev/null)"; then
            die "Could not repair Rust toolchain. Run: rustup default stable"
        fi
    fi
    ok "cargo  $cargo_ver"

    # Verify rustc works
    local rustc_ver=""
    if ! rustc_ver="$(rustc --version 2>/dev/null)"; then
        warn "rustc is broken — repairing toolchain..."
        rustup default stable 2>/dev/null || rustup toolchain install stable -y
        if ! rustc_ver="$(rustc --version 2>/dev/null)"; then
            die "Could not repair rustc. Run: rustup default stable"
        fi
    fi
    ok "rustc  $rustc_ver"

    # Version check — require 1.88+
    local needed="1.88.0"
    local current
    current="$(echo "$rustc_ver" | sed 's/.*\([0-9]\+\.[0-9]\+\.[0-9]\+\).*/\1/')"
    if [ "$(printf '%s\n%s\n' "$needed" "$current" | sort -V | head -1)" != "$needed" ]; then
        die "Rust $needed+ required, found $current — run: rustup update"
    fi
}

do_build() {
    if [ "$SKIP_BUILD" = "1" ]; then
        warn "Skipping build (SKIP_BUILD=1)"
        return
    fi
    info "Building workspace (features: $FEATURES)..."
    if [ "$VERBOSE" = "1" ]; then
        cargo build --release --workspace --features "$FEATURES"
    else
        cargo build --release --workspace --features "$FEATURES" 2>&1 | tail -5
    fi
    ok "Build complete"
}

do_test() {
    if [ "$SKIP_TESTS" = "1" ]; then
        warn "Skipping tests (SKIP_TESTS=1)"
        return
    fi
    info "Running test suite..."
    cargo test --workspace 2>&1
    ok "All tests passed"

    info "Running clippy lints..."
    cargo clippy --all-targets -- -D warnings 2>&1
    ok "Clippy clean"

    info "Checking formatting..."
    cargo fmt --all --check 2>&1
    ok "Formatting clean"
}

do_install() {
    mkdir -p "$INSTALL_DIR"

    local bins=("hydra-client" "hydra")
    local src_dir="$REPO_ROOT/target/release"

    for bin in "${bins[@]}"; do
        local src="$src_dir/$bin"
        if [ ! -x "$src" ]; then
            die "Binary not found: $src — run --build first"
        fi
        cp "$src" "$INSTALL_DIR/$bin"
        chmod +x "$INSTALL_DIR/$bin"
        ok "Installed $bin → $INSTALL_DIR/$bin"
    done

    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        warn "$INSTALL_DIR is not in your PATH"
        echo "  Add to your shell profile:"
        echo "    export PATH=\"$INSTALL_DIR:\$PATH\""
    fi
}

do_config() {
    if [ "$NO_CONFIG" = "1" ]; then
        warn "Skipping config (NO_CONFIG=1)"
        return
    fi

    local target_config="$CONFIG_DIR/hydra.toml"
    local sample_config="$REPO_ROOT/crates/pool-engine/fixtures/hydra.toml"

    if [ -f "$target_config" ]; then
        warn "Config already exists at $target_config — skipping"
        return
    fi

    sudo mkdir -p "$CONFIG_DIR"
    sudo cp "$sample_config" "$target_config"
    sudo chmod 600 "$target_config"
    ok "Sample config installed → $target_config"
    warn "Edit $target_config with real master_secret + server_salt before deploying!"
}

do_uninstall() {
    info "Uninstalling REALITY-Hydra..."

    local bins=("hydra-client" "hydra")
    local removed=0

    for bin in "${bins[@]}"; do
        local path="$INSTALL_DIR/$bin"
        if [ -f "$path" ]; then
            rm -f "$path"
            ok "Removed $path"
            removed=$((removed + 1))
        fi
    done

    local config="$CONFIG_DIR/hydra.toml"
    if [ -f "$config" ]; then
        sudo rm -f "$config"
        ok "Removed $config"
        removed=$((removed + 1))
    fi

    if [ "$removed" -eq 0 ]; then
        warn "Nothing to uninstall"
    else
        ok "Uninstall complete ($removed items removed)"
    fi
}

do_status() {
    echo ""
    echo -e "${BOLD}REALITY-Hydra Status${NC}"
    echo -e "${CYAN}────────────────────────────────────────${NC}"

    echo -e "\n${BOLD}Binaries:${NC}"
    for bin in hydra-client hydra; do
        local path="$INSTALL_DIR/$bin"
        if [ -x "$path" ]; then
            ok "$path"
        else
            err "$path (not installed)"
        fi
    done

    echo -e "\n${BOLD}Config:${NC}"
    local config="$CONFIG_DIR/hydra.toml"
    if [ -f "$config" ]; then
        ok "$config"
    else
        err "$config (not installed)"
    fi

    echo -e "\n${BOLD}Rust toolchain:${NC}"
    if command -v rustc &>/dev/null; then
        ok "$(rustc --version)"
        ok "$(cargo --version)"
    else
        err "not installed"
    fi

    echo -e "\n${BOLD}Build artifacts:${NC}"
    if [ -f "$REPO_ROOT/target/release/hydra-client" ]; then
        ok "target/release/hydra-client ($(du -h "$REPO_ROOT/target/release/hydra-client" | cut -f1))"
    else
        warn "target/release/hydra-client (not built)"
    fi
    if [ -f "$REPO_ROOT/target/release/hydra" ]; then
        ok "target/release/hydra ($(du -h "$REPO_ROOT/target/release/hydra" | cut -f1))"
    else
        warn "target/release/hydra (not built)"
    fi
    echo ""
}

# ─── Main ──────────────────────────────────────────────────────────

main() {
    parse_args "$@"

    # Default to full pipeline if no actions specified
    if [ ${#ACTIONS[@]} -eq 0 ]; then
        ACTIONS=(--check --build --test --install --config)
    fi

    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  REALITY-Hydra Setup${NC} ${CYAN}v${VERSION}${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""

    cd "$REPO_ROOT"

    for action in "${ACTIONS[@]}"; do
        case "$action" in
            --check)    check_rust ;;
            --build)    do_build ;;
            --test)     do_test ;;
            --install)  do_install ;;
            --config)   do_config ;;
            --uninstall) do_uninstall; echo ""; return ;;
            --status)   do_status; return ;;
        esac
        echo ""
    done

    # Print usage summary after full pipeline
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  REALITY-Hydra installed successfully!${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  Binaries:  $INSTALL_DIR/{hydra-client,hydra}"
    echo "  Config:    $CONFIG_DIR/hydra.toml"
    echo ""
    echo -e "  ${BOLD}CLIENT:${NC}"
    echo "    hydra-client -c $CONFIG_DIR/hydra.toml --listen 127.0.0.1:1080"
    echo ""
    echo -e "  ${BOLD}SERVER:${NC}"
    echo "    hydra -c $CONFIG_DIR/hydra.toml"
    echo "    hydra -c $CONFIG_DIR/hydra.toml --format xray"
    echo ""
}

main "$@"
