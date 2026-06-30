#!/usr/bin/env bash
set -euo pipefail

# ─── REALITY-Hydra Server Setup ─────────────────────────────────────
# Builds, tests, and installs server-side components:
#   hydra          (epoch automation CLI — generates serverNames)
#   health-checker (optional sidecar — validates pool coherence)
# Also sets up config, cron-based epoch rotation, and Xray reload.
# ────────────────────────────────────────────────────────────────────

VERSION="0.1.0"
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

# Defaults
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/hydra"
CRON_INTERVAL="*/30"      # every 30 minutes (epoch is 6h, but check often)
XRAY_RELOAD_CMD=""
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
    echo -e "${BOLD}REALITY-Hydra Server Setup${NC} ${CYAN}v${VERSION}${NC}"
    echo ""
    echo -e "${BOLD}USAGE:${NC}"
    echo "    ./setup-server.sh [ACTION...] [OPTIONS]"
    echo ""
    echo -e "${BOLD}ACTIONS:${NC}"
    echo "    (no action)     Full pipeline: check → build → test → install → config → cron"
    echo "    --check         Check prerequisites (Rust toolchain)"
    echo "    --build         Build server binaries (release mode)"
    echo "    --test          Run tests, clippy, and fmt checks"
    echo "    --install       Install binaries to INSTALL_DIR"
    echo "    --config        Install sample config to CONFIG_DIR"
    echo "    --cron          Install cron job for automatic epoch rotation"
    echo "    --uninstall     Remove installed binaries, config, and cron"
    echo "    --status        Show installed files, cron, and current epoch"
    echo "    --rotate        Force-rotate serverNames now (manual trigger)"
    echo ""
    echo -e "${BOLD}OPTIONS:${NC}"
    echo "    -f, --features=FEAT       Cargo features (default: full)"
    echo "    -i, --install-dir=DIR     Binary install dir (default: /usr/local/bin)"
    echo "    -c, --config-dir=DIR      Config dir (default: /etc/hydra)"
    echo "    --cron-interval=EXPR      Cron interval (default: */30)"
    echo "    --reload-cmd=CMD          Command to reload Xray after rotation"
    echo "    -s, --skip-tests          Skip test suite"
    echo "    -b, --skip-build          Skip build step"
    echo "    -n, --no-config           Skip config installation"
    echo "    -v, --verbose             Verbose output"
    echo "    -h, --help                Show this help"
    echo "    -V, --version             Show version"
    echo ""
    echo -e "${BOLD}EXAMPLES:${NC}"
    echo -e "    ${CYAN}# Full server install${NC}"
    echo "    sudo ./setup-server.sh"
    echo ""
    echo -e "    ${CYAN}# Install + set Xray reload command${NC}"
    echo "    sudo ./setup-server.sh --reload-cmd 'systemctl reload xray'"
    echo ""
    echo -e "    ${CYAN}# Just generate serverNames for right now${NC}"
    echo "    ./setup-server.sh --rotate"
    echo ""
    echo -e "    ${CYAN}# Check server status${NC}"
    echo "    ./setup-server.sh --status"
    echo ""
}

# ─── Arg parsing ───────────────────────────────────────────────────

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --check|--build|--test|--install|--config|--cron|--uninstall|--status|--rotate)
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
            --cron-interval)
                [ -z "${2:-}" ] && die "Option $1 requires a value"
                CRON_INTERVAL="$2"; shift 2
                ;;
            --cron-interval=*)
                CRON_INTERVAL="${1#*=}"; shift
                ;;
            --reload-cmd)
                [ -z "${2:-}" ] && die "Option $1 requires a value"
                XRAY_RELOAD_CMD="$2"; shift 2
                ;;
            --reload-cmd=*)
                XRAY_RELOAD_CMD="${1#*=}"; shift
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
                echo "setup-server.sh v${VERSION}"; exit 0
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

    # Ensure cargo env is sourced (handles fresh installs and missing PATH entries)
    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env" 2>/dev/null || true
    fi

    # Check if rustup exists
    if command -v rustup &>/dev/null; then
        ok "rustup $(rustup --version 2>/dev/null | head -1)"
    else
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
    fi

    # Verify cargo actually works (not just that the command exists)
    if ! cargo_version=$(cargo --version 2>/dev/null); then
        warn "cargo is broken or missing — repairing toolchain..."
        rustup default stable 2>/dev/null || rustup toolchain install stable -y
        if ! cargo_version=$(cargo --version 2>/dev/null); then
            die "Could not repair Rust toolchain. Run: rustup default stable"
        fi
    fi
    ok "cargo  $cargo_version"

    # Verify rustc works
    if ! rustc_version=$(rustc --version 2>/dev/null); then
        warn "rustc is broken — repairing toolchain..."
        rustup default stable 2>/dev/null || rustup toolchain install stable -y
        if ! rustc_version=$(rustc --version 2>/dev/null); then
            die "Could not repair rustc. Run: rustup default stable"
        fi
    fi
    ok "rustc  $rustc_version"

    # Version check — require 1.88+
    local needed="1.88.0"
    local current
    current="$(echo "$rustc_version" | sed 's/.*\([0-9]\+\.[0-9]\+\.[0-9]\+\).*/\1/')"
    if [ "$(printf '%s\n%s\n' "$needed" "$current" | sort -V | head -1)" != "$needed" ]; then
        die "Rust $needed+ required, found $current — run: rustup update"
    fi

    # Check cmake if full features requested
    if [ "$FEATURES" = "full" ]; then
        if command -v cmake &>/dev/null; then
            ok "cmake $(cmake --version | head -1)"
        else
            warn "cmake not found — needed for BoringSSL (full feature)"
            warn "Install: apt install cmake / dnf install cmake / brew install cmake"
            warn "Or build without it: ./setup-server.sh --features ''"
        fi
    fi
}

do_build() {
    if [ "$SKIP_BUILD" = "1" ]; then
        warn "Skipping build (SKIP_BUILD=1)"
        return
    fi
    info "Building server binaries (features: $FEATURES)..."
    local feat_args=()
    if [ -n "$FEATURES" ] && [ "$FEATURES" != "none" ]; then
        feat_args=(--features "$FEATURES")
    fi
    if [ "$VERBOSE" = "1" ]; then
        cargo build --release -p hydra-cli -p health-checker "${feat_args[@]}"
    else
        cargo build --release -p hydra-cli -p health-checker "${feat_args[@]}" 2>&1 | tail -5
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

    local bins=("hydra")
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

    mkdir -p "$CONFIG_DIR"
    cp "$sample_config" "$target_config"
    chmod 600 "$target_config"
    ok "Sample config installed → $target_config"
    warn "Edit $target_config with real master_secret + server_salt before deploying!"
}

do_cron() {
    local hydra_bin="$INSTALL_DIR/hydra"
    local config="$CONFIG_DIR/hydra.toml"
    local log_file="/var/log/hydra-rotate.log"
    local cron_tag="# REALITY-Hydra epoch rotation"

    if [ ! -x "$hydra_bin" ]; then
        die "hydra binary not found at $hydra_bin — run --install first"
    fi
    if [ ! -f "$config" ]; then
        die "Config not found at $config — run --config first"
    fi

    # Build the rotation command
    local rotate_cmd="$hydra_bin -c $config --format json > /tmp/hydra-servernames.json"
    if [ -n "$XRAY_RELOAD_CMD" ]; then
        rotate_cmd="$rotate_cmd && $XRAY_RELOAD_CMD"
    fi

    # Remove old entry if present
    local tmpcron
    tmpcron="$(mktemp)"
    crontab -l 2>/dev/null | grep -v "$cron_tag" > "$tmpcron" || true

    # Add new entry
    echo "$CRON_INTERVAL * * * * $rotate_cmd >> $log_file 2>&1 $cron_tag" >> "$tmpcron"
    crontab "$tmpcron"
    rm -f "$tmpcron"

    ok "Cron job installed (${CRON_INTERVAL} * * * *)"
    info "Rotation command: $rotate_cmd"
    info "Log: $log_file"

    # Create log file
    touch "$log_file" 2>/dev/null || warn "Could not create $log_file (may need sudo)"

    # Do an initial rotation
    info "Running initial epoch rotation..."
    eval "$rotate_cmd"
    ok "Initial rotation complete → /tmp/hydra-servernames.json"
}

do_rotate() {
    local hydra_bin="$INSTALL_DIR/hydra"
    local config="$CONFIG_DIR/hydra.toml"

    # Fall back to cargo run if not installed
    if [ ! -x "$hydra_bin" ]; then
        if [ -f "$REPO_ROOT/target/release/hydra" ]; then
            hydra_bin="$REPO_ROOT/target/release/hydra"
        else
            die "hydra binary not found. Run --build --install first."
        fi
    fi
    if [ ! -f "$config" ]; then
        config="$REPO_ROOT/crates/pool-engine/fixtures/hydra.toml"
        warn "Config not at $CONFIG_DIR/hydra.toml — using fixture"
    fi

    echo ""
    echo -e "${BOLD}Current epoch serverNames (lines):${NC}"
    "$hydra_bin" -c "$config"

    echo ""
    echo -e "${BOLD}Xray inbound snippet:${NC}"
    "$hydra_bin" -c "$config" --format xray

    echo ""
    echo -e "${BOLD}JSON array:${NC}"
    "$hydra_bin" -c "$config" --format json
    echo ""
}

do_uninstall() {
    info "Uninstalling REALITY-Hydra server..."
    local removed=0

    # Remove binary
    local bin="$INSTALL_DIR/hydra"
    if [ -f "$bin" ]; then
        rm -f "$bin"
        ok "Removed $bin"
        removed=$((removed + 1))
    fi

    # Remove config (ask if not forced)
    local config="$CONFIG_DIR/hydra.toml"
    if [ -f "$config" ]; then
        echo -e "${YELLOW}Remove config $config? [y/N]${NC} "
        read -r answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            rm -f "$config"
            ok "Removed $config"
            removed=$((removed + 1))
        else
            info "Kept $config"
        fi
    fi

    # Remove cron entry
    local cron_tag="# REALITY-Hydra epoch rotation"
    if crontab -l 2>/dev/null | grep -q "$cron_tag"; then
        local tmpcron
        tmpcron="$(mktemp)"
        crontab -l 2>/dev/null | grep -v "$cron_tag" > "$tmpcron"
        crontab "$tmpcron"
        rm -f "$tmpcron"
        ok "Removed cron job"
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
    echo -e "${BOLD}REALITY-Hydra Server Status${NC}"
    echo -e "${CYAN}────────────────────────────────────────${NC}"

    echo -e "\n${BOLD}Binary:${NC}"
    local bin="$INSTALL_DIR/hydra"
    if [ -x "$bin" ]; then
        ok "$bin"
    else
        err "$bin (not installed)"
    fi

    echo -e "\n${BOLD}Config:${NC}"
    local config="$CONFIG_DIR/hydra.toml"
    if [ -f "$config" ]; then
        ok "$config"
        # Show current epoch info
        if [ -x "$bin" ]; then
            local epoch
            epoch=$("$bin" -c "$config" --single --format json 2>/dev/null)
            if [ -n "$epoch" ]; then
                local count
                count=$(echo "$epoch" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "?")
                info "Current epoch: $count active SNIs"
            fi
        fi
    else
        err "$config (not installed)"
    fi

    echo -e "\n${BOLD}Cron:${NC}"
    local cron_tag="# REALITY-Hydra epoch rotation"
    if crontab -l 2>/dev/null | grep -q "$cron_tag"; then
        local entry
        entry=$(crontab -l 2>/dev/null | grep "$cron_tag")
        ok "$entry"
    else
        err "No cron job installed"
    fi

    echo -e "\n${BOLD}Rust toolchain:${NC}"
    if command -v rustc &>/dev/null; then
        ok "$(rustc --version)"
        ok "$(cargo --version)"
    else
        err "Not installed"
    fi

    echo -e "\n${BOLD}Build artifacts:${NC}"
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
        ACTIONS=(--check --build --test --install --config --cron)
    fi

    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  REALITY-Hydra Server Setup${NC} ${CYAN}v${VERSION}${NC}"
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
            --cron)     do_cron ;;
            --uninstall) do_uninstall; echo ""; return ;;
            --status)   do_status; return ;;
            --rotate)   do_rotate; return ;;
        esac
        echo ""
    done

    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  REALITY-Hydra server installed successfully!${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  Binary:     $INSTALL_DIR/hydra"
    echo "  Config:     $CONFIG_DIR/hydra.toml"
    echo "  Cron:       ${CRON_INTERVAL} * * * *"
    echo ""
    echo -e "  ${BOLD}MANUAL COMMANDS:${NC}"
    echo "    # Generate serverNames for current epoch:"
    echo "    hydra -c $CONFIG_DIR/hydra.toml"
    echo ""
    echo "    # Paste-ready Xray inbound:"
    echo "    hydra -c $CONFIG_DIR/hydra.toml --format xray"
    echo ""
    echo "    # JSON array for automation:"
    echo "    hydra -c $CONFIG_DIR/hydra.toml --format json"
    echo ""
    echo -e "  ${BOLD}CRON:${NC}"
    echo "    Automatic rotation runs ${CRON_INTERVAL} * * * *"
    echo "    Output: /tmp/hydra-servernames.json"
    if [ -n "$XRAY_RELOAD_CMD" ]; then
        echo "    Xray reload: $XRAY_RELOAD_CMD"
    fi
    echo ""
    echo -e "  ${BOLD}NEXT STEPS:${NC}"
    echo "    1. Edit $CONFIG_DIR/hydra.toml with real keys"
    echo "    2. Set --reload-cmd to your Xray reload command"
    echo "    3. Point Xray's serverNames at the generated JSON"
    echo ""
}

main "$@"
