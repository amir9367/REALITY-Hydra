#!/usr/bin/env bash
set -euo pipefail

# ─── REALITY-Hydra installer (Linux) ───────────────────────────────
# A single, 3x-ui-style CLI that installs and manages BOTH sides on Linux:
#
#   • server  — builds `hydra`, generates the shared secret/salt + REALITY keys,
#               installs a systemd service + epoch timer, and prints a one-paste
#               connection bundle to hand to clients.
#   • client  — builds `hydra`, takes the bundle (or manual values) from a
#               server, writes hydra.toml, and runs a SOCKS5 proxy.
#
# The intended flow is: run the SERVER install first; it prints the salt, key,
# address and a `hydra://…` bundle. Then run the CLIENT install and paste the
# bundle (or the individual values) in.
#
# Run with no arguments for the interactive menu, or pass a subcommand:
#   ./setup.sh server | client | status | rotate | bundle | uninstall
# ───────────────────────────────────────────────────────────────────

VERSION="0.3.0"
REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

# ─── Colors / output helpers (3x-ui style) ─────────────────────────
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    CYAN='\033[0;36m'; BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; BLUE=''; BOLD=''; NC=''
fi
info()  { echo -e "${CYAN}▸${NC} $*"; }
ok()    { echo -e "${GREEN}✔${NC} $*"; }
warn()  { echo -e "${YELLOW}⚠${NC} $*"; }
err()   { echo -e "${RED}✘${NC} $*" >&2; }
die()   { err "$@"; exit 1; }
banner() {
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  REALITY-Hydra Installer${NC} ${BOLD}v${VERSION}${NC}  ${CYAN}(Linux)${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
}

# ─── Defaults (overridable by flags / env) ─────────────────────────
ROLE=""                                # server | client (empty = ask)
FEATURES="${FEATURES:-}"               # empty = no native TLS toolchain needed
SERVER_INSTALL_DIR="${SERVER_INSTALL_DIR:-/usr/local/bin}"
SERVER_CONFIG_DIR="${SERVER_CONFIG_DIR:-/etc/hydra}"
CLIENT_INSTALL_DIR="${CLIENT_INSTALL_DIR:-$HOME/.local/bin}"
CLIENT_CONFIG_DIR="${CLIENT_CONFIG_DIR:-$HOME/.config/hydra}"
LISTEN="${LISTEN:-127.0.0.1:1080}"
PORT="${PORT:-443}"
SCHEDULE="${SCHEDULE:-hourly}"         # systemd OnCalendar for the server timer
SKIP_TESTS="${SKIP_TESTS:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
ASSUME_YES="${ASSUME_YES:-0}"
NONINTERACTIVE="${HYDRA_NONINTERACTIVE:-0}"
[ -t 0 ] || NONINTERACTIVE=1           # piped stdin → non-interactive

# Detected platform facts (filled by scan_system).
DISTRO=""; DISTRO_FAMILY=""; PKG=""; ARCH=""; ARCH_OK=1

# ─── Distro + architecture detection (mirrors 3x-ui) ───────────────
scan_system() {
    local os_file=""
    if [ -r /etc/os-release ]; then
        os_file=/etc/os-release
    elif [ -r /usr/lib/os-release ]; then
        os_file=/usr/lib/os-release
    else
        die "Cannot read /etc/os-release — unsupported system."
    fi
    # Read os-release in a SUBSHELL and export only the fields we need. Sourcing
    # it directly would clobber this installer's own $VERSION (os-release also
    # defines VERSION=…), corrupting the banner (e.g. "v24.04.4 LTS").
    local ID ID_LIKE PRETTY_NAME
    # shellcheck disable=SC1090
    eval "$(. "$os_file"; printf 'ID=%q\nID_LIKE=%q\nPRETTY_NAME=%q\n' \
        "${ID:-}" "${ID_LIKE:-}" "${PRETTY_NAME:-}")"
    DISTRO="${ID:-unknown}"

    case "$DISTRO" in
        ubuntu|debian|raspbian|linuxmint|pop|elementary|zorin|kali|armbian|devuan)
            DISTRO_FAMILY="debian"; PKG="apt" ;;
        fedora|rhel|centos|rocky|almalinux|ol|amzn|virtuozzo)
            DISTRO_FAMILY="rhel"
            if command -v dnf >/dev/null 2>&1; then PKG="dnf"; else PKG="yum"; fi ;;
        arch|manjaro|endeavouros|garuda|parch|artix)
            DISTRO_FAMILY="arch"; PKG="pacman" ;;
        opensuse*|sles|suse)
            DISTRO_FAMILY="suse"; PKG="zypper" ;;
        alpine)
            DISTRO_FAMILY="alpine"; PKG="apk" ;;
        *)
            DISTRO_FAMILY="unknown"
            for p in apt dnf yum pacman zypper apk; do
                command -v "$p" >/dev/null 2>&1 && { PKG="$p"; break; }
            done ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)          ARCH="x86_64" ;;
        aarch64|arm64)         ARCH="aarch64" ;;
        armv7l|armv7|armv6l)   ARCH="arm" ;;
        i386|i686|x86)         ARCH="x86" ;;
        *)                     ARCH="$(uname -m)"; ARCH_OK=0 ;;
    esac

    info "Distro:  ${BOLD}${PRETTY_NAME:-$DISTRO}${NC} (family: ${DISTRO_FAMILY}, pkg: ${PKG:-none})"
    info "Arch:    ${BOLD}${ARCH}${NC} $([ "$ARCH_OK" = 1 ] && echo "" || echo "${YELLOW}(untested)${NC}")"
    # NOTE: use `if` blocks, not `[ … ] && warn`. Under `set -e`, a trailing
    # `[ false ] && cmd` makes this function return non-zero, which aborts the
    # whole script right here — before the menu ever prints.
    if [ "$DISTRO_FAMILY" = "unknown" ]; then
        warn "Unrecognized distro — will try '$PKG' and rustup; may need manual deps."
    fi
    if [ -z "${PKG:-}" ]; then
        warn "No known package manager found — install build deps manually if the build fails."
    fi
    return 0
}

# Elevate a command with sudo when not root.
SUDO=""
need_root() { [ "$(id -u)" -eq 0 ] || SUDO="sudo"; }

# Install a list of native packages via the detected package manager.
pkg_install() {
    [ $# -eq 0 ] && return 0
    [ -z "${PKG:-}" ] && { warn "No package manager — skipping: $*"; return 0; }
    info "Installing packages: $*"
    case "$PKG" in
        apt)    $SUDO apt-get update -qq && $SUDO apt-get install -y "$@" ;;
        dnf)    $SUDO dnf install -y "$@" ;;
        yum)    $SUDO yum install -y "$@" ;;
        pacman) $SUDO pacman -Sy --needed --noconfirm "$@" ;;
        zypper) $SUDO zypper --non-interactive install "$@" ;;
        apk)    $SUDO apk add --no-cache "$@" ;;
    esac
}

# Map generic dep names to this distro's package names, then install what's missing.
ensure_build_deps() {
    info "Scanning build requirements..."
    local want=() need=()

    # C toolchain + pkg-config + curl + git are always useful; cmake only for `full`.
    case "$DISTRO_FAMILY" in
        debian) want=(curl git pkg-config build-essential libssl-dev) ;;
        rhel)   want=(curl git pkgconf-pkg-config gcc gcc-c++ make openssl-devel) ;;
        arch)   want=(curl git pkgconf base-devel openssl) ;;
        suse)   want=(curl git pkg-config gcc gcc-c++ make libopenssl-devel) ;;
        alpine) want=(curl git pkgconf build-base openssl-dev) ;;
        *)      want=(curl git) ;;
    esac
    if [ "$FEATURES" = "full" ] || [[ ",$FEATURES," == *",boring-impersonate,"* ]]; then
        case "$DISTRO_FAMILY" in
            debian|rhel|suse|alpine) want+=(cmake) ;;
            arch)                    want+=(cmake) ;;
            *)                       want+=(cmake) ;;
        esac
        # BoringSSL also wants a modern clang/go on some distros; nasm not needed with `ring`.
    fi

    # Only install what's actually missing (checked by the command, best-effort).
    for p in "${want[@]}"; do need+=("$p"); done
    if [ "$ASSUME_YES" != 1 ] && [ "$NONINTERACTIVE" != 1 ]; then
        echo -e "  Will ensure: ${BOLD}${need[*]}${NC}"
        read -rp "  Install missing build dependencies now? [Y/n] " a
        case "$a" in [Nn]*) warn "Skipping dependency install (build may fail)."; return 0 ;; esac
    fi
    need_root
    if ! pkg_install "${need[@]}"; then
        warn "Some packages failed to install."
        # A broken dpkg state is the usual culprit on Debian/Ubuntu — surface the fix.
        if [ "$PKG" = apt ]; then
            warn "If you saw 'dpkg was interrupted', run this and retry:"
            warn "    sudo dpkg --configure -a && sudo apt-get install -y ${need[*]}"
        fi
    fi

    # Verify the C linker actually exists — the Rust build needs `cc`. Without
    # this check the script used to print '✔ Build dependencies ready' and then
    # die later with 'linker `cc` not found', which is much harder to diagnose.
    if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
        err "No C compiler (cc/gcc) found — the Rust build will fail with 'linker \`cc\` not found'."
        case "$DISTRO_FAMILY" in
            debian) err "Fix: sudo dpkg --configure -a && sudo apt-get install -y build-essential" ;;
            rhel)   err "Fix: sudo $PKG install -y gcc gcc-c++ make" ;;
            arch)   err "Fix: sudo pacman -S --needed base-devel" ;;
            suse)   err "Fix: sudo zypper install -y gcc gcc-c++ make" ;;
            alpine) err "Fix: sudo apk add build-base" ;;
            *)      err "Install your distro's C toolchain (gcc/make) and re-run." ;;
        esac
        die "Cannot continue without a C compiler."
    fi
    ok "Build dependencies ready"
}

# ─── Rust toolchain (rustup stable, the most compatible choice) ────
MIN_RUST_MAJOR=1; MIN_RUST_MINOR=88
ensure_rust() {
    [ -f "$HOME/.cargo/env" ] && { . "$HOME/.cargo/env" 2>/dev/null || true; }
    if ! command -v cargo >/dev/null 2>&1; then
        warn "Rust not found — installing via rustup (stable)..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
        [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
        command -v cargo >/dev/null 2>&1 || die "Rust installation failed."
    fi
    local ver maj min
    ver="$(rustc --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
    maj="${ver%%.*}"; min="$(echo "$ver" | cut -d. -f2)"
    if [ "${maj:-0}" -lt "$MIN_RUST_MAJOR" ] || { [ "${maj:-0}" -eq "$MIN_RUST_MAJOR" ] && [ "${min:-0}" -lt "$MIN_RUST_MINOR" ]; }; then
        warn "Rust $ver < ${MIN_RUST_MAJOR}.${MIN_RUST_MINOR} — updating via rustup..."
        rustup update stable && rustup default stable
    fi
    ok "$(rustc --version)"
    ok "$(cargo --version)"
}

# ─── Build / test ──────────────────────────────────────────────────
feat_args() {
    if [ -n "$FEATURES" ] && [ "$FEATURES" != "none" ]; then echo "--features $FEATURES"; fi
}

do_build() {
    [ "$SKIP_BUILD" = 1 ] && { warn "Skipping build (SKIP_BUILD=1)"; return 0; }
    info "Building release binary 'hydra' (features: ${FEATURES:-none})..."
    # shellcheck disable=SC2046
    ( cd "$REPO_ROOT" && cargo build --release -p hydra-cli $(feat_args) )
    ok "Build complete → target/release/hydra"
}

do_test() {
    [ "$SKIP_TESTS" = 1 ] && { warn "Skipping tests (SKIP_TESTS=1)"; return 0; }
    info "Running workspace tests..."
    ( cd "$REPO_ROOT" && cargo test --workspace )
    ok "Tests passed"
}

hydra_src() { echo "$REPO_ROOT/target/release/hydra"; }

install_bin() {
    local dir="$1"; local src; src="$(hydra_src)"
    [ -x "$src" ] || die "hydra binary not found at $src — build first."
    mkdir -p "$dir"
    install -m 0755 "$src" "$dir/hydra" 2>/dev/null || { cp "$src" "$dir/hydra" && chmod 0755 "$dir/hydra"; }
    ok "Installed hydra → $dir/hydra"
    case ":$PATH:" in
        *":$dir:"*) : ;;
        *) warn "$dir is not on PATH — add: export PATH=\"$dir:\$PATH\"" ;;
    esac
}

# ─── Connection bundle (portable client config, no private key) ────
# A bundle is: hydra://<base64 of a client hydra.toml>. It carries everything a
# client needs (secret, salt, pbk, short_id, dest, and the exact SNI pool) EXCEPT
# the server private key, which is stripped. base64 keeps it a single copy-paste
# token that both bash and PowerShell can decode without extra tooling.
make_bundle() {
    local server_cfg="$1"
    # Strip the `private_key = ...` line so the bundle is client-safe.
    local client_toml
    client_toml="$(grep -v '^[[:space:]]*private_key' "$server_cfg")"
    printf 'hydra://%s\n' "$(printf '%s' "$client_toml" | base64 | tr -d '\n')"
}

decode_bundle() {
    local token="$1"
    token="${token#hydra://}"
    printf '%s' "$token" | base64 -d 2>/dev/null || return 1
}

# ─── Server install ────────────────────────────────────────────────
install_server() {
    [ "$(id -u)" -eq 0 ] || warn "Server install usually needs root (for /usr/local/bin, /etc/hydra, systemd). Re-run with sudo if steps fail."
    need_root

    scan_system
    ensure_build_deps
    ensure_rust
    do_build
    do_test

    install_bin "$SERVER_INSTALL_DIR"
    local hydra="$SERVER_INSTALL_DIR/hydra"
    local cfg="$SERVER_CONFIG_DIR/hydra.toml"

    # Ask for the public reachable address + port (goes into `dest`).
    local addr
    if [ "$NONINTERACTIVE" = 1 ]; then
        addr="${SERVER_ADDR:-}"
        [ -z "$addr" ] && addr="$(detect_public_ip)"
    else
        local guess; guess="$(detect_public_ip)"
        read -rp "$(echo -e "${BOLD}Server public IP or domain${NC} [${guess}]: ")" addr
        addr="${addr:-$guess}"
        read -rp "$(echo -e "${BOLD}REALITY port${NC} [${PORT}]: ")" p
        PORT="${p:-$PORT}"
    fi
    [ -z "$addr" ] && die "No server address given (set SERVER_ADDR=… for non-interactive)."
    local dest="$addr:$PORT"

    $SUDO mkdir -p "$SERVER_CONFIG_DIR"
    if [ -f "$cfg" ]; then
        warn "Config already exists at $cfg — keeping it (delete it to regenerate)."
    else
        info "Generating server config via 'hydra init' (dest=$dest)..."
        $SUDO "$hydra" init --output "$cfg" --dest "$dest" >/dev/null
        $SUDO chmod 600 "$cfg"
        ok "Wrote $cfg"
    fi

    # Install the systemd service + epoch timer (server role).
    if command -v systemctl >/dev/null 2>&1; then
        info "Installing systemd service + timer (schedule: $SCHEDULE)..."
        $SUDO "$hydra" service install --role server --config "$cfg" --schedule "$SCHEDULE" \
            || warn "Service install failed (you can re-run: sudo $hydra service install --role server --config $cfg)"
    else
        warn "systemd not detected — skipping service install."
        warn "Regenerate serverNames from cron/manually: $hydra server-names -c $cfg --format xray"
    fi

    print_server_summary "$hydra" "$cfg" "$dest"
}

# Extract a value for a top-level TOML key (strips base64: prefix, quotes).
toml_val() { grep -E "^[[:space:]]*$2[[:space:]]*=" "$1" | head -1 | sed -E 's/^[^=]*=[[:space:]]*//; s/#.*$//; s/^"//; s/"[[:space:]]*$//; s/[[:space:]]*$//'; }

print_server_summary() {
    local hydra="$1" cfg="$2" dest="$3"
    local secret salt pbk sid
    secret="$(toml_val "$cfg" master_secret)"
    salt="$(toml_val "$cfg" server_salt)"
    pbk="$(grep -E '^[[:space:]]*public_key' "$cfg" | head -1 | sed -E 's/^[^=]*=[[:space:]]*//; s/#.*$//; s/"//g; s/[[:space:]]*$//')"
    sid="$(grep -E '^[[:space:]]*short_ids' "$cfg" | head -1 | sed -E 's/.*\["?//; s/"?\].*//; s/"//g')"

    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Server installed. Give these to your CLIENT.${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${BOLD}Address (dest):${NC}   $dest"
    echo -e "  ${BOLD}master_secret:${NC}    $secret"
    echo -e "  ${BOLD}server_salt:${NC}      $salt"
    echo -e "  ${BOLD}public_key (pbk):${NC} $pbk"
    echo -e "  ${BOLD}short_id:${NC}         $sid"
    echo ""
    echo -e "  ${BOLD}One-paste connection bundle${NC} (recommended — carries the exact SNI pool):"
    echo -e "  ${CYAN}$(make_bundle "$cfg")${NC}"
    echo ""
    echo -e "  ${BOLD}Xray inbound for this epoch:${NC} $hydra server-names -c $cfg --format xray"
    echo -e "  ${BOLD}Rotate now / status:${NC}       ./setup.sh rotate   |   ./setup.sh status"
    echo ""
    echo -e "  ${BOLD}Self-tunnel (no Xray):${NC} run the built-in Rust exit node instead —"
    echo -e "    ${CYAN}$hydra server -c $cfg --listen 0.0.0.0:443${NC}"
    echo -e "    It prints a ${BOLD}cert_pin${NC}; put that + ${BOLD}server_addr = \"$dest\"${NC} in the client's hydra.toml."
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
}

detect_public_ip() {
    local ip=""
    for url in "https://api.ipify.org" "https://ifconfig.me/ip" "https://icanhazip.com"; do
        ip="$(curl -fsS --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]')" || true
        [ -n "$ip" ] && { echo "$ip"; return 0; }
    done
    hostname -I 2>/dev/null | awk '{print $1}'
}

# ─── Client install ────────────────────────────────────────────────
install_client() {
    scan_system
    ensure_build_deps
    ensure_rust
    do_build
    do_test

    install_bin "$CLIENT_INSTALL_DIR"
    local hydra="$CLIENT_INSTALL_DIR/hydra"
    local cfg="$CLIENT_CONFIG_DIR/hydra.toml"
    mkdir -p "$CLIENT_CONFIG_DIR"

    if [ -f "$cfg" ]; then
        warn "Client config already exists at $cfg."
        if [ "$NONINTERACTIVE" != 1 ]; then
            read -rp "  Overwrite it? [y/N] " a
            case "$a" in [Yy]*) : ;; *) info "Keeping existing config."; print_client_summary "$hydra" "$cfg"; return 0 ;; esac
        else
            print_client_summary "$hydra" "$cfg"; return 0
        fi
    fi

    if [ "$NONINTERACTIVE" = 1 ]; then
        if [ -n "${BUNDLE:-}" ]; then
            client_from_bundle "$BUNDLE" "$cfg"
        else
            die "Non-interactive client install needs BUNDLE=hydra://… (or run interactively)."
        fi
    else
        echo ""
        echo -e "${BOLD}How do you want to configure this client?${NC}"
        echo "   1) Paste the hydra:// bundle from the server   ${GREEN}(recommended)${NC}"
        echo "   2) Enter the values manually (address, key, salt, pbk, short-id)"
        read -rp "  Choice [1]: " choice
        case "${choice:-1}" in
            2) client_manual "$hydra" "$cfg" ;;
            *) read -rp "  Paste bundle: " b; client_from_bundle "$b" "$cfg" ;;
        esac
    fi

    # Optional client service.
    if command -v systemctl >/dev/null 2>&1 && [ "$NONINTERACTIVE" != 1 ]; then
        read -rp "  Install a systemd service to run the client on boot? [y/N] " a
        case "$a" in
            [Yy]*)
                need_root
                $SUDO "$hydra" service install --role client --config "$cfg" --listen "$LISTEN" \
                    && ok "Client service installed" || warn "Service install failed" ;;
        esac
    fi

    print_client_summary "$hydra" "$cfg"
}

client_from_bundle() {
    local token="$1" cfg="$2" decoded
    decoded="$(decode_bundle "$token")" || die "Could not decode bundle (expected hydra://<base64>)."
    printf '%s\n' "$decoded" > "$cfg"
    chmod 600 "$cfg"
    ok "Wrote client config from bundle → $cfg"
}

client_manual() {
    local hydra="$1" cfg="$2"
    read -rp "  Server IP or domain: " addr
    read -rp "  REALITY port [${PORT}]: " p; p="${p:-$PORT}"
    read -rp "  master_secret (base64:… or raw): " secret
    read -rp "  server_salt (base64:… or raw):   " salt
    read -rp "  public_key / pbk (base64):       " pbk
    read -rp "  short_id (hex):                  " sid
    if [ -z "$addr" ] || [ -z "$secret" ] || [ -z "$salt" ] || [ -z "$pbk" ]; then
        die "Missing required value (address, secret, salt, and pbk are all required)."
    fi

    # Normalize base64: prefix.
    case "$secret" in base64:*) : ;; *) secret="base64:$secret" ;; esac
    case "$salt"   in base64:*) : ;; *) salt="base64:$salt" ;; esac
    case "$pbk"    in base64:*) pbk="${pbk#base64:}" ;; esac

    # Start from the default pool via `hydra init`, then rewrite the fields.
    local tmp; tmp="$(mktemp)"
    "$hydra" init --output "$tmp" --dest "$addr:$p" --force >/dev/null
    # Substitute the shared values and drop the server private key.
    sed -E -i \
        -e "s|^master_secret .*|master_secret = \"$secret\"|" \
        -e "s|^server_salt .*|server_salt   = \"$salt\"|" \
        -e "s|^([[:space:]]*)public_key .*|\1public_key  = \"$pbk\"|" \
        -e "s|^([[:space:]]*)short_ids .*|\1short_ids   = [\"$sid\"]|" \
        -e "/^[[:space:]]*private_key/d" \
        "$tmp"
    mv "$tmp" "$cfg"; chmod 600 "$cfg"
    ok "Wrote client config → $cfg"
    warn "Manual mode uses the DEFAULT SNI pool. It must match the server's pool —"
    warn "if the server customized its pool, use the hydra:// bundle instead."
}

print_client_summary() {
    local hydra="$1" cfg="$2"
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Client installed.${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${BOLD}Config:${NC} $cfg"
    echo -e "  ${BOLD}Run:${NC}    $hydra serve -c $cfg --listen $LISTEN"
    echo -e "  Point your app's SOCKS5 proxy at ${BOLD}$LISTEN${NC}."
    echo -e "  With real DNS + BoringSSL: rebuild with ${BOLD}--features full${NC}."
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
}

# ─── status / rotate / bundle / uninstall ──────────────────────────
find_hydra() {
    for c in "$SERVER_INSTALL_DIR/hydra" "$CLIENT_INSTALL_DIR/hydra" "$REPO_ROOT/target/release/hydra"; do
        [ -x "$c" ] && { echo "$c"; return 0; }
    done
    command -v hydra 2>/dev/null || echo ""
}
find_config() {
    for c in "$SERVER_CONFIG_DIR/hydra.toml" "$CLIENT_CONFIG_DIR/hydra.toml"; do
        [ -f "$c" ] && { echo "$c"; return 0; }
    done
    echo ""
}

do_status() {
    banner
    local hydra cfg; hydra="$(find_hydra)"; cfg="$(find_config)"
    echo -e "\n${BOLD}Binary:${NC}"
    [ -n "$hydra" ] && ok "$hydra ($("$hydra" --version 2>/dev/null | head -1))" || err "hydra not installed"
    echo -e "\n${BOLD}Config:${NC}"
    [ -n "$cfg" ] && ok "$cfg" || err "no hydra.toml found"
    echo -e "\n${BOLD}Toolchain:${NC}"
    command -v rustc >/dev/null 2>&1 && ok "$(rustc --version)" || err "rustc not installed"
    if command -v systemctl >/dev/null 2>&1; then
        echo -e "\n${BOLD}Services:${NC}"
        for u in hydra-server.timer hydra-client.service; do
            if systemctl list-unit-files 2>/dev/null | grep -q "^$u"; then
                ok "$u — $(systemctl is-active "$u" 2>/dev/null || echo inactive)"
            fi
        done
    fi
    if [ -n "$hydra" ] && [ -n "$cfg" ]; then
        echo -e "\n${BOLD}Current epoch serverNames:${NC}"
        "$hydra" server-names -c "$cfg" 2>/dev/null | sed 's/^/  /' || warn "could not derive (client config?)"
    fi
    echo ""
}

do_rotate() {
    local hydra cfg; hydra="$(find_hydra)"; cfg="$(find_config)"
    [ -n "$hydra" ] || die "hydra not installed."
    [ -n "$cfg" ] || die "no hydra.toml found."
    echo -e "${BOLD}Lines:${NC}";  "$hydra" server-names -c "$cfg"
    echo -e "\n${BOLD}JSON:${NC}";  "$hydra" server-names -c "$cfg" --format json
    echo -e "\n${BOLD}Xray:${NC}";  "$hydra" server-names -c "$cfg" --format xray
    echo ""
    warn "Reload Xray with the new serverNames (e.g. systemctl reload xray)."
}

do_bundle() {
    local cfg="$SERVER_CONFIG_DIR/hydra.toml"
    [ -f "$cfg" ] || cfg="$(find_config)"
    [ -n "$cfg" ] && [ -f "$cfg" ] || die "no server hydra.toml found."
    echo -e "${BOLD}Connection bundle (paste into the client):${NC}"
    make_bundle "$cfg"
}

do_uninstall() {
    banner
    info "Uninstalling REALITY-Hydra..."
    need_root
    if command -v systemctl >/dev/null 2>&1; then
        for u in hydra-server.timer hydra-server.service hydra-client.service; do
            systemctl list-unit-files 2>/dev/null | grep -q "^$u" && {
                $SUDO systemctl disable --now "$u" 2>/dev/null || true
                $SUDO rm -f "/etc/systemd/system/$u"
                ok "removed $u"
            }
        done
        $SUDO systemctl daemon-reload 2>/dev/null || true
    fi
    for b in "$SERVER_INSTALL_DIR/hydra" "$CLIENT_INSTALL_DIR/hydra"; do
        [ -f "$b" ] && { $SUDO rm -f "$b"; ok "removed $b"; }
    done
    for c in "$SERVER_CONFIG_DIR/hydra.toml" "$CLIENT_CONFIG_DIR/hydra.toml"; do
        if [ -f "$c" ]; then
            if [ "$NONINTERACTIVE" != 1 ]; then
                read -rp "  Remove config $c? [y/N] " a
                case "$a" in [Yy]*) $SUDO rm -f "$c"; ok "removed $c" ;; *) info "kept $c" ;; esac
            else
                info "kept $c (set ASSUME_YES=1 and remove manually if desired)"
            fi
        fi
    done
    ok "Uninstall complete"
}

# ─── Interactive menu (3x-ui style) ────────────────────────────────
menu() {
    banner
    scan_system
    echo ""
    echo -e "  ${BOLD}1)${NC} Install ${GREEN}server${NC}   (Linux only — generates keys, prints bundle)"
    echo -e "  ${BOLD}2)${NC} Install ${GREEN}client${NC}   (paste the server's bundle)"
    echo -e "  ${BOLD}3)${NC} Status"
    echo -e "  ${BOLD}4)${NC} Rotate serverNames (server)"
    echo -e "  ${BOLD}5)${NC} Show connection bundle (server)"
    echo -e "  ${BOLD}6)${NC} Uninstall"
    echo -e "  ${BOLD}0)${NC} Exit"
    echo ""
    read -rp "  Select [0-6]: " c
    case "$c" in
        1) ROLE="server"; install_server ;;
        2) ROLE="client"; install_client ;;
        3) do_status ;;
        4) do_rotate ;;
        5) do_bundle ;;
        6) do_uninstall ;;
        0|"") exit 0 ;;
        *) err "Invalid choice"; exit 1 ;;
    esac
}

# ─── Usage ─────────────────────────────────────────────────────────
usage() {
    banner
    cat <<EOF

USAGE:  ./setup.sh [COMMAND] [OPTIONS]

COMMANDS:
    (none)        Interactive menu
    server        Install & configure the SERVER (Linux, root)
    client        Install & configure the CLIENT
    status        Show binary, config, services, current epoch
    rotate        Print this epoch's serverNames (lines/JSON/Xray)
    bundle        Print the hydra:// connection bundle (server)
    uninstall     Remove binaries, config, and services

OPTIONS:
    -f, --features F     Cargo features (e.g. full, live-dns) [default: none]
        --port N         REALITY port for the server dest [default: 443]
        --listen ADDR    Client SOCKS5 listen address [default: 127.0.0.1:1080]
        --schedule EXPR  systemd OnCalendar for the server timer [default: hourly]
        --server-addr A  Server IP/domain (non-interactive server install)
        --bundle TOKEN   hydra:// bundle (non-interactive client install)
    -s, --skip-tests     Skip the test step
    -b, --skip-build     Skip the build step
    -y, --yes            Assume yes (install deps without asking)
    -h, --help           Show this help
    -V, --version        Show version

ENVIRONMENT (non-interactive):
    HYDRA_NONINTERACTIVE=1, SERVER_ADDR=…, BUNDLE=hydra://…, ASSUME_YES=1,
    FEATURES=…, PORT=…, LISTEN=…, SCHEDULE=…

FLOW:
    1. On the SERVER:  sudo ./setup.sh server     → copy the printed bundle
    2. On the CLIENT:  ./setup.sh client          → paste the bundle
EOF
}

# ─── Arg parsing ───────────────────────────────────────────────────
CMD=""
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            server|client|status|rotate|bundle|uninstall) CMD="$1"; shift ;;
            -f|--features) FEATURES="${2:?}"; shift 2 ;;
            --features=*)  FEATURES="${1#*=}"; shift ;;
            --port) PORT="${2:?}"; shift 2 ;;
            --port=*) PORT="${1#*=}"; shift ;;
            --listen) LISTEN="${2:?}"; shift 2 ;;
            --listen=*) LISTEN="${1#*=}"; shift ;;
            --schedule) SCHEDULE="${2:?}"; shift 2 ;;
            --schedule=*) SCHEDULE="${1#*=}"; shift ;;
            --server-addr) SERVER_ADDR="${2:?}"; shift 2 ;;
            --server-addr=*) SERVER_ADDR="${1#*=}"; shift ;;
            --bundle) BUNDLE="${2:?}"; shift 2 ;;
            --bundle=*) BUNDLE="${1#*=}"; shift ;;
            -s|--skip-tests) SKIP_TESTS=1; shift ;;
            -b|--skip-build) SKIP_BUILD=1; shift ;;
            -y|--yes) ASSUME_YES=1; shift ;;
            -h|--help) usage; exit 0 ;;
            -V|--version) echo "setup.sh v${VERSION}"; exit 0 ;;
            *) die "Unknown argument: $1 (use --help)" ;;
        esac
    done
}

main() {
    parse_args "$@"
    case "$CMD" in
        server)    banner; install_server ;;
        client)    banner; install_client ;;
        status)    do_status ;;
        rotate)    do_rotate ;;
        bundle)    do_bundle ;;
        uninstall) do_uninstall ;;
        "")        if [ "$NONINTERACTIVE" = 1 ]; then usage; else menu; fi ;;
    esac
}

main "$@"
