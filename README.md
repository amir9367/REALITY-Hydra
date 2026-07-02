# REALITY-Hydra

A proof-of-concept, in Rust, of a **rotating SNI-pool transport** for
[Xray REALITY](https://github.com/XTLS/REALITY). Instead of presenting one fixed
SNI, a client rotates through a *pool* of SNIs — per connection and over time —
to deny DPI a static `(IP, SNI)` signature. Both sides derive the live pool from
a shared secret and the current time epoch, with **no coordination channel**.

The full design, threat model, and honest non-goals live in
[`REALITY.md`](REALITY.md).

> ⚠️ **Censorship-circumvention research.** Deploy only against your own
> infrastructure, in lawful and authorized contexts. Rotating the SNI does **not**
> hide your IP (that's fronting/ECH) and does **not** defeat TLS-in-TLS flow
> analysis (that's `xtls-rprx-vision`). See [`REALITY.md` §2/§6](REALITY.md) for
> what each layer does and does not buy. Respect upstream licenses on any
> REALITY/Xray fork.

## The idea in three lines

```text
epoch  = floor(unix_time / EPOCH_LEN)
seed   = HMAC-SHA256(master_secret, "hydra-pool-v1" || server_salt || LE64(epoch))
active = weighted_reservoir(MasterList, ChaCha20(seed), k)   // A-Res, unbiased
```

Because REALITY's auth is SNI-independent and `serverNames` is already a list,
the server negotiates nothing: it just recomputes the SNIs it accepts as the
clock advances. The client draws from the same epoch pool and rotates per
connection. The one mandatory requirement is coherence — every pool SNI must be a
real domain on the same CDN your server is fronted by (see the three traps in
[`REALITY.md` §4](REALITY.md)).

## Installation

REALITY-Hydra ships two installers that build from source and configure both
sides. The intended order is **server first, then client** — the server install
generates the shared secret, salt, and REALITY keys and prints a one-paste
`hydra://` connection bundle you feed to each client.

| Platform | Roles | Installer |
|---|---|---|
| **Linux** | server **and** client | `./setup.sh` |
| **Windows 10 / 11** | client only | `.\setup.ps1` |

> The **server is Linux-only** (it runs a stock Xray REALITY inbound behind a
> CDN; Hydra just regenerates its `serverNames` each epoch). Windows and Linux
> can both run the **client**. macOS can build and run the client via `setup.sh`
> too, minus the systemd integration.

Both installers auto-install a Rust toolchain (rustup **stable**, ≥ 1.88) if one
isn't present. The default build needs **no** TLS toolchain; the `full` feature
(BoringSSL Chrome impersonation + real DNS) additionally needs `cmake`, which the
installers offer to pull in.

### 1. Server (Linux)

```bash
git clone https://github.com/amir9367/REALITY-Hydra && cd reality-hydra
sudo ./setup.sh server
```

`setup.sh` runs a 3x-ui-style flow: it detects your distro (Debian/Ubuntu,
RHEL/Fedora/Rocky/Alma, Arch, openSUSE, Alpine) and architecture, installs the
matching build dependencies with the native package manager, builds the `hydra`
binary, writes `/etc/hydra/hydra.toml` (fresh secret + salt + X25519 keys),
installs a systemd service + epoch timer, and then prints:

```text
  Address (dest):   203.0.113.7:443
  master_secret:    base64:…
  server_salt:      base64:…
  public_key (pbk): base64:…
  short_id:         …
  One-paste connection bundle:
  hydra://<base64>
```

Point your Xray REALITY inbound's `serverNames` at the current epoch:

```bash
hydra server-names -c /etc/hydra/hydra.toml --format xray   # paste-ready inbound
./setup.sh rotate                                           # reprint all formats
./setup.sh bundle                                           # reprint the bundle
```

The bundle is `hydra://` + base64 of a **client** `hydra.toml` (the same pool and
keys, with the server private key stripped). It's the reliable way to carry the
exact SNI pool to clients.

### 2. Client (Linux)

```bash
./setup.sh client
# choose “Paste the hydra:// bundle” (recommended) and paste what the server printed
```

This builds `hydra`, installs it to `~/.local/bin`, writes
`~/.config/hydra/hydra.toml` from the bundle, optionally installs a systemd
service, and starts a SOCKS5 proxy:

```bash
hydra serve -c ~/.config/hydra/hydra.toml --listen 127.0.0.1:1080
```

Point your app's SOCKS5 proxy at `127.0.0.1:1080`.

### 2′. Client (Windows 10 / 11)

In PowerShell (from the repo root):

```powershell
.\setup.ps1
# 1) Install client  →  paste the hydra:// bundle from the server
```

`setup.ps1` refuses anything older than Windows 10, installs Rust (via `winget`
or `rustup-init`), builds `hydra.exe`, writes `%USERPROFILE%\.config\hydra\hydra.toml`,
optionally registers a logon Scheduled Task, and prints the run command:

```powershell
hydra.exe serve -c $env:USERPROFILE\.config\hydra\hydra.toml --listen 127.0.0.1:1080
```

If you don't have the bundle, choose **manual entry** and paste the address,
`master_secret`, `server_salt`, `public_key`, and `short_id` from the server
summary — but note manual mode uses the **default** SNI pool, so it only works if
the server kept the default pool. When in doubt, use the bundle.

### Manage / remove

```bash
# Linux
./setup.sh status          # binary, config, services, current epoch
./setup.sh uninstall

# with the full feature set (BoringSSL + real DNS; needs cmake)
./setup.sh client --features full
```

```powershell
# Windows
.\setup.ps1 -Command status
.\setup.ps1 -Command uninstall
```

Non-interactive installs are supported for automation — e.g.
`HYDRA_NONINTERACTIVE=1 SERVER_ADDR=example.com ./setup.sh server` and
`BUNDLE='hydra://…' ./setup.sh client` (or `.\setup.ps1 -Command client -Bundle 'hydra://…'`).

## Status

Built in the phases laid out in REALITY.md §10. All seven phases are
implemented: the pure-logic core, the network-touching crates (feature-gated),
the BoringSSL TLS impersonation client, the full integration pipeline, and the
hardening suite.

| Phase | Component | Crate | Status |
|---|---|---|---|
| 1 | **PoolEngine** — keyed, time-evolving SNI pool (pure logic) | [`crates/pool-engine`](crates/pool-engine) | ✅ done |
| 2 | **HealthChecker** — async coherence / cert+SAN / ALPN / latency checks | [`crates/health-checker`](crates/health-checker) | ✅ done |
| 3 | **DnsWarmer** — real resolve-on-first-use, TTL-aware cache | [`crates/dns-warmer`](crates/dns-warmer) | ✅ done |
| 4 | **RealityTLS** — uTLS-equivalent ClientHello + REALITY auth | [`crates/reality-tls`](crates/reality-tls) | ✅ done |
| 5 | **Integration** — SOCKS5 inbound → PoolEngine → DnsWarmer → RealityTLS → CDN edge | [`crates/hydra-client`](crates/hydra-client) | ✅ done |
| 6 | **hydra-cli** — server-side epoch automation (`serverNames`) | [`crates/hydra-cli`](crates/hydra-cli) | ✅ done |
| 7 | **Hardening** — checklist, distribution validation, metrics | [`crates/hardening`](crates/hardening) | ✅ done |

## Architecture

```text
                 ┌──────────────── client (Phases 1,3,4) ────────────────┐
 app ─SOCKS5──▶  │  PoolEngine → Selector → DnsWarmer → RealityTLS        │──▶ CDN edge ──▶ server
                 └────────────────────────────────────────────────────────┘
                 ┌──────────────── server (Phases 1,2,6) ────────────────┐
                 │  stock Xray REALITY inbound, behind the CDN            │◀──┘
                 │   serverNames = active epoch pool   (← hydra-cli)      │
                 │   one dest = CDN edge → probe fallback to real sites   │
                 │   HealthChecker sidecar: coherence + cert + ALPN + RTT │
                 └────────────────────────────────────────────────────────┘
```

The crates in this workspace are the **new code**. `RealityTLS` (Phase 4)
provides the Chrome-fingerprinted TLS with embedded X25519 auth; `hydra-client`
(Phase 5) wires everything into a SOCKS5 proxy; the server inbound is **stock
Xray, fronted by a CDN**.

## Crates

| Crate | What it does | Network? |
|---|---|---|
| [`pool-engine`](crates/pool-engine) | The novel core: `MasterList` → keyed epoch subset → sticky weighted `Selector`; loads `hydra.toml` (secret zeroized). | pure logic |
| [`dns-warmer`](crates/dns-warmer) | Guarantees a *real* DNS lookup happened before an SNI is used (defeats Trap 1). Mockable `Resolver` seam; real `hickory` behind `live-dns`. | feature-gated |
| [`health-checker`](crates/health-checker) | Prunes the pool: DNS lands in the CDN range, leaf cert SAN matches, ALPN `h2`, latency sane (defeats Traps 2 & 3, P1/P8). Mockable seams; real TLS behind `live-tls`. | feature-gated |
| [`reality-tls`](crates/reality-tls) | Chrome-fingerprinted TLS client via BoringSSL + REALITY X25519 auth in session ID. Auth/crypto is pure logic; connector is behind `boring-impersonate`. | feature-gated |
| [`hydra-client`](crates/hydra-client) | Full integration: SOCKS5 inbound → PoolEngine → Selector → DnsWarmer → RealityTLS → CDN edge. Binary + library. | feature-gated |
| [`hydra-cli`](crates/hydra-cli) | The `hydra` binary: derive this epoch's accepted `serverNames` and emit them as lines, JSON, or a paste-ready Xray inbound. | none |
| [`hardening`](crates/hardening) | Checklist (8 invariants), χ² distribution validation, metrics (12 counters with snapshot/delta). | pure logic |

Everything builds and the entire test suite runs **with no network and no TLS
provider** — the live paths are opt-in Cargo features (`live-dns`, `live-tls`,
`boring-impersonate`).

## Quickstart

```bash
# Build everything and run the full suite (offline; ~70+ tests).
cargo test --workspace

# Lints and formatting must be clean.
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check

# Microbenchmarks for the keyed sampler / selector.
cargo bench -p pool-engine --bench pool
```

### Using the `hydra` CLI (Phase 6)

Regenerate a server's accepted `serverNames` for the current epoch and reload
Xray with the output. The committed [fixture](crates/pool-engine/fixtures/hydra.toml)
uses clearly-marked **test** keys.

The `hydra` binary is one tool for the whole lifecycle — `keygen`, `init`,
`server-names` (server), `serve` (client), and `service`. From an installed
binary, drop the `cargo run -p hydra-cli --`; the examples below run it in-tree
against the committed fixture.

```bash
# The SNIs to accept right now (±1 epoch window), one per line:
cargo run -p hydra-cli -- server-names --config crates/pool-engine/fixtures/hydra.toml

# The literal serverNames JSON array:
cargo run -p hydra-cli -- server-names -c crates/pool-engine/fixtures/hydra.toml --format json

# A paste-ready stock Xray REALITY inbound (serverNames + dest filled in):
cargo run -p hydra-cli -- server-names -c crates/pool-engine/fixtures/hydra.toml --format xray

# Pin an epoch or evaluate a specific instant (testing / diffing):
cargo run -p hydra-cli -- server-names -c crates/pool-engine/fixtures/hydra.toml --epoch 12345
cargo run -p hydra-cli -- server-names -c crates/pool-engine/fixtures/hydra.toml --at 1735689600 --single

# Scaffold a fresh config (unique secret/salt/keys) — what `setup.sh` calls:
cargo run -p hydra-cli -- init --output hydra.toml --dest cdn-edge.example:443
```

`--single` emits the exact single-epoch subset; the default is the ±1 epoch
acceptance window a server should publish so a clock-skewed client still matches.

### Running the client (Phase 5)

```bash
# Start a SOCKS5 proxy backed by the Hydra pipeline (offline/mock mode):
cargo run -p hydra-cli -- serve -c crates/pool-engine/fixtures/hydra.toml --listen 127.0.0.1:1080

# The standalone client binary is equivalent:
cargo run -p hydra-client -- -c crates/pool-engine/fixtures/hydra.toml --listen 127.0.0.1:1080

# With real DNS and BoringSSL impersonation:
cargo run -p hydra-cli --features full -- serve -c ~/.config/hydra/hydra.toml --listen 127.0.0.1:1080
```

An installed client (via `setup.sh`/`setup.ps1`) is just `hydra serve -c <config>`.

### Live network paths (opt-in)

```bash
# Real DNS resolution (hickory):
cargo test -p dns-warmer --features live-dns

# Real TLS validation probe (rustls + ring):
cargo test -p health-checker --features live-tls

# Chrome-fingerprinted TLS connector (requires BoringSSL toolchain):
cargo test -p reality-tls --features boring-impersonate
```

## Configuration

See the [`hydra.toml` sketch](crates/pool-engine/fixtures/hydra.toml) and
[`REALITY.md` §11](REALITY.md). The `master_secret` (32B) and `server_salt` (16B)
are base64; the secret is held in a zeroizing `SecretBox` and never logged.

> **Never commit a real `master_secret`/`server_salt`.** Leaking the secret
> exposes every past and future epoch pool (there is no forward secrecy by
> design — see [`REALITY.md` §5.4](REALITY.md)). Treat a leak as "rotate the
> secret." The checked-in values are random test data; `.gitignore` excludes
> `hydra.local.toml` and `.env` for your own.

## Security & scope (read before deploying)

Hydra targets a **passive SNI reader** and an **active prober** (tiers A/B). It is
orthogonal or useless against flow/ML classifiers (tier C → use Vision) and IP/ASN
blocking (tier D → use CDN fronting / IP pools / ECH). It makes the *plaintext SNI*
boring and ever-changing — nothing more. The honest non-goals are spelled out in
[`REALITY.md` §2/§3/§6](REALITY.md); do not deploy without reading them.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in the work by you shall be dual-licensed
as above, without any additional terms or conditions.
