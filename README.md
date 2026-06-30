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

```bash
# The SNIs to accept right now (±1 epoch window), one per line:
cargo run -p hydra-cli -- --config crates/pool-engine/fixtures/hydra.toml

# The literal serverNames JSON array:
cargo run -p hydra-cli -- -c crates/pool-engine/fixtures/hydra.toml --format json

# A paste-ready stock Xray REALITY inbound (serverNames + dest filled in):
cargo run -p hydra-cli -- -c crates/pool-engine/fixtures/hydra.toml --format xray

# Pin an epoch or evaluate a specific instant (testing / diffing):
cargo run -p hydra-cli -- -c crates/pool-engine/fixtures/hydra.toml --epoch 12345
cargo run -p hydra-cli -- -c crates/pool-engine/fixtures/hydra.toml --at 1735689600 --single
```

`--single` emits the exact single-epoch subset; the default is the ±1 epoch
acceptance window a server should publish so a clock-skewed client still matches.

### Running the client (Phase 5)

```bash
# Start a SOCKS5 proxy backed by the Hydra pipeline (offline/mock mode):
cargo run -p hydra-client -- -c crates/pool-engine/fixtures/hydra.toml --listen 127.0.0.1:1080

# With real DNS and BoringSSL impersonation:
cargo run -p hydra-client --features full -- -c /etc/hydra/hydra.toml --listen 127.0.0.1:1080
```

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
