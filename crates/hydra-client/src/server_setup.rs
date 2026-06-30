//! Server-side setup guide for Phase 5 integration.
//!
//! Phase 5 (REALITY.md §10) configures a **stock Xray REALITY server fronted
//! by a CDN**. The server needs no custom code — only the correct configuration
//! derived by `hydra-cli` each epoch.
//!
//! ## Prerequisites
//!
//! 1. **A CDN fronting your server** — Cloudflare, Fastly, etc. Your server's
//!    public IP must be a CDN edge IP so that every pool SNI's real DNS answer
//!    resolves into the same IP range (REALITY.md §4 Traps 2 & 3).
//!
//! 2. **Xray installed** — stock Xray-core with REALITY support.
//!
//! 3. **A pool of real domains on that CDN** — all entries must be genuine
//!    domains hosted on the same CDN. The health-checker validates this.
//!
//! ## Setup steps
//!
//! ### 1. Generate REALITY keys
//!
//! ```bash
//! xray x25519
//! # Private key: <privateKey>  (keep secret, put in server config)
//! # Public key:  <publicKey>   (distribute to clients as `pbk`)
//! ```
//!
//! ### 2. Configure the server (stock Xray)
//!
//! ```jsonc
//! {
//!   "inbounds": [{
//!     "protocol": "vless",
//!     "port": 443,
//!     "settings": {
//!       "clients": [{ "id": "<uuid>", "flow": "xtls-rprx-vision" }],
//!       "decryption": "none"
//!     },
//!     "streamSettings": {
//!       "network": "tcp",
//!       "security": "reality",
//!       "realitySettings": {
//!         "dest": "<cdn-edge-domain>:443",
//!         "serverNames": ["<derived by hydra-cli each epoch>"],
//!         "privateKey": "<from xray x25519>",
//!         "shortIds": ["<hex>"],
//!         "maxTimeDiff": 60000
//!       }
//!     }
//!   }],
//!   "outbounds": [{ "protocol": "freedom" }]
//! }
//! ```
//!
//! ### 3. Derive `serverNames` each epoch
//!
//! ```bash
//! # Using the hydra CLI (Phase 6):
//! cargo run -p hydra-cli -- -c hydra.toml --format json > server-names.json
//!
//! # Or generate a paste-ready Xray inbound:
//! cargo run -p hydra-cli -- -c hydra.toml --format xray > reality-inbound.json
//! ```
//!
//! ### 4. Reload Xray
//!
//! ```bash
//! # Send SIGHUP or use the Xray API to reload config.
//! xray api adi --server 127.0.0.1:10085
//! ```
//!
//! ### 5. Run the health-checker (optional sidecar)
//!
//! ```bash
//! # Validate that every pool SNI passes the 4-axis check.
//! # (Requires the `live-dns` and `live-tls` features.)
//! cargo test -p health-checker --features live-tls
//! ```
//!
//! ## Client config (`hydra.toml`)
//!
//! ```toml
//! master_secret = "base64:..."   # 32B, shared with the server
//! server_salt   = "base64:..."   # 16B, per-deployment
//! pool_format   = "hydra-pool-v1"
//! epoch_len     = "6h"
//! active_k      = 12
//! dest          = "cdn-edge.example:443"
//! coherence_cidrs = ["104.16.0.0/13"]
//!
//! [[pool]]
//! sni = "real-domain-on-cdn.example"
//! weight = 8.0
//! # ... more entries
//! ```
//!
//! ## Verification checklist
//!
//! After setup, verify:
//!
//! 1. **Authorized rotation works** — the Rust client can connect using any
//!    pool SNI and authenticate successfully.
//! 2. **Probe fallback works** — an unauthenticated connection to any pool SNI
//!    via the CDN edge returns the genuine site's certificate.
//! 3. **Coherence** — every pool SNI's real DNS resolves into `coherence_cidrs`.
//! 4. **Health check** — every pool SNI passes TLS 1.3 + h2 + SAN match.
//!
//! See REALITY.md §13 for the full validation checklist and success metrics.
