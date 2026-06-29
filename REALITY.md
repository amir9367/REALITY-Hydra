# REALITY-Hydra — A Rotating SNI-Pool Transport for Xray REALITY

> **Status:** design draft
> **Goal:** extend Xray's REALITY so that instead of presenting one fixed SNI, a client rotates
> through a *pool* of SNIs (per-connection and over time) to deny DPI a static
> `(IP, SNI)` signature — while staying honest about what this does and does not protect.
> **Target stack:** Rust (proof-of-concept client + pool engine) against a stock Xray REALITY server.

---

## 0. TL;DR

- REALITY already supports a **list** of `serverNames`, and its authentication is **independent of the
  SNI** (auth lives in the X25519 proof embedded in the ClientHello session ID). So a client *can*
  rotate SNIs per connection and a correctly-configured server will already accept it.
- The "new protocol" is therefore mostly **client-side rotation policy** + a **coherent fallback** on the
  server + one genuinely novel piece: a **keyed, time-evolving pool** that both sides derive from a
  shared secret with zero coordination.
- **Rotating the SNI does NOT stop IP blocking.** SNI lives at L7; IP blocking is L3. Keep these layers
  separate. Hydra defeats *SNI-signature* detection and *long-term SNI profiling*; it does **not** make
  your IP unblockable.
- Done naively, rotation gets you blocked **faster** because of **three traps**: unresolved-hostname
  detection, ASN/co-hosting incoherence, and **resolved-IP vs connected-IP mismatch** (§4). The mitigation
  for all three converges on one hard requirement: **the server must live behind a real CDN, and the pool
  must be drawn from domains genuinely hosted on that CDN.** This is mandatory, not optional.
- **Hydra is one layer only.** It does nothing against **TLS-in-TLS** flow detection (use REALITY's
  `xtls-rprx-vision`) and nothing against IP blocking (use CDN fronting / IP pools / ECH). See the
  adversary model (§2) for which threats each layer owns.

---

## 1. Background — how REALITY actually works

REALITY is a TLS-camouflage transport for Xray-core. Instead of presenting its own (detectable)
certificate like VLESS+TLS/Trojan, it **borrows the TLS identity of a real, high-reputation website**.

Key mechanisms:

1. **uTLS fingerprint mimicry** — the client emits a ClientHello that byte-matches a real browser
   (Chrome/Firefox/Safari), so JA3/JA4 looks normal.
2. **Embedded authentication** — an X25519 proof of knowledge of the shared secret (plus a `shortId`
   and a **timestamp**) is encrypted into the TLS **session ID** field. Only the real server (holding
   `privateKey`) can decrypt and verify it. **This auth is not tied to the SNI.**
3. **Active-probe fallback** — when a connection arrives that is *not* an authenticated REALITY client
   (e.g. a censor's prober), the server transparently relays it to a genuine destination (`dest`), so
   the prober sees the real website with a valid certificate and cannot distinguish it from a real visit.
4. **`xtls-rprx-vision` (Vision) flow** — REALITY is normally paired with the Vision flow, which exists
   specifically to **reduce TLS-in-TLS detectability** (it stops the inner TLS from being re-split into
   tell-tale record bursts and adds padding). Hydra concerns the SNI; **Vision concerns the flow shape** —
   you want both. See §6 (TLS-in-TLS) and the adversary model (§2).

Relevant config fields:

| Field | Side | Meaning |
|---|---|---|
| `dest` / `target` | server | The **single** real upstream the server relays unauthenticated/probe traffic to. Must support TLS 1.3 + h2. (There is **one** `dest`, not one-per-SNI — see §5.3.) |
| `serverNames` | server | **Array** of SNIs the server accepts from authorized clients. An SNI *not* in this list is silently forwarded to `dest`. No `*` wildcards. |
| `privateKey` | server | X25519 private key (`xray x25519`). |
| `publicKey` / `pbk` | client | Matching public key (or password that packs it). |
| `shortIds` / `sid` | both | Allowed short ID(s) (hex). Can tag/segment users; `""` is allowed. |
| `serverName` / `sni` | client | The single SNI the client currently uses — **this is what we are turning into a pool.** |
| `fingerprint` / `fp` | client | uTLS browser fingerprint to emulate (e.g. `chrome`). |
| `maxTimeDiff` | server | REALITY's **existing** anti-replay window: max allowed difference between the client's embedded timestamp and server time. Distinct from Hydra's epoch clock (§5.4/§7-P6). |
| `spiderX` | client | Path the client "crawls" on `dest` to look like a real visitor. |
| `flow` | both | Set to `xtls-rprx-vision` for the Vision flow described above. |
| `mldsa65` | both | (Newer REALITY) optional **post-quantum** ML-DSA-65 auth key. Forward-looking; mention but not required for the PoC. |

**The load-bearing fact for this project:** because auth is SNI-independent and `serverNames` is already
a list, the server side needs almost no change — the work is in *how the client chooses its SNI* and in
making sure every SNI we rotate to is served by a coherent, live fallback.

---

## 2. Adversary model

Every claim below is scoped to a specific adversary tier. Hydra targets **A and B**; it is orthogonal or
useless against **C and D** (which need other layers).

| Tier | Capability | What defeats it |
|---|---|---|
| **A — Passive SNI reader** | Reads plaintext SNI; builds `(IP, SNI)` blocklists; long-term profiling. | **Hydra** (rotation + keyed epoch pool). |
| **B — Active prober** | Connects to your IP with your SNI to see if it's a real site. | REALITY's fallback to `dest` (Hydra must keep every pool SNI's fallback valid). |
| **C — Flow / ML classifier** | TLS-in-TLS detection, packet-length/timing/entropy analysis, handshake-burst patterns. | **`xtls-rprx-vision`** + traffic shaping. **Hydra does nothing here.** |
| **D — Resolved-IP correlator / nation-state** | Correlates the client's DNS answers with the IP it then connects to; can selectively TLS-MITM or null-route IPs/ASNs. | **CDN co-hosting** (Trap 3) + IP survivability layer (fronting / pools / ECH). **Hydra alone does not.** |

**Non-goals (explicit):** Hydra is *not* a transport-shape obfuscator (tier C), *not* an IP-survivability
mechanism (tier D's blocking), and *not* an SNI-hiding mechanism (that's ECH). It makes the *plaintext SNI*
boring and ever-changing — nothing more.

---

## 3. The problem we are solving (and the one we are *not*)

### 3.1 What we are solving

A censor that can read the plaintext SNI (tier A) can build cheap rules:

- `IP=X AND SNI=www.microsoft.com → block` (static signature), or
- "this IP keeps showing SNI=S for weeks → flag and block S on X" (long-term profiling).

A fixed-SNI REALITY deployment hands the censor exactly this stable signature. **Hydra removes the
static signature** by rotating the SNI per connection and drifting the *set* of SNIs over time.

### 3.2 What we are NOT solving (read this twice)

> **SNI rotation does not prevent IP blocking.**

- SNI is L7 (inside the TLS handshake). IP blocking is L3. If the censor null-routes your server IP,
  every SNI in the world is irrelevant.
- *"Single-ASN concentration creates a structural fingerprint that proxy rotation cannot fix."*
- IP survivability is a **separate, orthogonal layer**: CDN fronting, large shared-IP ranges, IP pools,
  or true ECH. We treat it as out of scope for the transport itself but call out where it must plug in.

**Mental model:** Hydra makes your SNI *boring and ever-changing*. It does not hide the SNI (that's ECH)
and it does not hide the IP (that's fronting/pools).

---

## 4. The three traps that make naive rotation *worse than* a single SNI

These are the heart of the design. Get them wrong and rotation actively hurts you. **All three resolve to
the same fix: be a real tenant behind a CDN and draw the pool from that CDN's domains.**

### Trap 1 — Unresolved hostname

DPI engines (e.g. nDPI) raise a flag such as `NDPI_UNRESOLVED_HOSTNAME` when a host sends a TLS SNI it
**never DNS-resolved**, and feed that straight into a dynamic blocklist. A normal browser always resolves
a domain *before* connecting to it.

- Naive rotation sends, say, 50 SNIs the client never looked up → 50 anomalies instead of 1.
- **Mitigation:** the client must perform (or convincingly pre-warm) a **real DNS lookup for every SNI it
  is about to use.** Resolve-on-first-use + cache, or pre-resolve the whole active pool on startup and
  refresh on the same TTLs the real records advertise.

### Trap 2 — ASN / co-hosting incoherence

A censor can ask: *"does this SNI's real domain actually resolve into the ASN/IP range of the server I'm
talking to?"* If your generic VPS presents `SNI=www.apple.com`, the answer is no — Apple isn't hosted on
your Hetzner box. Rotating among 50 big brands means **50 impossible claims on one strange IP**, which is
*more* suspicious, not less. DPI tools explicitly report SNIs in order to detect name-based services on
the same server IP.

- **Mitigation (the core design principle):**

  > Rotate only among SNIs that are **genuinely co-hostable on your IP** — ideally domains whose *real*
  > DNS resolves into the same CDN/ASN range your server sits in or behind. Then "many SNIs → one IP" is
  > literally what a shared CDN edge looks like, and the client resolves them for real because they are
  > real.

### Trap 3 — Resolved-IP vs connected-IP mismatch (the sharp one)

Even if you satisfy Trap 1 by *really* resolving `SNI=X`, a real browser then connects to **X's real IP**.
Hydra connects to **your server IP**. A tier-D adversary that correlates per-client *"resolved X → IP_real,
then opened TLS(SNI=X) to IP_server ≠ IP_real"* catches you regardless of how cleverly you rotate. This is
strictly stronger than Trap 2: it doesn't need a global hosting database, just the client's own DNS answers
versus its own connections.

- **Mitigation = the mandatory requirement:** be a **real tenant behind a CDN** so your server is reachable
  via one of X's *genuine* edge IPs. When the pool SNIs are real domains on, say, Cloudflare, and your
  server is fronted by Cloudflare, then `X` resolves to a Cloudflare IP **and** your server answers on a
  Cloudflare IP → resolved-IP and connected-IP coincide (or at least share the CDN's anycast range).
- This is why **CDN fronting is not the "IP survivability" nice-to-have from §3.2 — it is also the only
  way to make the SNI camouflage coherent at all.** Without it, Hydra is theatre.

> **One CDN edge, many SNIs = normal. One VPS, many SNIs = a beacon.** Traps 1–3 all say the same thing.

---

## 5. The main idea — REALITY-Hydra

### 5.1 The pool model

```
PoolEntry = {
  sni:    String,   // a real domain genuinely hosted on the CDN your server is fronted by
  weight: f64,      // selection probability ∝ real-world popularity (e.g. Tranco rank)
}

MasterList = [PoolEntry; N]    // large, curated, all coherence-checked (DNS → CDN range, valid cert)
dest:        String            // ONE upstream: a CDN edge that serves a valid cert for EVERY pool SNI
```

> **Correction vs earlier drafts:** there is **no per-SNI `dest`**. Stock REALITY relays all probe traffic
> to a single `dest`. Coherence is achieved by making that one `dest` a **CDN edge that does per-SNI cert
> selection itself** — REALITY forwards the prober's original ClientHello bytes, so a real CDN edge returns
> the correct genuine certificate for whatever pool SNI the prober used. Per-SNI routing is therefore
> unnecessary *and* unsupported by stock Xray.

### 5.2 Client behavior (per outbound connection)

1. **Select** an entry from the *active* pool by **weighted random** (weighted by realism, not uniform —
   a real CDN IP sees a popularity-shaped SNI distribution, not a flat one).
2. **Guarantee a real DNS resolution** for the chosen SNI happened (resolve-on-first-use + cache) →
   defeats Trap 1; the CDN co-hosting makes that resolution land on the connected IP → defeats Trap 3.
3. **Sticky-cache** the chosen SNI per *real destination* for a short TTL, mimicking browser connection
   reuse — a browser does not flip SNI mid-session for the same site.
4. Perform the normal REALITY handshake with that SNI + fixed `pbk`/`sid` + uTLS Chrome fingerprint +
   `flow=xtls-rprx-vision`.

### 5.3 Server behavior

1. **Auth unchanged** — SNI-independent, so authorized clients pass regardless of which pool SNI they used.
2. **Single `dest` = CDN edge.** On any unauthenticated/probe connection, REALITY forwards to that one
   `dest`; because it is a CDN edge fronting all pool domains, the prober receives the genuine cert and
   site for the SNI it sent. **Every pool SNI must be a real domain on that CDN** or its probe fallback
   produces a cert mismatch → instant tell.
3. Run a **health-checker** (see §7) that evicts any entry whose DNS no longer resolves into the coherence
   range, whose cert is invalid/SAN-mismatched, or whose latency is anomalous.

### 5.4 The novel piece — a keyed, time-evolving pool (zero-coordination sync)

Instead of a fixed `serverNames` list, both sides derive the **active subset** deterministically from a
shared secret and the current time epoch.

**Precise spec (don't hand-wave the sampler):**

```
Inputs:   master_secret (32B, separate from REALITY keys), server_salt (16B, per-deployment),
          MasterList (N entries), k (active size), EPOCH_LEN (e.g. 6h)
epoch  =  floor(unix_time / EPOCH_LEN)
seed   =  HMAC-SHA256(master_secret, "hydra-pool-v1" || server_salt || LE64(epoch))   // domain-separated
prng   =  ChaCha20 keyed by seed                                                       // deterministic CSPRNG
active =  weighted_reservoir(MasterList, prng, k)   // A-Res: unbiased weighted sampling without replacement
```

- Client and server share only `master_secret` + `server_salt`. Both compute the **same active subset every
  epoch with no extra channel.**
- **`server_salt`** ensures two deployments with the same MasterList derive *different* pools → no
  cross-deployment correlation, no shared signature across users.
- **Domain-separation tag** (`"hydra-pool-v1"`) lets the key be reused for nothing else and lets the format
  be versioned.
- **Sampler must be unbiased.** Use weighted reservoir sampling (A-Res) or seeded Fisher–Yates over a
  weight-expanded list; naive `seed % N` is biased and itself fingerprintable across epochs.
- **No forward secrecy (footgun — state it):** leaking `master_secret` exposes *every* past and future
  epoch pool. So (a) keep the pool key **separate** from the REALITY `privateKey`, and (b) make it
  **rotatable** out of band; treat a leak as "rotate the secret," not "rotate every cert."
- **Clock-skew handling:** the server accepts entries from `epoch`, `epoch-1`, and `epoch+1` (a ±1 window)
  so a client with a slightly wrong clock near a boundary still matches. This is *separate* from REALITY's
  own `maxTimeDiff` anti-replay window (§1) — there are two clocks; document both.

This is the part worth writing up as the contribution: *a censorship-resistant transport whose camouflage
identity set is a keyed, salted function of time, requiring no rendezvous.*

---

## 6. Threat model — what Hydra does and does not buy

| Threat | Tier | Helped? | Notes |
|---|---|---|---|
| Static `(IP, SNI)` blocklist rule | A | ✅ | broken by per-connection rotation |
| Long-term SNI profiling of your IP | A | ✅ | broken by the keyed epoch pool |
| Looking like a normal shared/CDN IP | A/D | ✅ | **only if** behind a CDN with a coherent pool (§4) |
| `NDPI_UNRESOLVED_HOSTNAME` flag | A | ✅ | **only if** the client really resolves each SNI (Trap 1) |
| Resolved-IP vs connected-IP correlation | D | ➖ | **only** solved by CDN co-hosting (Trap 3); not by rotation itself |
| Active probing | B | ➖ | same as stock REALITY — **only if** the single CDN `dest` serves every pool SNI |
| **TLS-in-TLS nested-handshake detection** | C | ❌ | **orthogonal** — mitigate with `xtls-rprx-vision`, not Hydra |
| **Pure IP / ASN blocking** | D | ❌ | **not addressed** — needs CDN fronting / IP pool / ECH |
| TLS JA3/JA4 fingerprint | C | ❌ | orthogonal — keep uTLS consistent across all SNIs |
| Flow/timing/volume analysis | C | ❌ | orthogonal — Hydra changes *which name*, not traffic shape |

The honest endgame for "can't block my IP" is **ECH** (encrypts the SNI entirely) or living behind a CDN
whose IPs are too valuable to block. Hydra is the pragmatic middle path for when you can't get real ECH:
it doesn't hide the SNI, it makes the SNI boring and ever-changing.

---

## 7. Problems we will bump into (detailed)

### P1. Probe fallback must be valid for every pool SNI (single-`dest` reality)
Stock REALITY relays probes to **one** `dest`. If a pool SNI isn't actually served by that `dest`, a prober
gets a cert mismatch → instant tell. **Mitigation:** make `dest` a CDN edge and restrict the pool to real
domains on that CDN; the **health-checker** verifies, per entry: (a) DNS resolves into the coherence range,
(b) a TLS 1.3 handshake to `dest` with that SNI returns a valid leaf cert whose SAN matches the SNI,
(c) ALPN advertises `h2`, (d) latency within a sane band. Auto-evict failures from the active pool.

### P2. Certificate / co-hosting realism
With rotation, one IP presents real certs for many different domains. Normal for a CDN edge, **abnormal
for a dedicated VPS.** Reinforces the §4 principle: actually be behind a CDN.

### P3. Rotation pattern as a meta-fingerprint
If selection is round-robin or time-periodic, the *pattern itself* is a signal.
**Mitigation:** weighted-random per connection (not per timer); weights shaped by real popularity;
sticky-per-destination so reuse looks browser-like.

### P4. SNI popularity distribution realism
Uniform-random across 50 brands is itself unnatural. Real CDN edges see a long-tail/Zipf distribution.
**Mitigation:** derive weights from a real ranking (Tranco) and clamp the tail.

### P5. DNS as a side channel (Trap 1 generalized)
Even if you resolve each SNI, *when* and *how* you resolve matters — a burst of lookups for the whole pool
at startup is itself anomalous. **Mitigation:** lazy resolve-on-first-use, honor real record TTLs, and
spread refreshes; or use the same resolver path (DoH) the camouflaged browser would.

### P6. Two clocks: epoch skew *and* REALITY `maxTimeDiff`
Hydra's keyed epoch pool needs client/server time agreement (±1 epoch window, generous `EPOCH_LEN`,
optional NTP). **Separately**, REALITY's own `maxTimeDiff` anti-replay rejects handshakes whose embedded
timestamp drifts too far. Document and test both; they fail differently.

### P7. uTLS-equivalent fingerprint in Rust is hard
`rustls` does **not** produce a Chrome-identical ClientHello (cipher order, extensions, GREASE, key-share,
ALPS). A JA3/JA4 mismatch undoes all the SNI work. **Mitigation:** use a BoringSSL-impersonation path —
`rquest` / `reqwest-impersonate` / `wreq`, or `boring` directly — rather than vanilla `rustls`; validate
JA3/JA4 against a real Chrome capture before trusting the transport.

### P8. ALPN / h2 / TLS 1.3 coherence
REALITY only works against TLS 1.3 + h2 targets. Mixed pool entries that fall back to HTTP/1.1 or TLS 1.2
break the handshake. **Mitigation:** the health-checker rejects any entry whose CDN edge isn't TLS 1.3 + h2.

### P9. Pool distribution / freshness & versioning
The master list rots: domains migrate CDNs, certs change, ranks shift. **Mitigation:** treat the master
list as **versioned data** (`hydra-pool-v1` tag in the KDF), refresh via the health-checker, and ship
updates out of band. Plan a migration path when the format/tag bumps.

### P10. TLS-in-TLS detection (tier C — Hydra is blind to it)
REALITY tunnels your *inner* TLS inside the *outer* one, producing detectable nested-handshake patterns
(record-size bursts, entropy, ACK timing). **Hydra does nothing here.** **Mitigation:** always run
`xtls-rprx-vision`; consider added padding/shaping. Track censorship research on TLS-in-TLS classifiers.

### P11. The "many SNIs to one server-IP" anomaly
A single client hitting a single *server* IP with many SNIs is unlike a browser, which spreads SNIs across
many *destination* IPs. This is benign **only** when the server IP is a CDN edge (where many SNIs to one IP
is normal). **Mitigation:** CDN fronting (again); optionally bias rotation so a given client↔IP pair shows
a realistic *few* SNIs per session rather than churning through the whole pool.

### P12. Pure IP blocking (the elephant)
Restated because it's the original goal: **Hydra does not solve it.** Plan the orthogonal layer explicitly —
CDN fronting (put REALITY behind a real CDN edge), rotating server IPs, or ECH-capable hosting.

### P13. Legal/operational
Censorship-circumvention research. Keep deployment to authorized testing, your own infrastructure, and
lawful contexts. Document upstream licenses (REALITY/Xray per XTLS; respect them on any fork).

---

## 8. Architecture

```
                         ┌─────────────────────────── client ───────────────────────────┐
 app traffic  ──SOCKS5──▶│  Hydra outbound                                               │
                         │   ├─ PoolEngine     (master list, weights, keyed-epoch subset) │
                         │   ├─ Selector       (weighted-random + sticky-per-dest cache)  │
                         │   ├─ DnsWarmer      (real resolution per SNI, TTL-aware)        │
                         │   └─ RealityTLS     (uTLS-equiv ClientHello, embedded auth,     │──▶ CDN edge ──▶ server
                         │                      flow=xtls-rprx-vision)                     │   (fronts pool + server)
                         └───────────────────────────────────────────────────────────────┘
                                                                                                │
                         ┌─────────────────────────── server ───────────────────────────┐      │
                         │  Xray REALITY inbound (stock), behind the CDN                  │◀─────┘
                         │   ├─ serverNames = active epoch pool (SNIs)                    │
                         │   ├─ auth (SNI-independent X25519 proof + timestamp)           │
                         │   └─ ONE dest = the CDN edge ──▶ probe fallback (real sites)   │
                         │  HealthChecker (sidecar): coherence + cert/SAN + ALPN + latency │
                         └───────────────────────────────────────────────────────────────┘
```

The **PoolEngine, Selector, DnsWarmer, and HealthChecker are the new code.** `RealityTLS` is the hard
infrastructure piece (fingerprint + embedded auth + Vision). The server inbound can start as **stock Xray**,
**fronted by a CDN** (the single `dest` points at the CDN edge).

### 8.1 Handshake vs probe (sequence sketch)

```
Authorized client:   ClientHello(SNI=X∈pool, sessionID=enc-auth, fp=chrome, flow=vision)
                      → REALITY server decrypts sessionID with privateKey → auth OK
                      → proxies tunneled traffic (Vision-shaped)

Active prober:        ClientHello(SNI=X∈pool, no valid auth)
                      → REALITY forwards raw bytes to dest=CDN edge
                      → CDN edge returns genuine cert+site for X  → prober sees a real visit
```

---

## 9. Comparison to alternatives

When to reach for Hydra versus the field. (All assume a tier-A/B censor; tier-C/D needs the extra layers.)

| Approach | SNI seen by DPI | Active-probe safe | Hides server IP | Needs own domain/cert | TLS-in-TLS exposure | Note |
|---|---|---|---|---|---|---|
| **REALITY (fixed SNI)** | one borrowed real SNI | ✅ (fallback) | ❌ | ❌ (borrows cert) | yes → use Vision | baseline |
| **REALITY-Hydra** | rotating borrowed SNIs | ✅ (if CDN dest) | ❌ (CDN if fronted) | ❌ | yes → use Vision | adds SNI diversity; **needs CDN** |
| **ShadowTLS v3** | one real relayed site | ✅ | ❌ | ❌ | yes | simpler; no cert borrowing |
| **NaiveProxy** | your real domain | ✅ (real web server) | via CDN | ✅ | low (real h2) | very robust; needs domain+cert |
| **VLESS+WS+CDN** | CDN domain | ✅ | ✅ (CDN IP) | ✅ | n/a (WS) | CDN hides IP; higher latency |
| **Hysteria2 / TUIC** | QUIC / none (UDP) | ✅ | ❌ | optional | n/a (UDP) | fast; vulnerable to UDP QoS/block |
| **Plain ECH** | **encrypted** | n/a | needs ECH host | ❌ | n/a | strongest SNI hiding; often blocked |

**Pick Hydra when:** you already run REALITY, can front it behind a CDN, and want to deny tier-A SNI
signatures without owning a domain/cert. **Prefer NaiveProxy / VLESS+WS+CDN** when you can own a domain and
want genuine IP hiding. **Prefer ECH** where it actually works in-region. Hydra and ECH are complementary.

---

## 10. Implementation plan (phased, Rust-first)

The plan deliberately front-loads the *novel, self-contained, testable* logic and defers the gnarly TLS
infrastructure, so you get value early and learn Rust on clean modules.

### Phase 0 — Spec & fixtures
- Write the `PoolEntry` schema, the master-list format (TOML/JSON), and the KDF/epoch/sampler spec (§5.4)
  precisely. Pin the domain-separation tag `hydra-pool-v1`.
- Capture a **real Chrome JA3/JA4** to use as the fingerprint validation target later.

### Phase 1 — PoolEngine (pure Rust, no network) ✅ *start here*
- Data model: `PoolEntry`, `MasterList`, `ActivePool`.
- `keyed_epoch_subset(master_secret, server_salt, epoch, k)` using `hmac` + `sha2` → `chacha20` PRNG →
  weighted reservoir (A-Res) sampler.
- Weighted-random `select()` with a sticky-per-destination cache.
- Crates: `hmac`, `sha2`, `chacha20`/`rand_chacha`, `secrecy`+`zeroize` (master_secret), `serde`.
- **Tests:** determinism (same secret+salt+epoch ⇒ identical subset on both "sides"), ±1 epoch window,
  **sampler unbiasedness** (χ² over many epochs ≈ weight distribution, via `proptest`), sticky-cache
  behavior. Add `criterion` benches for selection.
- *Perfect Rust onramp: pure logic, property-testable, no async.*

### Phase 2 — HealthChecker (async Rust)
- Resolve each SNI (`hickory-dns`), verify it lands in the configured coherence range (`ipnet`/`iprange`
  CIDR allowlist for the CDN).
- TLS 1.3 handshake to `dest` (`tokio` + `rustls` is fine *here* — this is just validation, not the
  camouflaged client), assert leaf cert valid + SAN matches `sni` + ALPN `h2`.
- Latency band check. Emit a pruned `ActivePool`.
- **Tests:** against known-good (a real CDN domain) and known-bad (expired-cert test endpoints).

### Phase 3 — DnsWarmer
- Real resolve-on-first-use + TTL-aware cache; refresh spreading. Wire selection ⇒ guaranteed prior resolve.

### Phase 4 — RealityTLS (the hard part)
- uTLS-equivalent ClientHello via a **BoringSSL-impersonation path** (`rquest`/`reqwest-impersonate`/`wreq`
  or `boring`) — **not** vanilla `rustls` — matching the Phase 0 Chrome JA3.
- Embed the REALITY X25519 auth proof + timestamp in the session ID. (Cross-check against XTLS REALITY
  source.) Enable `flow=xtls-rprx-vision`.
- **Validate JA3/JA4** equals the real-Chrome fixture before trusting anything.

### Phase 5 — Integration against stock Xray (behind a CDN)
- Because auth is SNI-independent: configure a stock Xray REALITY server **fronted by a CDN**, with the
  **active epoch pool** in `serverNames` and the **single `dest` pointing at the CDN edge**.
- Point the Rust Hydra client at it; confirm authorized rotation works and probes fall back to genuine
  sites for **every** pool SNI.

### Phase 6 — (optional) Server-side epoch automation
- A sidecar that regenerates the server's `serverNames` each epoch from the same `master_secret`+`server_salt`,
  so the accepted set tracks the keyed pool automatically.

### Phase 7 — Hardening & measurement
- Run §7 (P1–P13) as a checklist. Measure JA3 stability, DNS-resolution coverage, fallback success rate,
  and selection distribution against a Tranco-shaped target. See §13 for metrics.

---

## 11. Config sketch

```toml
# hydra.toml
master_secret = "base64:...."        # 32B, SEPARATE from REALITY keys; rotatable on leak
server_salt   = "base64:...."        # 16B, per-deployment; prevents cross-deployment pool correlation
pool_format   = "hydra-pool-v1"      # KDF domain-separation tag; bump on format change
epoch_len     = "6h"
active_k      = 12                    # SNIs live per epoch
dest          = "cdn-edge.example:443"   # ONE CDN edge that serves a valid cert for EVERY pool SNI
coherence_cidrs = [                   # the CDN's edge ranges your server is fronted by
  "104.16.0.0/13",                    # example: a CDN range
]

[[pool]]                              # all entries: real domains on the SAME CDN as `dest`
sni    = "real-domain-on-that-cdn.example"
weight = 1.0
# ... N entries, all coherence-checked by the HealthChecker before going live
```

```jsonc
// stock Xray server inbound (REALITY), fronted by a CDN — serverNames = current active epoch pool
{
  "protocol": "vless",
  "settings": { "clients": [{ "id": "....", "flow": "xtls-rprx-vision" }] },
  "streamSettings": {
    "security": "reality",
    "realitySettings": {
      "dest": "cdn-edge.example:443",         // the ONE CDN edge (not per-SNI)
      "serverNames": ["...active epoch pool SNIs..."],
      "privateKey": "....",
      "shortIds": ["...."],
      "maxTimeDiff": 60000                     // REALITY anti-replay window (ms)
    }
  }
}
```

---

## 12. Operational playbook

**Building a coherent SNI pool (the hard operational part):**
- Pick your CDN first (the one fronting your server). Then enumerate **real domains served by that CDN**:
  - `crt.sh` / Certificate Transparency logs filtered by the CDN's issuing patterns,
  - **Censys**/Shodan queries for the CDN's cert + ASN,
  - passive-DNS providers, or
  - Tranco top-list filtered by `CNAME → <cdn>` (resolve each and keep those whose A-records fall in
    `coherence_cidrs`).
- Health-check every candidate (P1) before it enters the MasterList; re-check on a schedule (P9).

**IP survivability (tier D, orthogonal to Hydra):**
- Front REALITY behind the CDN so the public IP is the CDN's, not your VPS's.
- Keep a **pool of fallback server IPs / domains** and a rotation/UX path for when one is blocked.
- Watch ECH availability in-region; adopt it where it actually passes.

**Secret & list distribution:** ship `master_secret` + `server_salt` + MasterList to clients over an
out-of-band channel that doesn't itself fingerprint (bundle in the client config, not a fetch from a
flagged endpoint). Rotating `master_secret` is the response to a suspected leak.

**Monitoring:** alert on (a) pool entries failing health-check, (b) probe traffic spikes to your server,
(c) sudden drop in successful handshakes (possible IP block — trigger IP rotation).

---

## 13. Validation checklist & success metrics

**Correctness checklist**
- [ ] PoolEngine: client-derived active set == server-derived active set for the same `(secret, salt, epoch)`.
- [ ] Sampler is unbiased (χ² of long-run selection ≈ configured weights).
- [ ] ±1 epoch boundary: a client one epoch off still authenticates; REALITY `maxTimeDiff` separately tested.
- [ ] Every active SNI: real DNS resolves into a `coherence_cidrs` range (Traps 2 & 3).
- [ ] Every active SNI: client issued a real DNS query before connecting (Trap 1).
- [ ] Every active SNI via the single `dest`: TLS 1.3 + h2 + valid cert + SAN match (P1/P8).
- [ ] JA3/JA4 of the Rust client == real Chrome fixture (P7); `flow=xtls-rprx-vision` enabled (P10).
- [ ] Selection distribution ≈ Tranco-shaped, not uniform (P3/P4).
- [ ] Active-probe test: unauthenticated connection to each SNI returns the genuine site.
- [ ] Documented, separate plan for the IP-blocking layer (P12).

**Success metrics (how you'd empirically know it works)**
- **Blocking-survival time:** days a deployment stays reachable from inside the censored region vs a
  fixed-SNI control.
- **Detection rate:** fraction of Hydra flows a reference classifier (e.g. an nDPI/Vision-style detector)
  flags vs the fixed-SNI baseline.
- **Coherence pass rate:** % of active-pool SNIs whose resolved IP matches the connected IP.
- **A/B:** run fixed-SNI and Hydra side by side on sibling IPs; compare time-to-block.

---

## 14. Open questions / future work

- **ECH convergence:** once ECH is reliably usable in the target region, does Hydra reduce to "pick any
  coherent SNI once"? Hydra and ECH are complementary, not exclusive.
- **Server IP rotation** synchronized to the same epoch key (extends Hydra to the L3 layer it currently
  punts on).
- **Decoy DNS traffic** to make the resolve pattern (P5) indistinguishable from a real browser session.
- **Pool distribution** trust model — how do client and server agree on the master list without that
  exchange itself being a fingerprint?
- **Post-quantum auth** — adopt REALITY's `mldsa65` for the embedded auth.

---

## 15. Glossary

- **SNI** — Server Name Indication; the plaintext hostname in the TLS ClientHello.
- **REALITY** — XTLS transport that borrows a real site's TLS identity and hides auth in the session ID.
- **dest / target** — the single real upstream REALITY relays unauthenticated/probe traffic to.
- **serverNames** — server-side list of SNIs accepted from authorized clients.
- **Vision (`xtls-rprx-vision`)** — REALITY flow that mitigates TLS-in-TLS detection via padding/shaping.
- **Active probing** — a censor connecting to your server to test whether it's a genuine site.
- **TLS-in-TLS** — the detectable pattern of one TLS session tunneled inside another.
- **Coherence** — the property that a pool SNI's real DNS resolves into the same CDN/ASN as your server IP.
- **Epoch** — a time window over which the keyed active pool is constant (`floor(time / EPOCH_LEN)`).
- **A-Res** — algorithm for unbiased weighted random sampling without replacement.
- **ECH** — Encrypted Client Hello; encrypts the SNI entirely (the thing Hydra does *not* do).
- **Tranco** — a research-grade domain popularity ranking used to shape selection weights.

---

## 16. References

- REALITY README — https://github.com/XTLS/REALITY/blob/main/README.en.md
- REALITY protocol (DeepWiki) — https://deepwiki.com/amnezia-vpn/amnezia-xray-core/5.2-reality-protocol
- Xray REALITY examples (Vision flow) — https://github.com/XTLS/Xray-examples/blob/main/VLESS-TCP-XTLS-Vision-REALITY/REALITY.ENG.md
- "When SNIs Cannot be Trusted" (nDPI, `NDPI_UNRESOLVED_HOSTNAME`) — https://www.ntop.org/when-snis-cannot-be-trusted/
- Proxy rotation & ASN diversity (single-ASN fingerprint) — https://plainproxies.com/blog/integrations/proxy-rotation-asn-diversity-ip-reputation-detection
- Frolov et al., "Detecting Probe-resistant Proxies" (TLS-in-TLS / probe resistance) — https://www.ndss-symposium.org/ndss-paper/detecting-probe-resistant-proxies/
- Tranco list — https://tranco-list.eu/

---

*This is censorship-circumvention research. Deploy only against your own infrastructure and in lawful,
authorized contexts. Respect upstream licenses on any REALITY/Xray fork.*
