//! Rendering an [`ActivePool`] into the three output shapes the sidecar emits.
//!
//! * [`OutputFormat::Lines`] — one SNI per line, for piping into other tooling.
//! * [`OutputFormat::Json`] — a JSON array of SNIs (the literal `serverNames`
//!   value).
//! * [`OutputFormat::Xray`] — a paste-ready stock Xray REALITY inbound, with
//!   `serverNames` filled from the pool and `dest` from the config (REALITY.md
//!   §11). This is the artifact a server operator regenerates each epoch.

use pool_engine::{ActivePool, Epoch, HydraConfig};
use serde_json::{Value, json};

use crate::error::CliError;

/// The output shape selected on the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// One SNI per line.
    #[default]
    Lines,
    /// A JSON array of SNIs.
    Json,
    /// A full stock Xray REALITY inbound snippet.
    Xray,
}

/// Shown in the generated Xray snippet when the config has no `dest`. Stock
/// REALITY *requires* a `dest`, so we emit an obvious placeholder rather than a
/// plausible-looking wrong value (REALITY.md §5.3 — the single CDN edge).
const DEST_PLACEHOLDER: &str = "SET-dest-IN-hydra.toml:443";

/// One SNI per line (no trailing blank line).
pub fn render_lines(pool: &ActivePool) -> String {
    pool.snis().collect::<Vec<_>>().join("\n")
}

/// A pretty-printed JSON array of the SNIs — exactly the `serverNames` value.
pub fn render_json(pool: &ActivePool) -> Result<String, CliError> {
    let arr: Value = pool.snis().collect::<Vec<_>>().into();
    Ok(serde_json::to_string_pretty(&arr)?)
}

/// A paste-ready stock Xray REALITY inbound (VLESS + Vision), with `serverNames`
/// set to this epoch's accepted pool and `dest` taken from the config.
///
/// `epoch` is recorded in a leading comment-style `_hydra` block so an operator
/// can see which epoch the snippet was generated for; Xray ignores unknown
/// fields. `privateKey`/`shortIds`/client `id` are left as placeholders — those
/// are deployment secrets, not derived by Hydra.
pub fn render_xray(cfg: &HydraConfig, pool: &ActivePool, epoch: Epoch) -> Result<String, CliError> {
    let server_names: Vec<&str> = pool.snis().collect();
    let dest = cfg
        .dest
        .clone()
        .unwrap_or_else(|| DEST_PLACEHOLDER.to_string());

    let inbound = json!({
        "_hydra": {
            "note": "REALITY-Hydra Phase 6: regenerate each epoch from hydra.toml",
            "epoch": epoch,
            "active_k": cfg.active_k,
            "serverNames_are": "the ±1 epoch accepted window"
        },
        "protocol": "vless",
        "settings": {
            "clients": [
                { "id": "SET-client-uuid", "flow": "xtls-rprx-vision" }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "dest": dest,
                "serverNames": server_names,
                "privateKey": "SET-from-`xray x25519`",
                "shortIds": [""],
                "maxTimeDiff": 60000
            }
        }
    });

    Ok(serde_json::to_string_pretty(&inbound)?)
}

/// Render `pool` in the requested `format`.
pub fn render(
    cfg: &HydraConfig,
    pool: &ActivePool,
    epoch: Epoch,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Lines => Ok(render_lines(pool)),
        OutputFormat::Json => render_json(pool),
        OutputFormat::Xray => render_xray(cfg, pool, epoch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch::server_names;

    fn cfg() -> HydraConfig {
        HydraConfig::from_toml_str(include_str!("../../pool-engine/fixtures/hydra.toml")).unwrap()
    }

    #[test]
    fn lines_match_pool_snis_in_order() {
        let cfg = cfg();
        let pool = server_names(&cfg, 7, true);
        let rendered = render_lines(&pool);
        let lines: Vec<&str> = rendered.lines().collect();
        let expected: Vec<&str> = pool.snis().collect();
        assert_eq!(lines, expected);
    }

    #[test]
    fn json_is_an_array_of_the_same_snis() {
        let cfg = cfg();
        let pool = server_names(&cfg, 7, true);
        let parsed: Value = serde_json::from_str(&render_json(&pool).unwrap()).unwrap();
        let got: Vec<&str> = parsed
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        let expected: Vec<&str> = pool.snis().collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn xray_carries_servernames_dest_and_epoch() {
        let cfg = cfg();
        let epoch = 7;
        let pool = server_names(&cfg, epoch, true);
        let v: Value = serde_json::from_str(&render_xray(&cfg, &pool, epoch).unwrap()).unwrap();

        let reality = &v["streamSettings"]["realitySettings"];
        // dest comes from the fixture config.
        assert_eq!(reality["dest"], "cdn-edge.example:443");
        // serverNames is exactly the accepted pool.
        let names: Vec<&str> = reality["serverNames"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(names, pool.snis().collect::<Vec<_>>());
        // The epoch is recorded for the operator.
        assert_eq!(v["_hydra"]["epoch"], epoch);
        // Vision flow is set (REALITY.md §1/P10).
        assert_eq!(v["settings"]["clients"][0]["flow"], "xtls-rprx-vision");
    }
}
