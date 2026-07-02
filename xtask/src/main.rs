//! `xtask` — the cross-platform task runner for REALITY-Hydra.
//!
//! One Rust implementation of the build/test/install lifecycle, so `setup.sh`
//! (Linux/macOS) and `setup.ps1` (Windows) can be thin bootstrappers that install
//! Rust and then delegate here. That keeps the two scripts in perfect parity —
//! all the real logic lives in this single place.
//!
//! Run via the cargo alias (see `.cargo/config.toml`):
//!
//! ```text
//! cargo xtask all                 # check → build → test → install → config
//! cargo xtask build --features full
//! cargo xtask install --install-dir ~/.local/bin
//! cargo xtask status
//! ```

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};

/// The two shipped binaries.
const BINS: &[&str] = &["hydra", "hydra-client"];
const MIN_RUST: (u32, u32) = (1, 88);

#[derive(Parser, Debug)]
#[command(name = "xtask", about = "REALITY-Hydra developer task runner")]
struct Cli {
    #[command(subcommand)]
    command: Command_,

    /// Cargo features (comma-separated) to enable for build/test.
    #[arg(long, global = true)]
    features: Option<String>,

    /// Directory to install binaries into.
    #[arg(long, global = true)]
    install_dir: Option<PathBuf>,

    /// Directory for the generated hydra.toml.
    #[arg(long, global = true)]
    config_dir: Option<PathBuf>,

    /// Skip the test step in `all`.
    #[arg(long, global = true)]
    skip_tests: bool,

    /// Skip the build step in `all`.
    #[arg(long, global = true)]
    skip_build: bool,
}

#[derive(Subcommand, Debug)]
enum Command_ {
    /// Verify the Rust toolchain (>= 1.88).
    Check,
    /// Build the workspace in release mode.
    Build,
    /// Run tests, clippy (-D warnings), and rustfmt --check.
    Test,
    /// Copy the release binaries into the install dir.
    Install,
    /// Generate a hydra.toml in the config dir (via `hydra init`).
    Config,
    /// Remove installed binaries and config.
    Uninstall,
    /// Show what is installed and built.
    Status,
    /// check → build → test → install → config.
    All,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\x1b[31m✘\x1b[0m {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: &Cli) -> Result<(), String> {
    match cli.command {
        Command_::Check => check(),
        Command_::Build => build(cli),
        Command_::Test => test(),
        Command_::Install => install(cli),
        Command_::Config => config(cli),
        Command_::Uninstall => uninstall(cli),
        Command_::Status => status(cli),
        Command_::All => {
            check()?;
            if !cli.skip_build {
                build(cli)?;
            }
            if !cli.skip_tests {
                test()?;
            }
            install(cli)?;
            config(cli)?;
            ok(&format!(
                "REALITY-Hydra installed → {}",
                install_dir(cli).display()
            ));
            Ok(())
        }
    }
}

// ─── steps ──────────────────────────────────────────────────────────

fn check() -> Result<(), String> {
    step("Checking Rust toolchain");
    let ver = capture("rustc", &["--version"])?;
    let (maj, min) = parse_semver(&ver)
        .ok_or_else(|| format!("could not parse rustc version from {ver:?}"))?;
    if (maj, min) < MIN_RUST {
        return Err(format!(
            "Rust {}.{}+ required, found {maj}.{min} — run: rustup update",
            MIN_RUST.0, MIN_RUST.1
        ));
    }
    ok(ver.trim());
    ok(capture("cargo", &["--version"])?.trim());
    Ok(())
}

fn build(cli: &Cli) -> Result<(), String> {
    step("Building workspace (release)");
    let mut args = vec!["build", "--release", "--workspace"];
    let feats = cli.features.clone().unwrap_or_default();
    if !feats.is_empty() {
        args.push("--features");
        args.push(&feats);
    }
    run("cargo", &args)?;
    ok("build complete");
    Ok(())
}

fn test() -> Result<(), String> {
    step("Running tests");
    run("cargo", &["test", "--workspace"])?;
    step("Running clippy");
    run("cargo", &["clippy", "--all-targets", "--", "-D", "warnings"])?;
    step("Checking formatting");
    run("cargo", &["fmt", "--all", "--check"])?;
    ok("tests, clippy, fmt clean");
    Ok(())
}

fn install(cli: &Cli) -> Result<(), String> {
    let dir = install_dir(cli);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let rel = repo_root().join("target").join("release");
    for bin in BINS {
        let file = format!("{bin}{}", std::env::consts::EXE_SUFFIX);
        let src = rel.join(&file);
        if !src.exists() {
            return Err(format!("{} not found — run `xtask build` first", src.display()));
        }
        let dst = dir.join(&file);
        std::fs::copy(&src, &dst).map_err(|e| format!("copy {}: {e}", src.display()))?;
        ok(&format!("installed {} → {}", bin, dst.display()));
    }
    warn_if_not_on_path(&dir);
    Ok(())
}

fn config(cli: &Cli) -> Result<(), String> {
    let dir = config_dir(cli);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let cfg = dir.join("hydra.toml");
    if cfg.exists() {
        ok(&format!("config already exists at {} (kept)", cfg.display()));
        return Ok(());
    }
    let hydra = install_dir(cli).join(format!("hydra{}", std::env::consts::EXE_SUFFIX));
    let hydra = if hydra.exists() {
        hydra
    } else {
        repo_root()
            .join("target/release")
            .join(format!("hydra{}", std::env::consts::EXE_SUFFIX))
    };
    step("Generating config via `hydra init`");
    run(
        &hydra.to_string_lossy(),
        &["init", "--output", &cfg.to_string_lossy()],
    )?;
    Ok(())
}

fn uninstall(cli: &Cli) -> Result<(), String> {
    let dir = install_dir(cli);
    let mut removed = 0;
    for bin in BINS {
        let p = dir.join(format!("{bin}{}", std::env::consts::EXE_SUFFIX));
        if p.exists() {
            std::fs::remove_file(&p).map_err(|e| format!("remove {}: {e}", p.display()))?;
            ok(&format!("removed {}", p.display()));
            removed += 1;
        }
    }
    let cfg = config_dir(cli).join("hydra.toml");
    if cfg.exists() {
        std::fs::remove_file(&cfg).map_err(|e| format!("remove {}: {e}", cfg.display()))?;
        ok(&format!("removed {}", cfg.display()));
        removed += 1;
    }
    if removed == 0 {
        ok("nothing to uninstall");
    }
    Ok(())
}

fn status(cli: &Cli) -> Result<(), String> {
    println!("REALITY-Hydra status");
    println!("  install dir: {}", install_dir(cli).display());
    for bin in BINS {
        let p = install_dir(cli).join(format!("{bin}{}", std::env::consts::EXE_SUFFIX));
        println!("    {} {}", mark(p.exists()), p.display());
    }
    let cfg = config_dir(cli).join("hydra.toml");
    println!("  config: {} {}", mark(cfg.exists()), cfg.display());
    let rel = repo_root().join("target/release");
    for bin in BINS {
        let p = rel.join(format!("{bin}{}", std::env::consts::EXE_SUFFIX));
        println!("  built:  {} {}", mark(p.exists()), p.display());
    }
    match capture("rustc", &["--version"]) {
        Ok(v) => println!("  {}", v.trim()),
        Err(_) => println!("  rustc: not found"),
    }
    Ok(())
}

// ─── helpers ────────────────────────────────────────────────────────

fn install_dir(cli: &Cli) -> PathBuf {
    cli.install_dir
        .clone()
        .unwrap_or_else(|| home().join(".local").join("bin"))
}

fn config_dir(cli: &Cli) -> PathBuf {
    cli.config_dir
        .clone()
        .unwrap_or_else(|| home().join(".config").join("hydra"))
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is xtask/; the repo root is its parent.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn parse_semver(s: &str) -> Option<(u32, u32)> {
    // e.g. "rustc 1.88.0 (…)" → (1, 88)
    let nums = s.split_whitespace().find(|t| t.contains('.'))?;
    let mut it = nums.split('.');
    let maj = it.next()?.parse().ok()?;
    let min = it.next()?.parse().ok()?;
    Some((maj, min))
}

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .current_dir(repo_root())
        .status()
        .map_err(|e| format!("failed to launch {program}: {e}"))?;
    if !status.success() {
        return Err(format!("{program} {} failed ({status})", args.join(" ")));
    }
    Ok(())
}

fn capture(program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("failed to launch {program}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{program} {} failed", args.join(" ")));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn warn_if_not_on_path(dir: &Path) {
    if let Some(path) = std::env::var_os("PATH") {
        if std::env::split_paths(&path).any(|p| p == dir) {
            return;
        }
    }
    eprintln!(
        "\x1b[1;33m⚠\x1b[0m {} is not on your PATH — add it to your shell profile",
        dir.display()
    );
}

fn step(msg: &str) {
    println!("\x1b[36m▸\x1b[0m {msg}...");
}

fn ok(msg: &str) {
    println!("\x1b[32m✔\x1b[0m {msg}");
}

fn mark(present: bool) -> &'static str {
    if present {
        "\x1b[32m✔\x1b[0m"
    } else {
        "\x1b[31m✘\x1b[0m"
    }
}
