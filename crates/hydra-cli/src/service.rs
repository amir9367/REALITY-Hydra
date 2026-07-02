//! `hydra service` — install the client or server as a background service.
//!
//! Generates and (optionally) installs an OS-native service:
//!
//! * **Linux** — a systemd unit. The client role is a long-running service
//!   (`hydra serve`); the server role is a `oneshot` service plus a timer that
//!   regenerates the epoch `serverNames` (`hydra server-names --format xray`).
//! * **Windows** — a Scheduled Task (via `schtasks`) running `hydra serve`.
//! * **macOS / other** — the unit text is printed with install instructions.
//!
//! `print` emits the definition without touching the system (works everywhere and
//! is what the tests exercise); `install` / `uninstall` shell out to the platform
//! service manager and need appropriate privileges.

use std::process::Command;

use clap::{Args, Subcommand, ValueEnum};

use crate::error::CliError;

#[derive(Args, Debug)]
pub struct ServiceArgs {
    #[command(subcommand)]
    pub action: ServiceAction,
}

#[derive(Subcommand, Debug)]
pub enum ServiceAction {
    /// Print the service definition without installing anything.
    Print(ServiceSpec),
    /// Install and enable the service (needs root / admin).
    Install(ServiceSpec),
    /// Stop and remove the service (needs root / admin).
    Uninstall(ServiceSpec),
}

#[derive(Args, Debug, Clone)]
pub struct ServiceSpec {
    /// Which side to run.
    #[arg(long, value_enum, default_value_t = Role::Client)]
    pub role: Role,

    /// Path to hydra.toml (absolute recommended for services).
    #[arg(short, long, value_name = "PATH")]
    pub config: String,

    /// SOCKS5 listen address (client role).
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    pub listen: String,

    /// How often the server role regenerates serverNames (systemd OnCalendar or
    /// a shorthand like `hourly`). Ignored for the client role.
    #[arg(long, default_value = "hourly")]
    pub schedule: String,

    /// Service name. Defaults to `hydra-client` / `hydra-server`.
    #[arg(long)]
    pub name: Option<String>,

    /// Path to the `hydra` binary. Defaults to the current executable.
    #[arg(long)]
    pub bin: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Role {
    Client,
    Server,
}

impl ServiceSpec {
    fn service_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| match self.role {
            Role::Client => "hydra-client".to_string(),
            Role::Server => "hydra-server".to_string(),
        })
    }

    fn bin_path(&self) -> String {
        self.bin.clone().unwrap_or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.to_str().map(String::from))
                .unwrap_or_else(|| "hydra".to_string())
        })
    }
}

/// The systemd `.service` unit text.
fn systemd_service(spec: &ServiceSpec) -> String {
    let bin = spec.bin_path();
    let cfg = &spec.config;
    match spec.role {
        Role::Client => format!(
            "[Unit]\n\
             Description=REALITY-Hydra SOCKS5 client\n\
             After=network-online.target\n\
             Wants=network-online.target\n\n\
             [Service]\n\
             ExecStart={bin} serve --config {cfg} --listen {listen}\n\
             Restart=on-failure\n\
             RestartSec=3\n\
             DynamicUser=yes\n\n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            listen = spec.listen,
        ),
        Role::Server => format!(
            "[Unit]\n\
             Description=REALITY-Hydra epoch serverNames refresh\n\n\
             [Service]\n\
             Type=oneshot\n\
             # Regenerate the accepted serverNames for the current epoch. Wire your\n\
             # own Xray reload after this (e.g. ExecStartPost=systemctl reload xray).\n\
             ExecStart={bin} server-names --config {cfg} --format xray\n",
        ),
    }
}

/// The systemd `.timer` unit text (server role only).
fn systemd_timer(spec: &ServiceSpec) -> String {
    format!(
        "[Unit]\n\
         Description=Run {name} on the epoch schedule\n\n\
         [Timer]\n\
         OnCalendar={schedule}\n\
         Persistent=true\n\n\
         [Install]\n\
         WantedBy=timers.target\n",
        name = spec.service_name(),
        schedule = spec.schedule,
    )
}

/// The Windows `schtasks` create command (client role).
fn schtasks_command(spec: &ServiceSpec) -> String {
    format!(
        "schtasks /Create /TN {name} /SC ONLOGON /RL HIGHEST /TR \"'{bin}' serve --config '{cfg}' --listen {listen}\"",
        name = spec.service_name(),
        bin = spec.bin_path(),
        cfg = spec.config,
        listen = spec.listen,
    )
}

/// Render the full definition (unit text or command) for `print`.
pub fn render(spec: &ServiceSpec) -> String {
    let name = spec.service_name();
    if cfg!(target_os = "linux") {
        let mut out = format!("# /etc/systemd/system/{name}.service\n{}", systemd_service(spec));
        if spec.role == Role::Server {
            out.push_str(&format!(
                "\n# /etc/systemd/system/{name}.timer\n{}",
                systemd_timer(spec)
            ));
        }
        out
    } else if cfg!(target_os = "windows") {
        format!("REM Create the scheduled task:\n{}\n", schtasks_command(spec))
    } else {
        format!(
            "# Unsupported OS for automatic install. systemd equivalent:\n{}",
            systemd_service(spec)
        )
    }
}

pub fn run(args: &ServiceArgs) -> Result<String, CliError> {
    match &args.action {
        ServiceAction::Print(spec) => Ok(render(spec)),
        ServiceAction::Install(spec) => install(spec),
        ServiceAction::Uninstall(spec) => uninstall(spec),
    }
}

#[cfg(target_os = "linux")]
fn install(spec: &ServiceSpec) -> Result<String, CliError> {
    let name = spec.service_name();
    let dir = std::path::Path::new("/etc/systemd/system");
    write_unit(&dir.join(format!("{name}.service")), &systemd_service(spec))?;
    let mut enabled = format!("{name}.service");
    if spec.role == Role::Server {
        write_unit(&dir.join(format!("{name}.timer")), &systemd_timer(spec))?;
        enabled = format!("{name}.timer");
    }
    run_cmd("systemctl", &["daemon-reload"])?;
    run_cmd("systemctl", &["enable", "--now", &enabled])?;
    Ok(format!("Installed and started {enabled}"))
}

#[cfg(target_os = "linux")]
fn uninstall(spec: &ServiceSpec) -> Result<String, CliError> {
    let name = spec.service_name();
    let unit = if spec.role == Role::Server {
        format!("{name}.timer")
    } else {
        format!("{name}.service")
    };
    let _ = run_cmd("systemctl", &["disable", "--now", &unit]);
    for suffix in ["service", "timer"] {
        let _ = std::fs::remove_file(format!("/etc/systemd/system/{name}.{suffix}"));
    }
    run_cmd("systemctl", &["daemon-reload"])?;
    Ok(format!("Removed {name}"))
}

#[cfg(target_os = "windows")]
fn install(spec: &ServiceSpec) -> Result<String, CliError> {
    if spec.role == Role::Server {
        return Err(CliError::Service(
            "server role isn't supported as a Windows task; run it on the Linux server".into(),
        ));
    }
    let name = spec.service_name();
    let tr = format!(
        "\"{}\" serve --config \"{}\" --listen {}",
        spec.bin_path(),
        spec.config,
        spec.listen
    );
    run_cmd(
        "schtasks",
        &[
            "/Create", "/F", "/TN", &name, "/SC", "ONLOGON", "/RL", "HIGHEST", "/TR", &tr,
        ],
    )?;
    Ok(format!("Created scheduled task {name}"))
}

#[cfg(target_os = "windows")]
fn uninstall(spec: &ServiceSpec) -> Result<String, CliError> {
    let name = spec.service_name();
    run_cmd("schtasks", &["/Delete", "/F", "/TN", &name])?;
    Ok(format!("Deleted scheduled task {name}"))
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn install(spec: &ServiceSpec) -> Result<String, CliError> {
    Err(CliError::Service(format!(
        "automatic install is unsupported on this OS; use the printed definition:\n{}",
        render(spec)
    )))
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn uninstall(_spec: &ServiceSpec) -> Result<String, CliError> {
    Err(CliError::Service(
        "automatic uninstall is unsupported on this OS".into(),
    ))
}

#[cfg(target_os = "linux")]
fn write_unit(path: &std::path::Path, contents: &str) -> Result<(), CliError> {
    std::fs::write(path, contents).map_err(|source| CliError::Io {
        path: path.display().to_string(),
        source,
    })
}

#[allow(dead_code)]
fn run_cmd(program: &str, args: &[&str]) -> Result<(), CliError> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|e| CliError::Service(format!("failed to run {program}: {e}")))?;
    if !status.success() {
        return Err(CliError::Service(format!(
            "{program} {} exited with {status}",
            args.join(" ")
        )));
    }
    Ok(())
}
