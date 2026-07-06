<#
.SYNOPSIS
    REALITY-Hydra Windows client installer (Windows 10 / 11 only).

.DESCRIPTION
    Installs and manages the CLIENT side of REALITY-Hydra on Windows. The server
    is Linux-only (use setup.sh on the server); this script never builds or runs
    a server.

    Intended flow: run the SERVER install on Linux first - it prints a
    `hydra://...` connection bundle (plus the salt, key, and address). Then run
    this script and paste the bundle (or enter the values manually).

    Run with no parameters for the interactive menu, or pass -Command:
        .\setup.ps1 -Command client      # install & configure the client
        .\setup.ps1 -Command status
        .\setup.ps1 -Command uninstall

.PARAMETER Command
    client | status | uninstall. Omit for the interactive menu.

.PARAMETER Bundle
    A hydra://<base64> connection bundle (non-interactive install).

.PARAMETER Features
    Cargo features (e.g. "full", "live-dns"). "full" needs cmake (BoringSSL).

.PARAMETER InstallDir
    Where to install hydra.exe. Default: %USERPROFILE%\.local\bin

.PARAMETER ConfigDir
    Where to write hydra.toml. Default: %USERPROFILE%\.config\hydra

.PARAMETER Listen
    SOCKS5 listen address. Default: 127.0.0.1:1080

.PARAMETER SkipTests
    Skip the test suite.

.PARAMETER SkipBuild
    Skip the build step.

.EXAMPLE
    .\setup.ps1
    # Interactive menu

.EXAMPLE
    .\setup.ps1 -Command client -Bundle "hydra://..."
    # Non-interactive install from a bundle
#>

[CmdletBinding()]
param(
    [ValidateSet("client","status","uninstall")]
    [string]$Command,

    [string]$Bundle,
    [string]$Features = "",
    [string]$InstallDir,
    [string]$ConfigDir,
    [string]$Listen = "127.0.0.1:1080",
    [switch]$SkipTests,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$Version = "0.3.0"
$RepoRoot = $PSScriptRoot

if (-not $InstallDir) { $InstallDir = Join-Path $env:USERPROFILE ".local\bin" }
if (-not $ConfigDir)  { $ConfigDir  = Join-Path $env:USERPROFILE ".config\hydra" }

# --- Output helpers ---
function Write-Step { param([string]$m) Write-Host ([char]0x25B8 + " $m") -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host ([char]0x2714 + " $m") -ForegroundColor Green }
function Write-WarnMsg { param([string]$m) Write-Host ([char]0x26A0 + " $m") -ForegroundColor Yellow }
function Write-ErrMsg  { param([string]$m) Write-Host ([char]0x2718 + " $m") -ForegroundColor Red }
function Write-Banner {
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  REALITY-Hydra Client Installer  v$Version  (Windows)" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}
function Die { param([string]$m) Write-ErrMsg $m; exit 1 }

# --- Windows 10/11 gate ---
function Test-WindowsVersion {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $build = 0
    try { $build = [int]([System.Environment]::OSVersion.Version.Build) } catch {}
    $caption = if ($os) { $os.Caption } else { "Windows" }

    # Windows 10 = build 10240+, Windows 11 = build 22000+. Anything below 10 is out.
    if ([System.Environment]::OSVersion.Version.Major -lt 10 -or $build -lt 10240) {
        Die "Unsupported Windows. This client requires Windows 10 or 11 (found: $caption, build $build)."
    }
    $name = if ($build -ge 22000) { "Windows 11" } else { "Windows 10" }
    Write-Ok "$name (build $build) - supported"
}

# --- Toolchain ---
function Add-CargoToPath {
    $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
    if ((Test-Path $cargoBin) -and ($env:PATH -notlike "*$cargoBin*")) {
        $env:PATH = "$cargoBin;$env:PATH"
    }
}

function Install-Rust {
    Add-CargoToPath
    if (Get-Command cargo -ErrorAction SilentlyContinue) {
        $ver = (cmd /c "rustc --version 2>nul")
        $m = [regex]::Match($ver, '(\d+)\.(\d+)\.(\d+)')
        if ($m.Success) {
            $maj = [int]$m.Groups[1].Value; $min = [int]$m.Groups[2].Value
            if ($maj -lt 1 -or ($maj -eq 1 -and $min -lt 88)) {
                Write-WarnMsg "Rust $($m.Value) < 1.88 - updating..."
                & rustup update stable; & rustup default stable
            }
        }
        Write-Ok (cmd /c "rustc --version 2>nul")
        Write-Ok (cmd /c "cargo --version 2>nul")
        return
    }

    Write-WarnMsg "Rust not found - installing (stable)..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        try {
            & winget install --id Rustlang.Rustup -e --silent --accept-source-agreements --accept-package-agreements
        } catch { Write-WarnMsg "winget install failed; falling back to rustup-init." }
    }
    Add-CargoToPath
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        $installer = Join-Path $env:TEMP "rustup-init.exe"
        Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $installer
        & $installer -y --default-toolchain stable
        Remove-Item $installer -ErrorAction SilentlyContinue
        Add-CargoToPath
    }
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Die "Rust installation failed. Install from https://rustup.rs and re-run."
    }
    Write-Ok (cmd /c "cargo --version 2>nul")
}

function Test-Cmake {
    if ($Features -eq "full" -or $Features -like "*boring-impersonate*") {
        if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
            Write-WarnMsg "'$Features' needs cmake (BoringSSL). Installing via winget..."
            if (Get-Command winget -ErrorAction SilentlyContinue) {
                & winget install --id Kitware.CMake -e --silent --accept-source-agreements --accept-package-agreements
                $env:PATH = "$env:PATH;C:\Program Files\CMake\bin"
            }
            if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
                Die "cmake not found. Install it (winget install Kitware.CMake) or use -Features '' for the default build."
            }
        }
        Write-Ok "cmake present"
    }
}

# --- Build / test ---
function Invoke-Build {
    if ($SkipBuild) { Write-WarnMsg "Skipping build (-SkipBuild)"; return }
    $lbl = if ([string]::IsNullOrWhiteSpace($Features)) { "none" } else { $Features }
    Write-Step "Building hydra.exe (features: $lbl, release)..."
    $cargoArgs = @("build","--release","-p","hydra-cli")
    if (-not [string]::IsNullOrWhiteSpace($Features)) { $cargoArgs += @("--features",$Features) }
    & cargo @cargoArgs
    if ($LASTEXITCODE -ne 0) { Die "Build failed (exit $LASTEXITCODE)" }
    Write-Ok "Build complete -> target\release\hydra.exe"
}

function Invoke-Test {
    if ($SkipTests) { Write-WarnMsg "Skipping tests (-SkipTests)"; return }
    Write-Step "Running workspace tests..."
    & cargo test --workspace
    if ($LASTEXITCODE -ne 0) { Die "Tests failed" }
    Write-Ok "Tests passed"
}

function Install-Bin {
    if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }
    $src = Join-Path $RepoRoot "target\release\hydra.exe"
    if (-not (Test-Path $src)) { Die "Binary not found: $src - build first." }
    $dst = Join-Path $InstallDir "hydra.exe"
    Copy-Item $src $dst -Force
    Write-Ok "Installed hydra.exe -> $dst"
    $userPath = [Environment]::GetEnvironmentVariable("Path","User")
    if ($userPath -notlike "*$InstallDir*") {
        Write-WarnMsg "$InstallDir is not on your PATH. Add it permanently:"
        Write-Host "    [Environment]::SetEnvironmentVariable('Path','$InstallDir;'+[Environment]::GetEnvironmentVariable('Path','User'),'User')"
    }
    return $dst
}

# --- Bundle handling ---
function Convert-FromBundle {
    param([string]$Token)
    $t = $Token.Trim()
    if ($t.StartsWith("hydra://")) { $t = $t.Substring(8) }
    try {
        $bytes = [System.Convert]::FromBase64String($t)
        return [System.Text.Encoding]::UTF8.GetString($bytes)
    } catch {
        Die "Could not decode bundle (expected hydra://<base64>)."
    }
}

function New-ClientConfigFromBundle {
    param([string]$Token, [string]$CfgPath)
    $toml = Convert-FromBundle -Token $Token
    # Defensive: never keep a server private key in a client config.
    $toml = ($toml -split "`n" | Where-Object { $_ -notmatch '^\s*private_key' }) -join "`n"
    Set-Content -Path $CfgPath -Value $toml -Encoding UTF8
    Write-Ok "Wrote client config from bundle -> $CfgPath"
}

function New-ClientConfigManual {
    param([string]$HydraBin, [string]$CfgPath)
    $addr   = Read-Host "  Server IP or domain"
    $port   = Read-Host "  REALITY port [443]"; if ([string]::IsNullOrWhiteSpace($port)) { $port = "443" }
    $secret = Read-Host "  master_secret (base64:... or raw)"
    $salt   = Read-Host "  server_salt (base64:... or raw)"
    $pbk    = Read-Host "  public_key / pbk (base64)"
    $sid    = Read-Host "  short_id (hex)"
    $pin    = Read-Host "  cert_pin from 'hydra server' (base64, blank = no pinning / Xray path)"
    if (-not $addr -or -not $secret -or -not $salt -or -not $pbk) {
        Die "Missing required value (address, secret, salt, and pbk are all required)."
    }
    if ($secret -notlike "base64:*") { $secret = "base64:$secret" }
    if ($salt   -notlike "base64:*") { $salt   = "base64:$salt" }
    if ($pbk    -like    "base64:*") { $pbk    = $pbk.Substring(7) }
    if ($pin -and $pin -notlike "base64:*") { $pin = "base64:$pin" }

    # Start from the default pool, then rewrite the shared fields.
    $tmp = [System.IO.Path]::GetTempFileName()
    & $HydraBin init --output $tmp --dest "$addr`:$port" --force | Out-Null
    $lines = Get-Content $tmp
    $out = foreach ($ln in $lines) {
        if     ($ln -match '^master_secret\s*=')     { "master_secret = `"$secret`"" }
        elseif ($ln -match '^server_salt\s*=')        { "server_salt   = `"$salt`"" }
        elseif ($ln -match '^\s*public_key\s*=')      { "public_key  = `"$pbk`"" }
        elseif ($ln -match '^\s*short_ids\s*=')       { "short_ids   = [`"$sid`"]" }
        elseif ($ln -match '^\s*private_key\s*=')     { continue }
        # For the self-tunnel, dial the VPS directly and (optionally) pin its cert.
        elseif ($ln -match '^#\s*server_addr\s*=')    { "server_addr = `"$addr`:$port`"" }
        elseif ($ln -match '^#\s*cert_pin\s*=')       { if ($pin) { "cert_pin    = `"$pin`"" } else { $ln } }
        else { $ln }
    }
    Set-Content -Path $CfgPath -Value ($out -join "`n") -Encoding UTF8
    Remove-Item $tmp -ErrorAction SilentlyContinue
    Write-Ok "Wrote client config -> $CfgPath"
    if ($pin) { Write-Ok "Self-tunnel: dialing $addr`:$port with a pinned certificate." }
    else { Write-WarnMsg "No cert_pin given: self-tunnel will accept any cert (or use the Xray path)." }
    Write-WarnMsg "Manual mode uses the DEFAULT SNI pool; it must match the server's."
    Write-WarnMsg "If the server customized its pool, use the hydra:// bundle instead."
}

# --- Client install ---
function Install-Client {
    Write-Banner
    Test-WindowsVersion
    Install-Rust
    Test-Cmake
    Invoke-Build
    Invoke-Test
    $hydra = Install-Bin

    if (-not (Test-Path $ConfigDir)) { New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null }
    $cfg = Join-Path $ConfigDir "hydra.toml"

    if (Test-Path $cfg) {
        Write-WarnMsg "Client config already exists at $cfg."
        $a = Read-Host "  Overwrite it? [y/N]"
        if ($a -notmatch '^[Yy]') { Show-ClientSummary $hydra $cfg; return }
    }

    if ($Bundle) {
        New-ClientConfigFromBundle -Token $Bundle -CfgPath $cfg
    } else {
        Write-Host ""
        Write-Host "How do you want to configure this client?" -ForegroundColor White
        Write-Host "   1) Paste the hydra:// bundle from the server   (recommended)"
        Write-Host "   2) Enter the values manually"
        $choice = Read-Host "  Choice [1]"
        if ($choice -eq "2") {
            New-ClientConfigManual -HydraBin $hydra -CfgPath $cfg
        } else {
            $b = Read-Host "  Paste bundle"
            New-ClientConfigFromBundle -Token $b -CfgPath $cfg
        }
    }

    # Optional: run on logon via a Scheduled Task.
    $a = Read-Host "  Run the client automatically on logon (Scheduled Task)? [y/N]"
    if ($a -match '^[Yy]') {
        & $hydra service install --role client --config $cfg --listen $Listen
        if ($LASTEXITCODE -eq 0) { Write-Ok "Scheduled task installed (hydra-client)" }
        else { Write-WarnMsg "Task install failed (try an elevated PowerShell)." }
    }

    Show-ClientSummary $hydra $cfg
}

function Show-ClientSummary {
    param([string]$Hydra, [string]$Cfg)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Client installed." -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Config: $Cfg"
    Write-Host "  Run:    `"$Hydra`" serve -c `"$Cfg`" --listen $Listen"
    Write-Host "  Point your app's SOCKS5 proxy at $Listen."
    Write-Host "  For real DNS + BoringSSL, rebuild with -Features full."
    Write-Host ""
}

# --- Status / Uninstall ---
function Show-Status {
    Write-Banner
    Test-WindowsVersion
    $bin = Join-Path $InstallDir "hydra.exe"
    Write-Host "`nBinary:" -ForegroundColor White
    if (Test-Path $bin) { Write-Ok "$bin" } else { Write-ErrMsg "$bin (not installed)" }
    $cfg = Join-Path $ConfigDir "hydra.toml"
    Write-Host "`nConfig:" -ForegroundColor White
    if (Test-Path $cfg) { Write-Ok "$cfg" } else { Write-ErrMsg "$cfg (not installed)" }
    Write-Host "`nToolchain:" -ForegroundColor White
    if (Get-Command cargo -ErrorAction SilentlyContinue) { Write-Ok (cmd /c "rustc --version 2>nul") }
    else { Write-ErrMsg "Rust not installed" }
    Write-Host "`nScheduled task:" -ForegroundColor White
    $t = schtasks /Query /TN "hydra-client" 2>$null
    if ($LASTEXITCODE -eq 0) { Write-Ok "hydra-client task registered" } else { Write-WarnMsg "no hydra-client task" }
    Write-Host ""
}

function Uninstall-Client {
    Write-Banner
    Write-Step "Uninstalling REALITY-Hydra client..."
    schtasks /Delete /F /TN "hydra-client" 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Ok "Removed scheduled task" }
    $bin = Join-Path $InstallDir "hydra.exe"
    if (Test-Path $bin) { Remove-Item $bin -Force; Write-Ok "Removed $bin" }
    $cfg = Join-Path $ConfigDir "hydra.toml"
    if (Test-Path $cfg) {
        $a = Read-Host "  Remove config $cfg? [y/N]"
        if ($a -match '^[Yy]') { Remove-Item $cfg -Force; Write-Ok "Removed $cfg" }
        else { Write-Step "Kept $cfg" }
    }
    Write-Ok "Uninstall complete"
}

# --- Menu ---
function Show-Menu {
    Write-Banner
    Test-WindowsVersion
    Write-Host ""
    Write-Host "  1) Install client   (paste the server's hydra:// bundle)"
    Write-Host "  2) Status"
    Write-Host "  3) Uninstall"
    Write-Host "  0) Exit"
    Write-Host ""
    $c = Read-Host "  Select [0-3]"
    switch ($c) {
        "1" { Install-Client }
        "2" { Show-Status }
        "3" { Uninstall-Client }
        default { exit 0 }
    }
}

# --- Main ---
switch ($Command) {
    "client"    { Install-Client }
    "status"    { Show-Status }
    "uninstall" { Uninstall-Client }
    default     { Show-Menu }
}
