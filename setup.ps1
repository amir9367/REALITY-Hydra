<#
.SYNOPSIS
    REALITY-Hydra Windows client setup - builds, tests, and installs hydra-client.

.DESCRIPTION
    Builds only the client-side binary (hydra-client) and its dependencies.
    Server-side crates (hydra-cli, health-checker) are excluded.

.PARAMETER Action
    One or more actions: Check, Build, Test, Install, Config, Uninstall, Status.
    Default (no action): runs the full pipeline Check, Build, Test, Install, Config.

.PARAMETER Features
    Cargo features to enable. Default: "full".

.PARAMETER InstallDir
    Directory to install the binary. Default: "$env:USERPROFILE\.local\bin".

.PARAMETER ConfigDir
    Directory to install the sample config. Default: "$env:USERPROFILE\.config\hydra".

.PARAMETER SkipTests
    Skip the test suite.

.PARAMETER SkipBuild
    Skip the build step.

.PARAMETER NoConfig
    Skip config installation.

.PARAMETER VerboseOutput
    Verbose cargo output.

.EXAMPLE
    .\setup.ps1
    # Full install: check, build, test, install, config

.EXAMPLE
    .\setup.ps1 -Action Build,Test
    # Build and test only

.EXAMPLE
    .\setup.ps1 -Action Install -SkipBuild -SkipTests
    # Install pre-built binary only

.EXAMPLE
    .\setup.ps1 -Action Status
    # Show what's installed

.EXAMPLE
    .\setup.ps1 -Action Uninstall
    # Remove installed binary and config
#>

[CmdletBinding()]
param(
    [ValidateSet("Check","Build","Test","Install","Config","Uninstall","Status")]
    [string[]]$Action,

    [string]$Features = "",

    [string]$InstallDir,
    [string]$ConfigDir,

    [switch]$SkipTests,
    [switch]$SkipBuild,
    [switch]$NoConfig,
    [switch]$VerboseOutput
)

$ErrorActionPreference = "Continue"
$Version = "0.1.0"
$RepoRoot = $PSScriptRoot

# Set defaults here to avoid encoding issues with $env: in param block
if (-not $InstallDir) { $InstallDir = Join-Path $env:USERPROFILE ".local\bin" }
if (-not $ConfigDir)  { $ConfigDir  = Join-Path $env:USERPROFILE ".config\hydra" }

# --- Colored output helpers ---

function Write-Step {
    param([string]$msg)
    Write-Host ([char]0x25B8 + " $msg") -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$msg)
    Write-Host ([char]0x2714 + " $msg") -ForegroundColor Green
}

function Write-WarnMsg {
    param([string]$msg)
    Write-Host ([char]0x26A0 + " $msg") -ForegroundColor Yellow
}

function Write-ErrMsg {
    param([string]$msg)
    Write-Host ([char]0x2718 + " $msg") -ForegroundColor Red
}

# --- Help ---

function Show-Usage {
    Write-Host "REALITY-Hydra Windows Client Setup  v$Version" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "USAGE:" -ForegroundColor White
    Write-Host "    .\setup.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "ACTIONS (pass via -Action):"
    Write-Host "    (none)          Full pipeline: Check > Build > Test > Install > Config"
    Write-Host "    Check           Check prerequisites (Rust toolchain)"
    Write-Host "    Build           Build hydra-client (release mode)"
    Write-Host "    Test            Run tests, clippy, and fmt checks"
    Write-Host "    Install         Copy binary to InstallDir"
    Write-Host "    Config          Install sample config to ConfigDir"
    Write-Host "    Uninstall       Remove installed binary and config"
    Write-Host "    Status          Show installed files and toolchain info"
    Write-Host ""
    Write-Host "OPTIONS:"
    Write-Host "    -Features FEAT       Cargo features (default: full)"
    Write-Host "    -InstallDir DIR      Binary install dir (default: ~\.local\bin)"
    Write-Host "    -ConfigDir DIR       Config install dir (default: ~\.config\hydra)"
    Write-Host "    -SkipTests           Skip test suite"
    Write-Host "    -SkipBuild           Skip build step"
    Write-Host "    -NoConfig            Skip config installation"
    Write-Host "    -VerboseOutput       Verbose cargo output"
    Write-Host ""
}

# --- Prerequisite check ---

function Test-RustToolchain {
    Write-Step "Checking Rust toolchain..."

    $hasRustup = $null -ne (Get-Command rustup -ErrorAction SilentlyContinue)
    $hasCargo  = $null -ne (Get-Command cargo  -ErrorAction SilentlyContinue)

    if ($hasRustup) {
        $rv = (cmd /c "rustup --version 2>nul") -replace "`n.*",""
        $cv = (cmd /c "cargo --version 2>nul") -replace "`n.*",""
        Write-Ok "rustup $rv"
        Write-Ok "cargo  $cv"
    } elseif ($hasCargo) {
        $cv = (cmd /c "cargo --version 2>nul") -replace "`n.*",""
        Write-Ok "cargo  $cv"
        Write-WarnMsg "rustup not found - managing toolchain upgrades may be manual"
    } else {
        Write-WarnMsg "Rust not found. Installing via rustup-init..."
        $installer = Join-Path $env:TEMP "rustup-init.exe"
        Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $installer
        & $installer -y --default-toolchain stable
        Remove-Item $installer -ErrorAction SilentlyContinue
        # Refresh PATH for this session
        $cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
        $env:PATH = $cargoBin + ";" + $env:PATH
        $ver = cmd /c "rustc --version 2>nul"
        Write-Ok "Installed $ver"
    }

    # Version check - require 1.88+
    $current = (cmd /c "rustc --version 2>nul") -replace '.*?(\d+\.\d+\.\d+).*','$1'
    $needed  = "1.88.0"
    if ([version]$current -lt [version]$needed) {
        Write-ErrMsg "Rust $needed+ required, found $current - run: rustup update"
        exit 1
    }
    Write-Ok "Rust $current meets minimum ($needed)"

    # Check for cmake when full feature is requested (needed for BoringSSL)
    if ($Features -eq "full") {
        $hasCmake = $null -ne (Get-Command cmake -ErrorAction SilentlyContinue)
        if (-not $hasCmake) {
            Write-WarnMsg "'full' feature requires cmake (for BoringSSL). Not found."
            Write-Host "  Either install cmake:  winget install cmake"
            Write-Host "  Or build without it:   .\setup.ps1 -Features ''"
            Write-ErrMsg "cmake not found - cannot build with 'full' feature"
            exit 1
        }
        Write-Ok "cmake $(cmd /c 'cmake --version 2>nul' | Select-Object -First 1)"
    }
}

# --- Build ---

function Invoke-Build {
    if ($SkipBuild) {
        Write-WarnMsg "Skipping build (-SkipBuild)"
        return
    }
    $featuresLabel = if ([string]::IsNullOrWhiteSpace($Features)) { "none" } else { $Features }
    Write-Step "Building hydra-client (features: $featuresLabel, release)..."
    $cargoArgs = @("build", "--release", "-p", "hydra-client")
    if (-not [string]::IsNullOrWhiteSpace($Features)) {
        $cargoArgs += @("--features", $Features)
    }
    if ($VerboseOutput) {
        & cargo @cargoArgs
    } else {
        $out = & cargo @cargoArgs 2>&1
        $out | Select-Object -Last 5 | ForEach-Object { Write-Host $_ }
    }
    if ($LASTEXITCODE -ne 0) {
        Write-ErrMsg "Build failed (exit $LASTEXITCODE)"
        exit $LASTEXITCODE
    }
    Write-Ok "Build complete"
}

# --- Test ---

function Invoke-Test {
    if ($SkipTests) {
        Write-WarnMsg "Skipping tests (-SkipTests)"
        return
    }

    Write-Step "Running test suite..."
    & cargo test --workspace 2>&1
    if ($LASTEXITCODE -ne 0) { Write-ErrMsg "Tests failed"; exit $LASTEXITCODE }
    Write-Ok "All tests passed"

    Write-Step "Running clippy lints..."
    & cargo clippy --all-targets -- -D warnings 2>&1
    if ($LASTEXITCODE -ne 0) { Write-ErrMsg "Clippy failed"; exit $LASTEXITCODE }
    Write-Ok "Clippy clean"

    Write-Step "Checking formatting..."
    & cargo fmt --all --check 2>&1
    if ($LASTEXITCODE -ne 0) { Write-ErrMsg "Formatting check failed"; exit $LASTEXITCODE }
    Write-Ok "Formatting clean"
}

# --- Install ---

function Invoke-Install {
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    $src = Join-Path $RepoRoot "target\release\hydra-client.exe"
    if (-not (Test-Path $src)) {
        Write-ErrMsg "Binary not found: $src - run -Action Build first"
        exit 1
    }

    $dst = Join-Path $InstallDir "hydra-client.exe"
    Copy-Item $src $dst -Force
    Write-Ok "Installed hydra-client.exe -> $dst"

    # Check if InstallDir is in PATH
    $pathDirs = $env:PATH -split ";"
    if ($pathDirs -notcontains $InstallDir) {
        Write-WarnMsg "$InstallDir is not in your PATH"
        Write-Host "  Add it permanently:"
        $cmdText = '[Environment]::SetEnvironmentVariable(''Path'', ''' + $InstallDir + ';'' + [Environment]::GetEnvironmentVariable(''Path'', ''User''), ''User'')'
        Write-Host "    $cmdText"
    }
}

# --- Config ---

function Invoke-Config {
    if ($NoConfig) {
        Write-WarnMsg "Skipping config (-NoConfig)"
        return
    }

    $targetConfig = Join-Path $ConfigDir "hydra.toml"
    $sampleConfig = Join-Path $RepoRoot "crates\pool-engine\fixtures\hydra.toml"

    if (Test-Path $targetConfig) {
        Write-WarnMsg "Config already exists at $targetConfig - skipping"
        return
    }

    if (-not (Test-Path $ConfigDir)) {
        New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
    }

    if (-not (Test-Path $sampleConfig)) {
        Write-ErrMsg "Sample config not found: $sampleConfig"
        exit 1
    }

    Copy-Item $sampleConfig $targetConfig
    Write-Ok "Sample config installed -> $targetConfig"
    Write-WarnMsg "Edit $targetConfig with real master_secret + server_salt before using!"
}

# --- Uninstall ---

function Invoke-Uninstall {
    Write-Step "Uninstalling REALITY-Hydra client..."
    $removed = 0

    $binPath = Join-Path $InstallDir "hydra-client.exe"
    if (Test-Path $binPath) {
        Remove-Item $binPath -Force
        Write-Ok "Removed $binPath"
        $removed++
    }

    $configPath = Join-Path $ConfigDir "hydra.toml"
    if (Test-Path $configPath) {
        Remove-Item $configPath -Force
        Write-Ok "Removed $configPath"
        $removed++
    }

    if ($removed -eq 0) {
        Write-WarnMsg "Nothing to uninstall"
    } else {
        Write-Ok "Uninstall complete ($removed items removed)"
    }
}

# --- Status ---

function Show-Status {
    Write-Host ""
    Write-Host "REALITY-Hydra Client Status" -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Cyan

    Write-Host ""
    Write-Host "Binary:" -ForegroundColor White
    $binPath = Join-Path $InstallDir "hydra-client.exe"
    if (Test-Path $binPath) {
        $size = (Get-Item $binPath).Length / 1MB
        $sizeStr = "{0:N1}" -f $size
        Write-Ok "$binPath ($sizeStr MB)"
    } else {
        Write-ErrMsg "$binPath (not installed)"
    }

    Write-Host ""
    Write-Host "Config:" -ForegroundColor White
    $configPath = Join-Path $ConfigDir "hydra.toml"
    if (Test-Path $configPath) {
        Write-Ok "$configPath"
    } else {
        Write-ErrMsg "$configPath (not installed)"
    }

    Write-Host ""
    Write-Host "Rust toolchain:" -ForegroundColor White
    $hasCargo = $null -ne (Get-Command cargo -ErrorAction SilentlyContinue)
    if ($hasCargo) {
        $rv = cmd /c "rustc --version 2>nul"
        $cv = cmd /c "cargo --version 2>nul"
        Write-Ok $rv
        Write-Ok $cv
    } else {
        Write-ErrMsg "Not installed"
    }

    Write-Host ""
    Write-Host "Build artifacts:" -ForegroundColor White
    $releaseBin = Join-Path $RepoRoot "target\release\hydra-client.exe"
    if (Test-Path $releaseBin) {
        $size = (Get-Item $releaseBin).Length / 1MB
        $sizeStr = "{0:N1}" -f $size
        Write-Ok "target\release\hydra-client.exe ($sizeStr MB)"
    } else {
        Write-WarnMsg "target\release\hydra-client.exe (not built)"
    }

    Write-Host ""
}

# --- Main ---

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "  REALITY-Hydra Windows Client Setup  v$Version" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host ""

# Default to full pipeline
if (-not $Action -or $Action.Count -eq 0) {
    $Action = @("Check","Build","Test","Install","Config")
}

Set-Location $RepoRoot

$didInstall = $false
foreach ($a in $Action) {
    switch ($a) {
        "Check"     { Test-RustToolchain }
        "Build"     { Invoke-Build }
        "Test"      { Invoke-Test }
        "Install"   { Invoke-Install; $didInstall = $true }
        "Config"    { Invoke-Config }
        "Uninstall" { Invoke-Uninstall; Write-Host ""; return }
        "Status"    { Show-Status; return }
    }
    Write-Host ""
}

if ($didInstall) {
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host "  REALITY-Hydra client installed successfully!" -ForegroundColor Green
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host ""

    $binMsg = "  Binary:  " + (Join-Path $InstallDir "hydra-client.exe")
    $cfgMsg = "  Config:  " + (Join-Path $ConfigDir "hydra.toml")
    Write-Host $binMsg
    Write-Host $cfgMsg
    Write-Host ""
    Write-Host "  Run the client:" -ForegroundColor White
    $runCmd = "    hydra-client.exe -c " + (Join-Path $ConfigDir "hydra.toml") + " --listen 127.0.0.1:1080"
    Write-Host $runCmd
    Write-Host ""
    Write-Host "  With real DNS + BoringSSL impersonation:" -ForegroundColor White
    $runFull = "    hydra-client.exe --features full -c " + (Join-Path $ConfigDir "hydra.toml") + " --listen 127.0.0.1:1080"
    Write-Host $runFull
    Write-Host ""
} else {
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host "  Done." -ForegroundColor Green
    Write-Host "===========================================================" -ForegroundColor Cyan
    Write-Host ""
}
