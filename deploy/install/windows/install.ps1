Param(
  [string]$ConfigPath = "$env:ProgramData\Chameleon\config.toml",
  [switch]$DownloadWinSW
)

$ErrorActionPreference = "Stop"

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
  Write-Error "Please run PowerShell as Administrator."
  exit 1
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
  Write-Error "cargo not found. Install Rust toolchain or build binaries manually."
  exit 1
}

Write-Host "Building release binaries..."
cargo build --release -p chameleon-client -p chameleon-bridge

$InstallDir = "$env:ProgramFiles\Chameleon"
$LogDir = "$env:ProgramData\Chameleon\logs"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path $ConfigPath) | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

Copy-Item -Force "target\release\chameleon-client.exe" "$InstallDir\chameleon-client.exe"
Copy-Item -Force "target\release\chameleon-bridge.exe" "$InstallDir\chameleon-bridge.exe"

if (-not (Test-Path $ConfigPath)) {
  Copy-Item -Force "deploy\docker\config.toml.example" $ConfigPath
}

$WinSW = "$InstallDir\winsw.exe"
if (-not (Test-Path $WinSW)) {
  if ($DownloadWinSW) {
    $url = "https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe"
    Invoke-WebRequest -Uri $url -OutFile $WinSW
  } else {
    Write-Error "winsw.exe not found in $InstallDir. Place WinSW there or run with -DownloadWinSW."
    exit 1
  }
}

$ServiceXml = "$InstallDir\ChameleonClientService.xml"
$XmlContent = @"
<service>
  <id>ChameleonClient</id>
  <name>Chameleon Client</name>
  <description>Chameleon local SOCKS5 client</description>
  <executable>$InstallDir\chameleon-client.exe</executable>
  <arguments>run --config $ConfigPath</arguments>
  <logpath>$LogDir</logpath>
  <log mode="roll-by-size">
    <sizeThreshold>10485760</sizeThreshold>
    <keepFiles>5</keepFiles>
  </log>
</service>
"@

Set-Content -Path $ServiceXml -Value $XmlContent

& $WinSW install
& $WinSW start

Write-Host "Install complete. Service 'ChameleonClient' started."
