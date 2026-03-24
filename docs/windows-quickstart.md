# Windows Quickstart

## Requirements
- Rust toolchain (stable)
- Administrator PowerShell

## Install
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
cd <repo>
.\deploy\install\windows\install.ps1 -DownloadWinSW
```

## Config
Default path:
```
%ProgramData%\Chameleon\config.toml
```

## Service control
```powershell
sc.exe query ChameleonClient
```

## Web UI
Open:
```
http://127.0.0.1:7777
```
