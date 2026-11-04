# Compile Escale en release puis produit dist\Escale-Setup-<version>.exe
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root

$env:Path += ";$env:USERPROFILE\.cargo\bin"
cargo build --release
if ($LASTEXITCODE -ne 0) { throw "cargo build a échoué" }

# Version lue dans Cargo.toml
$version = (Select-String -Path Cargo.toml -Pattern '^version\s*=\s*"(.+)"').Matches[0].Groups[1].Value

# Icône générée par build.rs
$ico = Get-ChildItem target\release\build -Recurse -Filter escale.ico | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Copy-Item $ico.FullName installer\escale.ico -Force

$iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 introuvable (winget install JRSoftware.InnoSetup)" }

# l'antivirus peut verrouiller un instant l'exe tout juste compilé : nouvelles tentatives
for ($try = 1; $try -le 3; $try++) {
    & $iscc /Qp "/DAppVersion=$version" installer\escale.iss
    if ($LASTEXITCODE -eq 0) { break }
    if ($try -eq 3) { throw "ISCC a échoué" }
    Start-Sleep -Seconds 3
}
Remove-Item installer\escale.ico
Get-ChildItem dist\*.exe | Select-Object Name, @{n = 'Mo'; e = { [math]::Round($_.Length / 1MB, 2) } }
