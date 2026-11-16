# Publie une nouvelle version d'Escale sur GitHub, depuis ce poste (pas de GitHub Actions).
#
#   .\release.ps1 0.2.3
#
# 1. met à jour la version (Cargo.toml + Cargo.lock) ;
# 2. compile en release (cargo build --release) -> dist\Escale.exe ;
# 3. commite tout, crée le tag vX.Y.Z et pousse sur origin/main ;
# 4. publie la release GitHub avec Escale.exe (gh release create).
#
# L'updater intégré (src/update.rs) lit la dernière release de nbstheo/Escale et vérifie
# l'empreinte SHA-256 que GitHub calcule pour Escale.exe.
#
# Prérequis : Rust (cargo), git et GitHub CLI connecté (gh auth login).
# Première fois sur un PC :
#   git clone https://github.com/nbstheo/Escale.git

param(
    [Parameter(Mandatory = $true)][string]$Version,
    # Ne lance pas les tests avant de compiler.
    [switch]$SkipTests
)

$Repo = "nbstheo/Escale"
$Remote = "origin"
$Branch = "main"

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$env:Path += ";$env:USERPROFILE\.cargo\bin"

$Version = $Version.TrimStart('v', 'V')
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Version invalide : $Version (attendu X.Y.Z)" }
$tag = "v$Version"

function Run {
    $cmd, $rest = $args
    # cargo et git écrivent leur progression sur stderr : ce n'est pas une erreur, seul le code de sortie compte
    $ErrorActionPreference = "Continue"
    & $cmd @rest
    if ($LASTEXITCODE -ne 0) { throw "$cmd $rest a échoué (code $LASTEXITCODE)" }
}

# --- vérifications avant de toucher à quoi que ce soit
foreach ($tool in "git", "cargo", "gh") {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "$tool introuvable dans le PATH" }
}
cmd /c "gh auth status >nul 2>&1"
if ($LASTEXITCODE -ne 0) { throw "GitHub CLI non connecté : gh auth login" }

$url = git remote get-url $Remote
if ($url -notmatch [regex]::Escape($Repo)) { throw "Le dépôt distant $Remote ($url) n'est pas $Repo" }
if ((git rev-parse --abbrev-ref HEAD) -ne $Branch) { throw "Pas sur la branche $Branch" }

$current = (Select-String -Path Cargo.toml -Pattern '^version\s*=\s*"(.+)"').Matches[0].Groups[1].Value
if ([version]$Version -le [version]$current) { throw "La version $Version doit être supérieure à l'actuelle ($current)" }

Run git fetch --quiet --tags $Remote
if (git tag --list $tag) { throw "Le tag $tag existe déjà" }
if ([int](git rev-list --count "HEAD..$Remote/$Branch") -gt 0) { throw "$Remote/$Branch a des commits absents d'ici : git pull --rebase d'abord" }

# rien de local (installateur, outils de test, secrets) ne doit partir sur le dépôt public
$forbidden = git status --porcelain --untracked-files=all | ForEach-Object { $_.Substring(3) } |
    Where-Object { $_ -match '^(installer|tools|dist|target|\.old)/|^\.github/workflows/|\.(escale|pem|ppk|env)$' }
if ($forbidden) { throw "Fichiers locaux qui seraient publiés (vérifier .gitignore) :`n  $($forbidden -join "`n  ")" }

# --- version : Cargo.toml (première ligne version = "..." de [package]) et entrée escale de Cargo.lock
$utf8 = New-Object System.Text.UTF8Encoding $false
$tomlBefore = [IO.File]::ReadAllText("$PWD\Cargo.toml")
$lockBefore = [IO.File]::ReadAllText("$PWD\Cargo.lock")
$toml = ([regex]'(?m)^version\s*=\s*".*"').Replace($tomlBefore, "version = `"$Version`"", 1)
$lock = [regex]::Replace($lockBefore, '(name = "escale"\r?\nversion = )".*"', "`$1`"$Version`"")
[IO.File]::WriteAllText("$PWD\Cargo.toml", $toml, $utf8)
[IO.File]::WriteAllText("$PWD\Cargo.lock", $lock, $utf8)
Write-Host "Version $current -> $Version" -ForegroundColor Cyan

# --- tests + compilation ; en cas d'échec la version d'origine est remise
try {
    if (-not $SkipTests) {
        Write-Host "Tests..." -ForegroundColor Cyan
        Run cargo test --release --locked
    }
    Write-Host "Compilation (release)..." -ForegroundColor Cyan
    Run cargo build --release --locked
}
catch {
    [IO.File]::WriteAllText("$PWD\Cargo.toml", $tomlBefore, $utf8)
    [IO.File]::WriteAllText("$PWD\Cargo.lock", $lockBefore, $utf8)
    throw
}

New-Item -ItemType Directory -Force dist | Out-Null
Copy-Item target\release\escale.exe dist\Escale.exe -Force
$sha = (Get-FileHash dist\Escale.exe -Algorithm SHA256).Hash.ToLower()
$mo = [math]::Round((Get-Item dist\Escale.exe).Length / 1MB, 1)
Write-Host "dist\Escale.exe : $mo Mo, SHA-256 $sha" -ForegroundColor Cyan

# --- commit, tag, envoi
Run git add -A
Run git commit -m "Escale $Version"
Run git tag -a $tag -m "Escale $Version"
Run git push $Remote $Branch
Run git push $Remote $tag

# --- release GitHub (même présentation que les précédentes)
$notes = @"
Télécharger **Escale.exe** et le lancer — rien à installer.
Download **Escale.exe** and run it — nothing to install.

SHA-256 : ``$sha``
"@
$notesFile = Join-Path $env:TEMP "escale-release-$Version.md"
[IO.File]::WriteAllText($notesFile, $notes, $utf8)
try {
    Run gh release create $tag "dist\Escale.exe" --repo $Repo --title "Escale $Version" --notes-file $notesFile --verify-tag --latest
}
finally {
    Remove-Item $notesFile -ErrorAction SilentlyContinue
}

Write-Host "Escale $Version publiée : https://github.com/$Repo/releases/tag/$tag" -ForegroundColor Green
