# Serveurs OpenVPN de test pour Escale (Docker Desktop requis).
#   .\run.ps1            -> build l'image, (re)lance A/B/C, exporte out\A.ovpn B.ovpn C.ovpn
#   .\run.ps1 -Validate  -> idem + valide chaque profil avec un vrai client OpenVPN (conteneur)
#   .\run.ps1 -Stop      -> arrête et supprime les conteneurs et le réseau
# Profils (publiés sur 127.0.0.1 uniquement) :
#   A  UDP 11194  tls-crypt, AES-256-GCM, certificat           tunnel 10.8.0.0/24  echo 10.8.0.1:7
#   B  TCP 11443  tls-auth SHA256, GCM/CBC, comp-lzo, test/secret  tunnel 10.9.0.0/24  echo 10.9.0.1:7
#   C  TCP 11444  comme B mais AES-256-CBC seul               tunnel 10.10.0.0/24 echo 10.10.0.1:7
param([switch]$Validate, [switch]$Stop)
$ErrorActionPreference = 'Continue'  # 'Stop' + 2>$null sur un exe natif lève une erreur en PS 5.1
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$image = 'escale-openvpn-test'
$net = 'escale-ovpn'
$profiles = @(
    @{ Name = 'A'; Port = 11194; Proto = 'udp'; Echo = '10.8.0.1' },
    @{ Name = 'B'; Port = 11443; Proto = 'tcp'; Echo = '10.9.0.1' },
    @{ Name = 'C'; Port = 11444; Proto = 'tcp'; Echo = '10.10.0.1' }
)

function Remove-Containers {
    foreach ($p in $profiles) {
        docker rm -f "escale-ovpn-$($p.Name)" 2>$null | Out-Null
    }
}

docker info --format '{{.ServerVersion}}' 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host 'Moteur Docker arrêté : démarrage de Docker Desktop...'
    Start-Process 'C:\Program Files\Docker\Docker\Docker Desktop.exe'
    $deadline = (Get-Date).AddMinutes(3)
    do {
        Start-Sleep -Seconds 3
        docker info --format '{{.ServerVersion}}' 2>$null | Out-Null
        $ok = ($LASTEXITCODE -eq 0)
    } until ($ok -or (Get-Date) -gt $deadline)
    if (-not $ok) { throw 'Docker ne démarre pas.' }
}

if ($Stop) {
    Remove-Containers
    docker network rm $net 2>$null | Out-Null
    Write-Host 'Conteneurs arrêtés.'
    return
}

docker build -t $image $here
if ($LASTEXITCODE -ne 0) { throw 'échec du build' }

docker network inspect $net 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { docker network create $net | Out-Null }

Remove-Containers
$out = Join-Path $here 'out'
New-Item -ItemType Directory -Force $out | Out-Null
foreach ($p in $profiles) {
    $n = $p.Name
    docker run -d --name "escale-ovpn-$n" --network $net `
        --cap-add NET_ADMIN --device /dev/net/tun `
        -p "127.0.0.1:$($p.Port):$($p.Port)/$($p.Proto)" `
        $image $n | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "échec du lancement du serveur $n" }
    # Export du profil client (LF, sans BOM).
    $ovpn = (docker run --rm $image export $n) -join "`n"
    [IO.File]::WriteAllText((Join-Path $out "$n.ovpn"), $ovpn + "`n")
}
Write-Host "Serveurs lancés ; profils clients dans $out"
docker ps --filter "name=escale-ovpn-" --format 'table {{.Names}}\t{{.Ports}}\t{{.Status}}'

if ($Validate) {
    Start-Sleep -Seconds 3
    $failed = @()
    foreach ($p in $profiles) {
        $n = $p.Name
        Write-Host "`n=== Validation $n (client OpenVPN réel -> escale-ovpn-$n, echo $($p.Echo):7) ==="
        $args2 = @('run', '--rm', '-i', '--network', $net, '--cap-add', 'NET_ADMIN',
            '--device', '/dev/net/tun', $image, 'validate-client.sh', "escale-ovpn-$n", $p.Echo)
        if ($n -ne 'A') { $args2 += @('test', 'secret') }
        Get-Content -Raw (Join-Path $out "$n.ovpn") | docker @args2
        if ($LASTEXITCODE -ne 0) { $failed += $n }
    }
    if ($failed.Count) { throw "Validation en échec : $($failed -join ', ')" }
    Write-Host "`nValidation OK pour A, B et C."
}
