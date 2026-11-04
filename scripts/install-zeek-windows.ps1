# Install the versioned Brim Data build for controlled PCAP analysis.
$ErrorActionPreference = 'Stop'
$release = 'v7.0.0-brim1'
$root = Split-Path -Parent $PSScriptRoot
$name = "zeek-$release.windows-amd64.zip"
$archive = Join-Path $root "work\tool-installers\$name"
$destination = Join-Path $env:LOCALAPPDATA "Programs\CyberBlackBox\zeek-$release"
$exe = Join-Path $destination 'zeek\bin\zeek.exe'
if (-not (Test-Path -LiteralPath $archive)) {
    New-Item -ItemType Directory -Force -Path (Split-Path $archive) | Out-Null
    & curl.exe --fail --silent --show-error --location --retry 2 --max-time 300 "https://github.com/brimdata/build-zeek/releases/download/$release/$name" -o $archive
    if ($LASTEXITCODE -ne 0) { throw 'Zeek archive download failed.' }
}
if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne 'ED3D5B6BBCC1C70580141D431C883FE03A5B8A6F6D7E0DE86A0F4A4A7B1A6F64') { throw 'Downloaded archive differs from the tested project version.' }
if (-not (Test-Path -LiteralPath $exe)) {
    if (Test-Path -LiteralPath $destination) {throw "Incomplete install at $destination. Inspect before retrying."}
    $stage = "$destination.stage-$([guid]::NewGuid().ToString('N'))"
    Expand-Archive -LiteralPath $archive -DestinationPath $stage
    if (-not (Test-Path -LiteralPath (Join-Path $stage 'zeek\bin\zeek.exe'))) {throw 'Zeek executable missing from download.'}
    Move-Item -LiteralPath $stage -Destination $destination
}
& $exe --version
if ($LASTEXITCODE -ne 0) { throw 'Zeek did not pass the version check.' }
Write-Host "Installed: $exe"
