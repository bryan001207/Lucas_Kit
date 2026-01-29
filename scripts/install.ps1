param(
  [string]$Repo = "lucasenlucas/Lucas_Kit",
  [string]$BinName = "lucasdns"
)

$ErrorActionPreference = "Stop"

$os = "windows"
$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }

$api = "https://api.github.com/repos/$Repo/releases/latest"
Write-Host "Downloading latest release from $Repo for $os/$arch..."

$release = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "lucasdns-installer" }
$asset = $release.assets | Where-Object { $_.browser_download_url -match "${os}_${arch}" } | Select-Object -First 1

if (-not $asset) {
  throw "Could not find a release asset matching ${os}_${arch}."
}

$tmp = New-Item -ItemType Directory -Path ([IO.Path]::Combine([IO.Path]::GetTempPath(), [guid]::NewGuid().ToString()))
$archive = Join-Path $tmp.FullName "asset.zip"

Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $archive

Expand-Archive -Path $archive -DestinationPath $tmp.FullName -Force


$exe2 = Join-Path $tmp.FullName "lucaskill.exe"
if (-not (Test-Path $exe2)) {
  # try any exe in root
  $exe2 = Get-ChildItem -Path $tmp.FullName -Filter "lucaskill.exe" -Recurse | Select-Object -First 1 | ForEach-Object { $_.FullName }
}

if (-not $exe) {
  throw "Binary lucasdns.exe not found in archive."
}

$dest = Join-Path $env:USERPROFILE "bin"
New-Item -ItemType Directory -Path $dest -Force | Out-Null

Copy-Item -Path $exe -Destination (Join-Path $dest "lucasdns.exe") -Force

if ($exe2 -and (Test-Path $exe2)) {
    Copy-Item -Path $exe2 -Destination (Join-Path $dest "lucaskill.exe") -Force
    Write-Host "Installed to $dest\\lucaskill.exe"
}

Write-Host "Installed to $dest\\lucasdns.exe"
Write-Host "Make sure $dest is in your PATH, then run: lucasdns --help"
