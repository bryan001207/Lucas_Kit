param(
  [string]$Repo = "lucasenlucas/Lucas_Kit"
)

$ErrorActionPreference = "Stop"

$os = "windows"
$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }

$api = "https://api.github.com/repos/$Repo/releases/latest"
Write-Host "Downloading latest release from $Repo for $os/$arch..."

$release = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "lucaskit-installer" }
$asset = $release.assets | Where-Object { $_.browser_download_url -match "${os}_${arch}" } | Select-Object -First 1

if (-not $asset) {
  throw "Could not find a release asset matching ${os}_${arch}."
}

$tmp = New-Item -ItemType Directory -Path ([IO.Path]::Combine([IO.Path]::GetTempPath(), [guid]::NewGuid().ToString()))
$archive = Join-Path $tmp.FullName "asset.zip"

Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $archive

Expand-Archive -Path $archive -DestinationPath $tmp.FullName -Force

$bins = @("ultradns.exe", "sitestress.exe", "ultracrack.exe")
$dest = Join-Path $env:USERPROFILE "bin"
New-Item -ItemType Directory -Path $dest -Force | Out-Null

foreach ($bin in $bins) {
    $src = Join-Path $tmp.FullName $bin
    if (-not (Test-Path $src)) {
        # Try finding anywhere (sometimes in subdir)
        $found = Get-ChildItem -Path $tmp.FullName -Filter $bin -Recurse | Select-Object -First 1
        if ($found) {
            $src = $found.FullName
        }
    }

    if (Test-Path $src) {
        Copy-Item -Path $src -Destination (Join-Path $dest $bin) -Force
        Write-Host "Installed: $bin"
    } else {
        Write-Host "Checking for $bin... Not found."
    }
}

Write-Host "Installation complete in $dest"
Write-Host "Make sure $dest is in your PATH, then run: ultradns --help"
