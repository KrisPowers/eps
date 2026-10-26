# at installer (Windows, PowerShell).
#
# Installs the compiled binary under the command name `@` (as `@.exe`).
#
#   irm https://at.krispowers.dev/install.ps1 | iex
#
# Override with environment variables before running:
#   $env:AT_INSTALL_BASE  base URL to fetch release archives from
#   $env:AT_INSTALL_DIR   directory to install into
#   $env:AT_VERSION       release tag to install (default: latest)
#
# NOTE: the project repo is currently private, so downloads will 404 until the
# first public release. The single place to change the host is $base below.

$ErrorActionPreference = 'Stop'

$base    = if ($env:AT_INSTALL_BASE) { $env:AT_INSTALL_BASE } else { 'https://at.krispowers.dev' }
$version = if ($env:AT_VERSION)      { $env:AT_VERSION }      else { 'latest' }
$dir     = if ($env:AT_INSTALL_DIR)  { $env:AT_INSTALL_DIR }  else { Join-Path $env:LOCALAPPDATA 'Programs\at' }

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'x86_64' }
    'ARM64' { 'aarch64' }
    default { throw "at: unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
}

$target  = "$arch-pc-windows-msvc"
$archive = "at-$target.zip"
$url     = "$base/releases/$version/$archive"

New-Item -ItemType Directory -Force -Path $dir | Out-Null
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    Write-Host "Downloading $url"
    $zip = Join-Path $tmp $archive
    Invoke-RestMethod -Uri $url -OutFile $zip
    Expand-Archive -Path $zip -DestinationPath $tmp -Force

    # The archive ships the binary as `at.exe`; install it as `@.exe`.
    Copy-Item -Path (Join-Path $tmp 'at.exe') -Destination (Join-Path $dir '@.exe') -Force
    Write-Host "Installed: $dir\@.exe"

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath -notlike "*$dir*") {
        [Environment]::SetEnvironmentVariable('Path', "$userPath;$dir", 'User')
        Write-Host "Added $dir to your user PATH (restart your shell to pick it up)."
    }

    Write-Host ""
    Write-Host "Try it (PowerShell treats @ specially, so call it explicitly):"
    Write-Host "  & '@' 127.0.0.1"
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
