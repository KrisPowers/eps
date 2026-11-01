# EPS installer (Windows, PowerShell). Installs the binary as `@.exe`, so
# the command you type is `@`.
#
#   irm https://raw.githubusercontent.com/KrisPowers/eps/main/install.ps1 | iex
#
# Override with environment variables before running:
#   $env:EPS_INSTALL_DIR  directory to install into
#   $env:EPS_VERSION      release tag to install, e.g. v1.0.0 (default: latest)

$ErrorActionPreference = 'Stop'

$repo    = 'https://github.com/KrisPowers/eps'
$version = if ($env:EPS_VERSION)     { $env:EPS_VERSION }     else { 'latest' }
$dir     = if ($env:EPS_INSTALL_DIR) { $env:EPS_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\eps' }

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'x86_64' }
    'ARM64' { 'aarch64' }
    default { throw "@: unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
}

$archive = "eps-$arch-pc-windows-msvc.zip"
$url = if ($version -eq 'latest') { "$repo/releases/latest/download/$archive" } else { "$repo/releases/download/$version/$archive" }

New-Item -ItemType Directory -Force -Path $dir | Out-Null
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    Write-Host "Downloading $url"
    $zip = Join-Path $tmp $archive
    Invoke-RestMethod -Uri $url -OutFile $zip
    Invoke-RestMethod -Uri "$url.sha256" -OutFile "$zip.sha256"
    $want = ((Get-Content -Raw "$zip.sha256").Trim() -split '\s+')[0]
    $got = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash
    if (-not $want -or $want -ne $got) { throw "@: checksum mismatch for $archive" }
    Expand-Archive -Path $zip -DestinationPath $tmp -Force

    # The archive ships the binary as `eps.exe`; install it as `@.exe`.
    Copy-Item -Path (Join-Path $tmp 'eps.exe') -Destination (Join-Path $dir '@.exe') -Force
    Write-Host "Installed: $dir\@.exe"

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath -notlike "*$dir*") {
        [Environment]::SetEnvironmentVariable('Path', "$userPath;$dir", 'User')
        Write-Host "Added $dir to your user PATH (restart your shell to pick it up)."
    }

    # PowerShell's parser rejects a bare `@`, so the profile wraps the host's
    # line reader and rewrites `@ <target>` into a call to @.exe after the line
    # is read. The screen and history keep what was typed. An older block is
    # replaced in place.
    $profilePath = $PROFILE.CurrentUserCurrentHost
    $block = @'
# >>> @ >>>
# Lets `@ <target>` run @.exe. PowerShell's parser rejects a bare `@`, so the
# line is rewritten after it is read and before it is parsed. The screen and
# history keep what was typed. `@(...)`, `@{...}` and here-strings are left alone.
$readLine = (Get-Command PSConsoleHostReadLine -CommandType Function -ErrorAction SilentlyContinue).ScriptBlock
if ($readLine) {
    Set-Item function:global:PSConsoleHostReadLine -Value {
        $line = & $readLine
        if ($line -match '^\s*@(\s|$)') { $line -replace '^\s*@', "& '@.exe'" } else { $line }
    }.GetNewClosure()
}
Remove-Variable readLine
# <<< @ <<<
'@
    $existing = if (Test-Path $profilePath) { Get-Content -Raw $profilePath } else { '' }
    $pattern = '(?s)# >>> @ >>>.*?# <<< @ <<<'
    if ($existing -match $pattern) {
        $updated = [regex]::Replace($existing, $pattern, { $block })
        Set-Content -Path $profilePath -Value $updated.TrimEnd() -Encoding utf8
        Write-Host "Updated the @ command in $profilePath."
    } else {
        New-Item -ItemType Directory -Force -Path (Split-Path $profilePath) | Out-Null
        Add-Content -Path $profilePath -Value "`r`n$block" -Encoding utf8
        Write-Host "Added the @ command to $profilePath."
    }

    Write-Host ""
    Write-Host "Try it (in a new shell):"
    Write-Host "  @ 127.0.0.1"
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
