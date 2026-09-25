<#
.SYNOPSIS
  Put the llama.cpp runtime the desktop app ships with into
  desktop/src-tauri/llama.

.DESCRIPTION
  Downloads a pinned llama.cpp release from github.com/ggml-org/llama.cpp,
  checks it against the SHA-256 digest recorded below, and copies
  llama-server with the libraries it loads. Nothing else from the release is
  bundled.

  -From copies from an existing install of the same build instead of
  downloading, for example a winget install of llama.cpp.

.EXAMPLE
  ./scripts/fetch-llama.ps1
.EXAMPLE
  ./scripts/fetch-llama.ps1 -From "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\ggml.llamacpp_Microsoft.Winget.Source_8wekyb3d8bbwe"
#>
param(
  [string]$Tag = "b11026",
  [ValidateSet("vulkan", "cpu")]
  [string]$Variant = "vulkan",
  [string]$From = ""
)

$ErrorActionPreference = "Stop"

# Digests of the release assets, as GitHub publishes them for this tag. A
# different tag needs its digest added here; nothing unpinned is bundled.
$Digests = @{
  "llama-b11026-bin-win-vulkan-x64.zip" = "ceb83d677cedbc7ec427f157adbc93da82d8fdc336d8b105152568a3be98bb18"
}

$Root = Split-Path -Parent $PSScriptRoot
$Dest = Join-Path $Root "desktop/src-tauri/llama"

if ($From) {
  $Source = (Resolve-Path $From).Path
  $Origin = "copied from $Source"
} else {
  $Asset = "llama-$Tag-bin-win-$Variant-x64.zip"
  if (-not $Digests.ContainsKey($Asset)) {
    throw "No pinned digest for $Asset. Add it to `$Digests before bundling a new build."
  }
  $Url = "https://github.com/ggml-org/llama.cpp/releases/download/$Tag/$Asset"
  $Work = Join-Path ([IO.Path]::GetTempPath()) "cordon-llama-$Tag"
  New-Item -ItemType Directory -Force $Work | Out-Null
  $Zip = Join-Path $Work $Asset
  Write-Host "Downloading $Url"
  Invoke-WebRequest -Uri $Url -OutFile $Zip -UseBasicParsing
  $Actual = (Get-FileHash -Algorithm SHA256 $Zip).Hash.ToLower()
  if ($Actual -ne $Digests[$Asset]) {
    throw "Digest mismatch for ${Asset}: expected $($Digests[$Asset]), got $Actual"
  }
  $Source = Join-Path $Work "extract"
  if (Test-Path $Source) { Remove-Item -Recurse -Force $Source }
  Expand-Archive -Path $Zip -DestinationPath $Source
  $Server = Get-ChildItem -Path $Source -Recurse -Filter "llama-server.exe" | Select-Object -First 1
  if (-not $Server) { throw "The archive has no llama-server.exe" }
  $Source = $Server.DirectoryName
  $Origin = "$Asset (sha256 $Actual)"
}

if (-not (Test-Path (Join-Path $Source "llama-server.exe"))) {
  throw "No llama-server.exe in $Source"
}

if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }
New-Item -ItemType Directory -Force $Dest | Out-Null

# The server, and every library except the ones other llama.cpp tools
# (llama-cli, llama-bench, ...) link: those are `<tool>-impl.dll`.
Copy-Item (Join-Path $Source "llama-server.exe") $Dest
Get-ChildItem -Path $Source -Filter "*.dll" |
  Where-Object { $_.Name -notlike "*-impl.dll" -or $_.Name -eq "llama-server-impl.dll" } |
  ForEach-Object { Copy-Item $_.FullName $Dest }
Get-ChildItem -Path $Source -Filter "LICENSE*" | ForEach-Object { Copy-Item $_.FullName $Dest }
Copy-Item (Join-Path $PSScriptRoot "llama-LICENSE.txt") (Join-Path $Dest "LICENSE-llama.cpp.txt")

$Provenance = @"
llama.cpp $Tag ($Variant), bundled with Cordon.
Source: https://github.com/ggml-org/llama.cpp/releases/tag/$Tag
Origin: $Origin
"@
# Written without a byte-order mark, which Windows PowerShell's utf8 adds.
[IO.File]::WriteAllText((Join-Path $Dest "BUNDLED.txt"), $Provenance + "`n")

# llama-server prints its version on stderr. Windows PowerShell turns native
# stderr into error records, which `Stop` would make fatal, so this one call
# runs under `Continue`.
$ErrorActionPreference = "Continue"
$Version = & (Join-Path $Dest "llama-server.exe") --version 2>&1 | ForEach-Object { "$_" } | Select-String "version"
Write-Host "Bundled into ${Dest}: $Version"
