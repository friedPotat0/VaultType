<#
  Builds a signed MSIX package of VaultType (self-contained x64) so it can act as a Windows 11
  passkey plugin provider. Dev-signed with a self-signed certificate.

  Usage (from the repo root, in an elevated-ish PowerShell for cert trust):
      pwsh packaging/msix/build-msix.ps1
      # then, once, trust the dev cert and install:
      #   Import-Certificate -FilePath packaging/msix/out/VaultType-dev.cer -CertStoreLocation Cert:\LocalMachine\TrustedPeople
      #   Add-AppxPackage packaging/msix/out/VaultType.msix

  Requires: .NET SDK, Windows SDK (makeappx.exe + signtool.exe, found automatically).
#>
[CmdletBinding()]
param(
  [string]$Configuration = "Release",
  [string]$Runtime = "win-x64",
  # Store mode: stamp the Partner Center product identity into the manifest and leave the
  # package unsigned - the Microsoft Store signs it during certification.
  [switch]$Store,
  # Package version (x.y.z.n); the Store requires the fourth part to be 0.
  [string]$Version = ""
)
$ErrorActionPreference = "Stop"
# Fail fast, before the (slow) publish: the Store only accepts x.y.z.0 package versions.
if ($Store -and $Version -and $Version -notmatch '^\d+\.\d+\.\d+\.0$') {
  throw "Store packages need a version of the form x.y.z.0 (got '$Version')."
}
$root      = (Resolve-Path "$PSScriptRoot\..\..").Path
$proj      = Join-Path $root "src\VaultType\VaultType.csproj"
$stage     = Join-Path $PSScriptRoot "stage"
$out       = Join-Path $PSScriptRoot "out"
$assetsSrc = Join-Path $root "assets\png"
$manifest  = Join-Path $PSScriptRoot "AppxManifest.xml"

# --- locate Windows SDK tools ---
function Find-SdkTool($name) {
  $binRoot = "C:\Program Files (x86)\Windows Kits\10\bin"
  Get-ChildItem $binRoot -Directory | Sort-Object Name -Descending | ForEach-Object {
    $p = Join-Path $_.FullName "x64\$name"
    if (Test-Path $p) { return $p }
  } | Select-Object -First 1
}
$makeappx = Find-SdkTool "makeappx.exe"
$signtool = Find-SdkTool "signtool.exe"
if (-not $makeappx) { throw "makeappx.exe not found - install the Windows SDK." }

# --- publish the app (self-contained so the package needs no separate runtime) ---
Write-Host "Publishing $Runtime ($Configuration)..."
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path $stage, $out | Out-Null
# Stamp the assembly version too (x.y.z of the package version) so the in-app version matches.
$asmVersion = if ($Version) { ($Version -split '\.')[0..2] -join '.' } else { $null }
$versionArg = if ($asmVersion) { "-p:Version=$asmVersion" } else { $null }
dotnet publish $proj -c $Configuration -r $Runtime --self-contained true `
  -p:PublishSingleFile=false $versionArg -o $stage | Out-Null

# --- manifest + assets ---
Copy-Item $manifest (Join-Path $stage "AppxManifest.xml") -Force
# license + third-party notices ship in every distributed copy (OFL/MIT requirement)
Copy-Item (Join-Path $root "LICENSE") $stage -Force
Copy-Item (Join-Path $root "THIRD-PARTY-NOTICES.md") $stage -Force

# --- stamp identity ---
$stagedManifest = Join-Path $stage "AppxManifest.xml"
$doc = [xml](Get-Content $stagedManifest -Raw)
if ($Store) {
  # Partner Center product identity (Apps and Games > VaultType > Product identity).
  # These are public identifiers, not secrets.
  $doc.Package.Identity.Name = "friedPotat0.VaultType"
  $doc.Package.Identity.Publisher = "CN=4B8578C4-7424-4939-B9D2-9E164B6F10A5"
  $doc.Package.Properties.PublisherDisplayName = "friedPotat0"
}
if ($Version) { $doc.Package.Identity.Version = $Version }
$doc.Save($stagedManifest)
$assets = Join-Path $stage "Assets"
New-Item -ItemType Directory -Force -Path $assets | Out-Null
# reuse the existing app icons for the required tile logos (dev packaging; exact sizes not enforced)
$map = @{
  "Square44x44Logo.png"   = "vaulttype-48.png"
  "Square71x71Logo.png"   = "vaulttype-64.png"
  "Square150x150Logo.png" = "vaulttype-128.png"
  "Square310x310Logo.png" = "vaulttype-256.png"
  "Wide310x150Logo.png"   = "vaulttype-256.png"
  "StoreLogo.png"         = "vaulttype-48.png"
}
foreach ($k in $map.Keys) { Copy-Item (Join-Path $assetsSrc $map[$k]) (Join-Path $assets $k) -Force }

# --- pack ---
$msix = Join-Path $out $(if ($Store) { "VaultType-Store.msix" } else { "VaultType.msix" })
if (Test-Path $msix) { Remove-Item $msix -Force }
Write-Host "Packing MSIX..."
& $makeappx pack /o /d $stage /p $msix | Out-Null

if ($Store) {
  Write-Host ""
  Write-Host "Done (Store mode, unsigned):"
  Write-Host "  Package: $msix"
  Write-Host "  Upload via Partner Center or 'msstore publish'."
  return
}

# --- self-signed dev cert (subject must equal the manifest Publisher) ---
$subject = "CN=VaultType Dev"
$cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $subject } | Select-Object -First 1
if (-not $cert) {
  Write-Host "Creating self-signed dev certificate..."
  $cert = New-SelfSignedCertificate -Type Custom -Subject $subject -KeyUsage DigitalSignature `
    -FriendlyName "VaultType Dev" -CertStoreLocation "Cert:\CurrentUser\My" `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
}
$cer = Join-Path $out "VaultType-dev.cer"
Export-Certificate -Cert $cert -FilePath $cer | Out-Null

# --- sign (timestamp is best-effort; a dev signature without one still installs) ---
if ($signtool) {
  Write-Host "Signing..."
  & $signtool sign /fd SHA256 /sha1 $cert.Thumbprint /t http://timestamp.digicert.com $msix 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "Timestamping failed (offline?) - signing without a timestamp."
    & $signtool sign /fd SHA256 /sha1 $cert.Thumbprint $msix | Out-Null
  }
} else {
  Write-Warning "signtool.exe not found - package left unsigned."
}

Write-Host ""
Write-Host "Done:"
Write-Host "  Package: $msix"
Write-Host "  Dev cert: $cer"
Write-Host ""
Write-Host "To install (once, elevated for the cert):"
Write-Host "  Import-Certificate -FilePath `"$cer`" -CertStoreLocation Cert:\LocalMachine\TrustedPeople"
Write-Host "  Add-AppxPackage `"$msix`""
