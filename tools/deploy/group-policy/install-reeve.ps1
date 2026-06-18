param(
  [Parameter(Mandatory=$true)][string]$BinaryUrl,
  [Parameter(Mandatory=$true)][string]$ConfigUrl,
  [Parameter(Mandatory=$true)][string]$BundleUrl,
  [Parameter(Mandatory=$true)][string]$SignerIdentityRegexp,
  [Parameter(Mandatory=$true)][string]$BinaryBundleUrl,
  [Parameter(Mandatory=$true)][string]$SignerIssuerRegexp
)

$ErrorActionPreference = "Stop"
$InstallDir = "$env:ProgramFiles\Reeve"
$ConfigDir = "$env:ProgramData\Reeve"
$ScanDir = "$env:ProgramData\Reeve\scans"
$Bin = Join-Path $InstallDir "aibom-cli.exe"

# Verify-ReeveBinary downloads the Reeve binary and its Sigstore bundle to
# temporary paths, cryptographically verifies the binary against the signer
# identity and OIDC issuer regexps, and only on success moves it into its
# final path. It fails closed: a missing cosign.exe, a non-https source, or a
# failed verification all abort the install with a terminating error.
#
# $env:REEVE_ALLOW_INSECURE_URL = "1" relaxes the https-only check for
# hermetic local tests. It NEVER bypasses signature verification.
function Verify-ReeveBinary {
  param(
    [string]$BinUrl,
    [string]$BundleUrl,
    [string]$FinalBin,
    [string]$IdentityRegexp,
    [string]$IssuerRegexp
  )

  if ($env:REEVE_ALLOW_INSECURE_URL -ne "1") {
    if ($BinUrl -notmatch '^https://') {
      throw "reeve: binary URL must be https://, refusing to install: $BinUrl"
    }
  }

  $cosign = Get-Command cosign.exe -ErrorAction SilentlyContinue
  if (-not $cosign) {
    $cosign = Get-Command cosign -ErrorAction SilentlyContinue
  }
  if (-not $cosign) {
    throw "reeve: cosign not found on PATH, refusing to install an unverified binary"
  }

  $tmpDir = Join-Path $env:TEMP ("reeve-verify-" + [System.Guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
  try {
    $tmpBin = Join-Path $tmpDir "aibom-cli.exe"
    $tmpBundle = Join-Path $tmpDir "aibom-cli.sigstore.json"

    Invoke-WebRequest -Uri $BinUrl -OutFile $tmpBin
    Invoke-WebRequest -Uri $BundleUrl -OutFile $tmpBundle

    & $cosign.Source verify-blob `
      --bundle $tmpBundle `
      --certificate-identity-regexp $IdentityRegexp `
      --certificate-oidc-issuer-regexp $IssuerRegexp `
      $tmpBin | Out-Null
    if ($LASTEXITCODE -ne 0) {
      throw "reeve: cosign verify-blob failed for the downloaded binary, refusing to install"
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $FinalBin) | Out-Null
    Move-Item -Force -Path $tmpBin -Destination $FinalBin
  }
  finally {
    Remove-Item -Recurse -Force -Path $tmpDir -ErrorAction SilentlyContinue
  }
}

New-Item -ItemType Directory -Force -Path $InstallDir, $ConfigDir, $ScanDir | Out-Null
Verify-ReeveBinary -BinUrl $BinaryUrl -BundleUrl $BinaryBundleUrl -FinalBin $Bin -IdentityRegexp $SignerIdentityRegexp -IssuerRegexp $SignerIssuerRegexp
Invoke-WebRequest -Uri $ConfigUrl -OutFile (Join-Path $ConfigDir "surfaces.yaml")
Invoke-WebRequest -Uri $BundleUrl -OutFile (Join-Path $ConfigDir "surfaces.yaml.sigstore.json")

$Action = New-ScheduledTaskAction -Execute $Bin -Argument "scan --target $env:USERPROFILE --output-dir `"$ScanDir`" --require-signed-config --signer-identity-regexp `"$SignerIdentityRegexp`" --skip-sign"
$Trigger = New-ScheduledTaskTrigger -Daily -At 2:17AM
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "Reeve Scan" -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null

& $Bin scope list --require-signed-config --signer-identity-regexp $SignerIdentityRegexp | Out-Null
Write-Output "Reeve Group Policy install complete"
