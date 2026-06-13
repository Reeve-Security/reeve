param(
  [Parameter(Mandatory=$true)][string]$BinaryUrl,
  [Parameter(Mandatory=$true)][string]$ConfigUrl,
  [Parameter(Mandatory=$true)][string]$BundleUrl,
  [Parameter(Mandatory=$true)][string]$SignerIdentityRegexp
)

$ErrorActionPreference = "Stop"
$InstallDir = "$env:ProgramFiles\Reeve"
$ConfigDir = "$env:ProgramData\Reeve"
$ScanDir = "$env:ProgramData\Reeve\scans"
$Bin = Join-Path $InstallDir "aibom-cli.exe"

New-Item -ItemType Directory -Force -Path $InstallDir, $ConfigDir, $ScanDir | Out-Null
Invoke-WebRequest -Uri $BinaryUrl -OutFile $Bin
Invoke-WebRequest -Uri $ConfigUrl -OutFile (Join-Path $ConfigDir "surfaces.yaml")
Invoke-WebRequest -Uri $BundleUrl -OutFile (Join-Path $ConfigDir "surfaces.yaml.sigstore.json")

$Action = New-ScheduledTaskAction -Execute $Bin -Argument "scan --target $env:USERPROFILE --output-dir `"$ScanDir`" --require-signed-config --signer-identity-regexp `"$SignerIdentityRegexp`" --skip-sign"
$Trigger = New-ScheduledTaskTrigger -Daily -At 2:17AM
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "Reeve Scan" -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null

& $Bin scope list --require-signed-config --signer-identity-regexp $SignerIdentityRegexp | Out-Null
Write-Output "Reeve Group Policy install complete"
