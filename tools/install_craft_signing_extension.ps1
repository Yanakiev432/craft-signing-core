#requires -Version 7.0
<#
  Per-user development installer for the optional Craft Signing Extension.
  This is NOT a trusted MSI and does not alter existing Craft editors.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [ValidateSet('Install','Uninstall')][string]$Mode='Install',
  [string]$Destination=(Join-Path $env:LOCALAPPDATA 'Programs\CraftSigningExtension'),
  [string]$SendToDirectory=(Join-Path $env:APPDATA 'Microsoft\Windows\SendTo')
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$destinationFull=[IO.Path]::GetFullPath($Destination)
$sendToFull=[IO.Path]::GetFullPath($SendToDirectory)
$shortcut=Join-Path $sendToFull 'Craft Signing Extension (verify).lnk'
$files=@('craft_signing_extension.ps1','office_opc_sign.ps1')
if($Mode -eq 'Install') {
  foreach($name in $files) {
    if(-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $name) -PathType Leaf)) { throw "MISSING_SOURCE:$name" }
  }
  if(-not (Get-Command pwsh.exe -ErrorAction SilentlyContinue)) { throw 'POWERSHELL_7_REQUIRED' }
  if($PSCmdlet.ShouldProcess($destinationFull,'Install optional extension')) {
    [void][IO.Directory]::CreateDirectory($destinationFull)
    [void][IO.Directory]::CreateDirectory($sendToFull)
    foreach($name in $files) {
      Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $destinationFull $name) -Force
    }
    # Verification is read-only; signing requires explicit thumbprint and is CLI-only in v1.
    $shell=New-Object -ComObject WScript.Shell
    $link=$shell.CreateShortcut($shortcut)
    $link.TargetPath=(Get-Command pwsh.exe).Source
    $link.Arguments='-NoProfile -NonInteractive -File "'+(Join-Path $destinationFull 'craft_signing_extension.ps1')+'" -Mode Verify -InputPath'
    $link.Description='Verify existing OPC signatures in DOCX/XLSX (not a QES verdict)'
    $link.WorkingDirectory=$destinationFull
    $link.Save()
    [pscustomobject]@{result='INSTALLED_DEVELOPMENT_ONLY';path=$destinationFull;sendto=$shortcut;editor_binaries_modified=$false}
  }
} else {
  if($PSCmdlet.ShouldProcess($destinationFull,'Uninstall optional extension')) {
    # Only remove our own known files; never delete the entire directory or user documents.
    if(Test-Path -LiteralPath $shortcut -PathType Leaf) { Remove-Item -LiteralPath $shortcut -Force }
    foreach($name in $files) {
      $path=Join-Path $destinationFull $name
      if(Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force }
    }
    [pscustomobject]@{result='UNINSTALLED_EXTENSION_FILES';path=$destinationFull;editor_binaries_modified=$false}
  }
}
