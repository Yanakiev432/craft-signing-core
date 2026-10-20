#requires -Version 7.0
<#
  Reversible per-user development deployment, not a signed MSI.
  Does not patch PDFCraft, WordCraft or GridCraft.
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
$files=@('craft_signing_extension.ps1','craft_signing_interactive.ps1','office_opc_sign.ps1')
$links=@(
  @{Name='Craft Signing Extension - Sign.lnk';Mode='Sign'},
  @{Name='Craft Signing Extension - Verify.lnk';Mode='Verify'}
)
if($Mode -eq 'Install'){
  foreach($name in $files){
    if(-not(Test-Path -LiteralPath (Join-Path $PSScriptRoot $name) -PathType Leaf)){throw "SOURCE_MISSING:$name"}
  }
  $pwsh=(Get-Command pwsh.exe -ErrorAction Stop).Source
  if($PSCmdlet.ShouldProcess($destinationFull,'Install optional signing extension')){
    [void][IO.Directory]::CreateDirectory($destinationFull)
    [void][IO.Directory]::CreateDirectory($sendToFull)
    foreach($name in $files){
      $target=Join-Path $destinationFull $name
      if(Test-Path -LiteralPath $target -PathType Leaf){throw "REFUSE_OVERWRITE:$target"}
      Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $target
    }
    $shell=New-Object -ComObject WScript.Shell
    foreach($linkInfo in $links){
      $shortcut=Join-Path $sendToFull $linkInfo.Name
      if(Test-Path -LiteralPath $shortcut){throw "REFUSE_EXISTING_SHORTCUT:$shortcut"}
      $link=$shell.CreateShortcut($shortcut)
      $link.TargetPath=$pwsh
      $link.Arguments='-NoProfile -File "'+(Join-Path $destinationFull 'craft_signing_interactive.ps1')+'" -Mode '+$linkInfo.Mode+' -InputPath'
      $link.Description='Craft optional document signature '+$linkInfo.Mode
      $link.WorkingDirectory=$destinationFull
      $link.Save()
    }
    [pscustomobject]@{status='DEVELOPMENT_INSTALL';path=$destinationFull;editors_modified=$false}
  }
} else {
  if($PSCmdlet.ShouldProcess($destinationFull,'Remove optional signing extension')){
    foreach($linkInfo in $links){
      $shortcut=Join-Path $sendToFull $linkInfo.Name
      if(Test-Path -LiteralPath $shortcut -PathType Leaf){
        $shell=New-Object -ComObject WScript.Shell
        $link=$shell.CreateShortcut($shortcut)
        if($link.Arguments -notlike ('*'+(Join-Path $destinationFull 'craft_signing_interactive.ps1')+'*')){throw "REFUSE_FOREIGN_SHORTCUT:$shortcut"}
        Remove-Item -LiteralPath $shortcut -Force
      }
    }
    foreach($name in $files){
      $target=Join-Path $destinationFull $name
      if(Test-Path -LiteralPath $target -PathType Leaf){Remove-Item -LiteralPath $target -Force}
    }
    [pscustomobject]@{status='DEVELOPMENT_UNINSTALL';editors_modified=$false}
  }
}
