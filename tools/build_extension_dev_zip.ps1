#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$names=@('craft_signing_extension.ps1','craft_signing_interactive.ps1','office_opc_sign.ps1','opc_signature_windows.ps1','pdfcraft_pades_adapter.ps1','install_craft_signing_extension_v2.ps1')
foreach($name in $names){if(-not(Test-Path -LiteralPath (Join-Path $PSScriptRoot $name) -PathType Leaf)){throw "MISSING_FILE:$name"}}
[void][IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($OutputDirectory))
$zip=Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) 'CraftSigningExtension-DEV.zip'
if(Test-Path -LiteralPath $zip){throw 'REFUSE_OVERWRITE_EXISTING_ARCHIVE'}
$stage=Join-Path ([IO.Path]::GetTempPath()) ('craft-signing-stage-'+[Guid]::NewGuid().ToString('N'))
try{
 [void][IO.Directory]::CreateDirectory($stage)
 foreach($name in $names){Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination (Join-Path $stage $name)}
 Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal
 $sha=(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash
 [pscustomobject]@{status='UNSIGNED_DEVELOPMENT_ARCHIVE';path=$zip;sha256=$sha;files=$names.Count}|ConvertTo-Json -Compress
} finally {
 if(Test-Path -LiteralPath $stage){Remove-Item -LiteralPath $stage -Recurse -Force}
}
