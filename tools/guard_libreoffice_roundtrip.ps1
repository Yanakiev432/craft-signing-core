#requires -Version 7.0
<#
.SYNOPSIS
  Read-only guard for LibreOffice round-trip of signed DOCX/XLSX.
.DESCRIPTION
  Inspect original OOXML package signature parts. Reject overwriting a signed
  input or treating a converted LibreOffice output as signature-preserving.
  Never modifies the input document.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$InputPath,
 [string]$OutputPath,
 [switch]$AllowUnsignedInput
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not(Test-Path -LiteralPath $InputPath -PathType Leaf)){throw 'INPUT_NOT_FOUND'}
$ext=[IO.Path]::GetExtension($InputPath).ToLowerInvariant()
if($ext -notin @('.docx','.xlsx')){throw 'UNSUPPORTED_OFFICE_FORMAT'}
Add-Type -AssemblyName System.IO.Compression
$zip=[IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $InputPath).ProviderPath)
try{
 $parts=@($zip.Entries|Where-Object {$_.FullName -match '^(?i:package/services/digital-signature/|_xmlsignatures/)'})
}finally{$zip.Dispose()}
$isSigned=$parts.Count -gt 0
if($OutputPath -and [IO.Path]::GetFullPath($InputPath) -eq [IO.Path]::GetFullPath($OutputPath)){throw 'REFUSE_IN_PLACE_OFFICE_RESAVE'}
if($isSigned -and -not $AllowUnsignedInput){
 [pscustomobject]@{status='SIGNED_INPUT_PROTECT';signature_parts=$parts.Count;input=(Resolve-Path -LiteralPath $InputPath).ProviderPath;policy='Do not round-trip or overwrite signed Office documents in LibreOffice'}|ConvertTo-Json -Compress
 exit 3
}
[pscustomobject]@{status='UNSIGNED_INPUT';signature_parts=$parts.Count;input=(Resolve-Path -LiteralPath $InputPath).ProviderPath}|ConvertTo-Json -Compress
