#requires -Version 7.0
<#
.SYNOPSIS
  Optional standalone Craft signing entry point. No editor modifications.
.DESCRIPTION
  Office OPC and PDFCraft PDF adapters. QES qualification is not established
  by this entry point. A real certificate must be selected by thumbprint.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Sign','Verify')][string]$Mode,
  [Parameter(Mandatory)][string]$InputPath,
  [string]$OutputPath,
  [string]$CertificateThumbprint,
  [string]$PdfCraftCli
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) { throw 'CRAFT_EXTENSION_INPUT_NOT_FOUND' }
$inputFile = (Resolve-Path -LiteralPath $InputPath).ProviderPath
$ext = [IO.Path]::GetExtension($inputFile).ToLowerInvariant()
if ($ext -notin @('.docx','.xlsx','.pdf')) { throw 'CRAFT_EXTENSION_UNSUPPORTED_FORMAT' }
$adapter = Join-Path $PSScriptRoot $(if ($ext -eq '.pdf') { 'pdfcraft_pades_adapter.ps1' } else { 'office_opc_sign.ps1' })
if (-not (Test-Path -LiteralPath $adapter -PathType Leaf)) { throw 'CRAFT_EXTENSION_ADAPTER_MISSING' }
$arguments = @{ Mode = $Mode; InputPath = $inputFile }
if ($ext -eq '.pdf' -and $PdfCraftCli) { $arguments.PdfCraftCli = $PdfCraftCli }
if ($Mode -eq 'Verify') {
  if ($OutputPath -or $CertificateThumbprint) { throw 'CRAFT_EXTENSION_VERIFY_ARGUMENTS_INVALID' }
} else {
  if ([string]::IsNullOrWhiteSpace($CertificateThumbprint)) { throw 'CRAFT_EXTENSION_CERTIFICATE_REQUIRED' }
  if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $directory = [IO.Path]::GetDirectoryName($inputFile)
    $stem = [IO.Path]::GetFileNameWithoutExtension($inputFile)
    $OutputPath = Join-Path $directory ($stem + '.signed' + $ext)
  }
  $arguments.OutputPath = $OutputPath
  $arguments.CertificateThumbprint = $CertificateThumbprint
}
& $adapter @arguments
if (-not $?) { throw 'CRAFT_EXTENSION_ADAPTER_FAILED' }
