#requires -Version 7.0
<#
.SYNOPSIS
  User-facing standalone signing command for Craft Office documents.
.DESCRIPTION
  Opens an interactive certificate selection dialog for a document-signing
  certificate with an accessible private key. Does not collect token PIN.
  This is NOT a QES or trust-chain verdict.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('Sign','Verify')][string]$Mode,
  [Parameter(Mandatory)][string]$InputPath,
  [string]$OutputPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$entry=Join-Path $PSScriptRoot 'craft_signing_extension.ps1'
if(-not(Test-Path -LiteralPath $entry -PathType Leaf)){throw 'EXTENSION_ENTRY_MISSING'}
if($Mode -eq 'Verify'){
  & $entry -Mode Verify -InputPath $InputPath
  if(-not $?){throw 'VERIFY_FAILED'}
  return
}
if(-not [Environment]::UserInteractive){throw 'INTERACTIVE_SESSION_REQUIRED'}
Add-Type -AssemblyName System.Windows.Forms
$certificates=[Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
foreach($storeLocation in @([Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser,[Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)){
  $store=[Security.Cryptography.X509Certificates.X509Store]::new('My',$storeLocation)
  try {
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    foreach($cert in $store.Certificates){
      if($cert.HasPrivateKey -and $cert.NotBefore -le [DateTime]::Now -and $cert.NotAfter -gt [DateTime]::Now){
        [void]$certificates.Add($cert)
      }
    }
  } finally {$store.Close()}
}
if($certificates.Count -eq 0){throw 'NO_AVAILABLE_PRIVATE_KEY_CERTIFICATE'}
$chosen=[Security.Cryptography.X509Certificates.X509Certificate2UI]::SelectFromCollection(
  $certificates,'Craft Signing Extension','Choose your document signing certificate',
  [Security.Cryptography.X509Certificates.X509SelectionFlag]::SingleSelection)
if($chosen.Count -ne 1){throw 'CERTIFICATE_SELECTION_CANCELLED'}
$args=@{Mode='Sign';InputPath=$InputPath;CertificateThumbprint=$chosen[0].Thumbprint}
if($OutputPath){$args.OutputPath=$OutputPath}
& $entry @args
if(-not $?){throw 'SIGNING_FAILED'}
