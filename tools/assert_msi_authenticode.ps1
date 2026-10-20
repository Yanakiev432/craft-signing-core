#requires -Version 7.0
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$MsiPath,
 [string]$ExpectedSha256,
 [switch]$RequireTrustedSignature
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not(Test-Path -LiteralPath $MsiPath -PathType Leaf)){throw 'MSI_NOT_FOUND'}
$path=(Resolve-Path -LiteralPath $MsiPath).ProviderPath
$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
if($ExpectedSha256 -and $hash -ne $ExpectedSha256){throw 'MSI_SHA256_MISMATCH'}
$sig=Get-AuthenticodeSignature -LiteralPath $path
$valid=($sig.Status -eq 'Valid')
$signer=if($sig.SignerCertificate){$sig.SignerCertificate.Subject}else{$null}
$report=[ordered]@{
 schema='craft.msi.signature-gate.v1'
 path=$path
 sha256=$hash
 authenticode_status=$sig.Status.ToString()
 signer_subject=$signer
 trusted_signature=if($valid){'PASS'}else{'FAIL'}
 public_release=if($valid){'SIGNATURE_GATE_PASS_ONLY'}else{'NO_GO'}
}
$report|ConvertTo-Json -Compress
if($RequireTrustedSignature -and -not $valid){exit 4}
