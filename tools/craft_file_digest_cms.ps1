#requires -Version 7.0
<#
  Craft reusable file-integrity signature envelope. Works on outputs from
  ANY Craft app without modifying or impersonating the signed upstream EXE.
  CMS attached *manifest* over streamed SHA256; NOT embedded format signature,
  PAdES, CAdES detached-file interoperability, QES, qualified timestamp or
  a Windows installer/code-signing certificate. Provider PIN UI only.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidateSet('sign','verify','list')][string]$Mode,
  [string]$InputFile,
  [string]$SignatureFile,
  [string]$CertificateThumbprint,
  [System.Security.Cryptography.X509Certificates.X509Certificate2]$DevelopmentCertificate
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security.Cryptography.Pkcs

function Get-HashStream([string]$Path) {
  $sha=[Security.Cryptography.SHA256]::Create()
  $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try {
    $len=$stream.Length
    $digest=[Convert]::ToHexString($sha.ComputeHash($stream)).ToLowerInvariant()
    return [pscustomobject]@{hash=$digest;size=$len}
  } finally {$stream.Dispose();$sha.Dispose()}
}
function Refuse-Reparse([string]$Path) {
  $full=[IO.Path]::GetFullPath($Path)
  if (-not [IO.File]::Exists($full)) { throw 'INPUT_NOT_FOUND' }
  $attributes=[IO.File]::GetAttributes($full)
  if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'REPARSE_INPUT_REJECTED' }
  return $full
}
function Find-Identity([string]$Thumbprint) {
  if ($Thumbprint -cnotmatch '^[0-9a-fA-F]{40}$') { throw 'EXACT_CERTIFICATE_SHA1_REFERENCE_REQUIRED' }
  $store=[Security.Cryptography.X509Certificates.X509Store]::new(
     [Security.Cryptography.X509Certificates.StoreName]::My,
     [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
  try {
    $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $matches=@($store.Certificates | Where-Object {
      $_.Thumbprint -ieq $Thumbprint -and $_.HasPrivateKey
    })
    if ($matches.Count -ne 1) { throw 'SIGNER_MUST_BE_UNIQUE_IN_CURRENT_USER_MY_WITH_PRIVATE_KEY' }
    return [Security.Cryptography.X509Certificates.X509Certificate2]::new($matches[0])
  } finally {$store.Close()}
}
function Result([hashtable]$Data) {
  $Data['eidas_qes']='NOT_CHECKED'
  $Data['tsa_qualified']='NOT_CHECKED'
  $Data['trusted_chain_and_revocation']='NOT_CHECKED'
  $Data['file_format_embedded_signature']= $false
  $Data['signed_msi']='NOT_APPLICABLE'
  $Data['qualified_release_ready']=$false
  $Data|ConvertTo-Json -Compress -Depth 6
}
if ($Mode -eq 'list') {
  if ($InputFile -or $SignatureFile -or $CertificateThumbprint -or $DevelopmentCertificate) {
    throw 'LIST_MODE_TAKES_NO_FILE_OR_CREDENTIAL_ARGUMENTS'
  }
  $store=[Security.Cryptography.X509Certificates.X509Store]::new('My','CurrentUser')
  try {
    $store.Open('ReadOnly')
    $row=@($store.Certificates | Where-Object HasPrivateKey | ForEach-Object {
      [pscustomobject]@{subject=$_.Subject;thumbprint_sha1=$_.Thumbprint;
        not_after_utc=$_.NotAfter.ToUniversalTime().ToString('o');
        private_key_exported=$false}
    })
    $row|ConvertTo-Json -Compress -Depth 5
  } finally {$store.Close()}
  return
}
if (-not $InputFile) { throw 'INPUT_FILE_REQUIRED' }
$source=Refuse-Reparse $InputFile
$defaultSig=$source+'.craftsig.p7m'
if (-not $SignatureFile) {$SignatureFile=$defaultSig}
$sigPath=[IO.Path]::GetFullPath($SignatureFile)
if ([StringComparer]::OrdinalIgnoreCase.Equals($source,$sigPath)) { throw 'OUTPUT_EQUALS_SOURCE_REFUSED' }
if ($Mode -eq 'sign') {
  if ([IO.File]::Exists($sigPath)) { throw 'EXISTING_SIGNATURE_REFUSED_NO_OVERWRITE' }
  if ($CertificateThumbprint -and $DevelopmentCertificate) {throw 'AMBIGUOUS_CERTIFICATE_SELECTION'}
  if (-not $CertificateThumbprint -and -not $DevelopmentCertificate) {throw 'CERTIFICATE_SELECTION_REQUIRED'}
  $cert=if ($DevelopmentCertificate) {$DevelopmentCertificate} else {Find-Identity $CertificateThumbprint}
  if (-not $cert.HasPrivateKey) {throw 'SIGNING_PRIVATE_KEY_NOT_AVAILABLE'}
  $now=[DateTime]::UtcNow
  if ($now -lt $cert.NotBefore.ToUniversalTime() -or $now -gt $cert.NotAfter.ToUniversalTime()) {
    throw 'CERTIFICATE_OUTSIDE_VALIDITY_PERIOD'
  }
  $before=Get-HashStream $source
  $data=[ordered]@{
    schema='craft.file-digest-envelope.v1'
    file_name=[IO.Path]::GetFileName($source)
    length_bytes=$before.size
    sha256=$before.hash
    hash_algorithm='SHA-256'
    claimed_signing_time_utc=[DateTime]::UtcNow.ToString('o')
    time_is_trusted=$false
    content_type='hash-manifest-not-native-file-signature'
  }
  $bytes=[Text.Encoding]::UTF8.GetBytes(($data|ConvertTo-Json -Compress -Depth 4))
  $cms=[Security.Cryptography.Pkcs.SignedCms]::new(
      [Security.Cryptography.Pkcs.ContentInfo]::new($bytes),$false)
  $signer=[Security.Cryptography.Pkcs.CmsSigner]::new(
      [Security.Cryptography.Pkcs.SubjectIdentifierType]::IssuerAndSerialNumber,$cert)
  $signer.DigestAlgorithm=[Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
  $signer.IncludeOption=[Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
  # Explicit user invocation; Windows CSP/CNG provider handles PIN interaction.
  $cms.ComputeSignature($signer,$false)
  $after=Get-HashStream $source
  if ($after.hash -cne $before.hash -or $after.size -ne $before.size) {
     throw 'SOURCE_CHANGED_DURING_SIGNING_REFUSED'
  }
  $encoded=$cms.Encode()
  if ($encoded.Length -gt 1048576) {throw 'CMS_ENVELOPE_TOO_LARGE'}
  $written=$false
  try {
    $f=[IO.File]::Open($sigPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {$f.Write($encoded,0,$encoded.Length);$f.Flush($true);$written=$true}
    finally {$f.Dispose()}
  } finally {
    if (-not $written -and [IO.File]::Exists($sigPath)) {[IO.File]::Delete($sigPath)}
  }
  Result @{schema='craft.file-digest-signature-result.v1';mode='sign';
    source=$source;envelope=$sigPath;file_sha256=$before.hash;file_bytes=$before.size;
    cms_signature_created=$true;independently_verified=$false}
  return
}
if ($CertificateThumbprint -or $DevelopmentCertificate) {throw 'VERIFY_MODE_MUST_NOT_SELECT_PRIVATE_KEY'}
if (-not [IO.File]::Exists($sigPath)) {throw 'SIGNATURE_ENVELOPE_NOT_FOUND'}
$info=[IO.FileInfo]::new($sigPath)
if ($info.Length -lt 100 -or $info.Length -gt 1048576) {throw 'INVALID_ENVELOPE_LENGTH'}
$bytes=[IO.File]::ReadAllBytes($sigPath)
$cms=[Security.Cryptography.Pkcs.SignedCms]::new()
$cms.Decode($bytes)
if ($cms.Detached -or $cms.SignerInfos.Count -ne 1) {throw 'EXPECTED_ONE_ATTACHED_CMS_MANIFEST_SIGNER'}
$cms.CheckSignature($true) # Cryptographic only; not certificate-chain validation.
$manifest=[Text.Encoding]::UTF8.GetString($cms.ContentInfo.Content)|ConvertFrom-Json -Depth 10
if ($manifest.schema -cne 'craft.file-digest-envelope.v1' -or
    $manifest.hash_algorithm -cne 'SHA-256' -or
    $manifest.content_type -cne 'hash-manifest-not-native-file-signature' -or
    $manifest.time_is_trusted -ne $false) {throw 'UNRECOGNIZED_OR_UNSAFE_MANIFEST'}
if ($manifest.file_name -cne [IO.Path]::GetFileName($source)) {throw 'SOURCE_FILE_NAME_MISMATCH'}
if ($manifest.sha256 -cnotmatch '^[a-f0-9]{64}$') {throw 'INVALID_SHA256_MANIFEST'}
$actual=Get-HashStream $source
if ($actual.size -ne [long]$manifest.length_bytes -or $actual.hash -cne [string]$manifest.sha256) {
  throw 'SIGNED_FILE_CONTENT_MISMATCH'
}
Result @{schema='craft.file-digest-signature-result.v1';mode='verify';
  source=$source;envelope=$sigPath;file_sha256=$actual.hash;file_bytes=$actual.size;
  cms_crypto_signature='PASS';file_hash_binding='PASS';publisher_certificate_trust='NOT_CHECKED'}
