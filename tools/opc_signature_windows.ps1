#requires -Version 5.1
<#
.SYNOPSIS
  Opt-in OPC/XMLDSig signing or integrity verification for DOCX and XLSX.
.DESCRIPTION
  WindowsBase PackageDigitalSignatureManager reference implementation.
  Uses an explicitly selected CurrentUser\\My certificate; private key
  operations remain with Windows CSP/CNG and token PIN UI, never this script.
  Cryptographic integrity != EU qualified status, revocation or trust.
  This tool is not a Microsoft Word/Excel interoperability certification.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('sign','verify')]
    [string]$Mode,
    [Parameter(Mandatory=$true)]
    [string]$InputFile,
    [string]$OutputFile,
    [string]$CertificateThumbprint,
    # In-memory test identity for disposable fixtures; never used by app CLIs.
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$DevelopmentCertificate
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName WindowsBase

function Inspect-OfficePackage([System.IO.Packaging.Package]$Package, [string]$Ext) {
    $types = @(
        'http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument',
        'http://purl.oclc.org/ooxml/officeDocument/relationships/officeDocument'
    )
    $found = $false
    $mainUri = $null
    foreach ($relationType in $types) {
        foreach ($relation in $Package.GetRelationshipsByType($relationType)) {
            if ($relation.TargetMode -ne [System.IO.Packaging.TargetMode]::Internal) { continue }
            $resolved = [System.IO.Packaging.PackUriHelper]::ResolvePartUri(
                [System.Uri]::new('/', [System.UriKind]::Relative), $relation.TargetUri
            )
            if ($Package.PartExists($resolved)) {
                $name = $resolved.OriginalString
                if (($Ext -eq '.docx' -and $name.StartsWith('/word/')) -or
                    ($Ext -eq '.xlsx' -and $name.StartsWith('/xl/'))) {
                    $mainUri = $resolved
                    $found = $true
                }
            }
        }
    }
    if (-not $found) { throw 'Invalid DOCX/XLSX: missing valid internal officeDocument relationship/main part' }
    return $mainUri.OriginalString
}

function Read-SignatureState([System.IO.Packaging.Package]$Package, [string]$Ext) {
    $main = Inspect-OfficePackage -Package $Package -Ext $Ext
    $manager = [System.IO.Packaging.PackageDigitalSignatureManager]::new($Package)
    $count = $manager.Signatures.Count
    if ($count -lt 1) { throw 'No OPC signature in package' }
    $verdict = $manager.VerifySignatures($false)
    $covered = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $generatedSignatureParts = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    [void]$generatedSignatureParts.Add($manager.SignatureOrigin.OriginalString)
    foreach ($signature in $manager.Signatures) {
        foreach ($partUri in $signature.SignedParts) { [void]$covered.Add($partUri.OriginalString) }
        # Exclude only the *exact* OPC signature blobs we know about, not an
        # entire directory whose contents might be attacker-supplied.
        [void]$generatedSignatureParts.Add($signature.SignaturePart.Uri.OriginalString)
    }
    $missing = @()
    foreach ($part in $Package.GetParts()) {
        $uri = $part.Uri.OriginalString
        if ($generatedSignatureParts.Contains($uri)) { continue }
        if (-not $covered.Contains($uri)) { $missing += $uri }
    }
    $ok = $verdict -eq [System.IO.Packaging.VerifyResult]::Success -and $missing.Count -eq 0
    [pscustomobject]@{
        schema = 'craft.opc.xml-dsig.validation.v1'
        file_type = $Ext.TrimStart('.')
        main_part = $main
        signature_count = $count
        signature_integrity = $verdict.ToString()
        unsigned_content_parts = @($missing)
        signed_parts_count = $covered.Count
        integrity_pass = [bool]$ok
        issuer_trust = 'NOT_EVALUATED'
        eidas_qes = 'NOT_EVALUATED'
        qualified_timestamp = 'NOT_EVALUATED'
    }
}

if (-not (Test-Path -LiteralPath $InputFile -PathType Leaf)) { throw 'Input file does not exist' }
$inputPath = [IO.Path]::GetFullPath($InputFile)
$ext = [IO.Path]::GetExtension($inputPath).ToLowerInvariant()
if ($ext -notin @('.docx','.xlsx')) { throw 'Only OPC DOCX and XLSX are supported' }
if ($Mode -eq 'verify') {
    if ($OutputFile -or $CertificateThumbprint -or $DevelopmentCertificate) { throw 'Verify mode accepts no signing/output parameters' }
    $package = [System.IO.Packaging.Package]::Open($inputPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $state = Read-SignatureState -Package $package -Ext $ext
    } finally { $package.Close() }
    $state | ConvertTo-Json -Depth 6 -Compress
    if (-not $state.integrity_pass) { exit 1 }
    exit 0
}
if (-not $OutputFile) { throw 'Signing requires an explicit distinct output file' }
if ($null -eq $DevelopmentCertificate -and $CertificateThumbprint -notmatch '^[0-9a-fA-F]{40}$') { throw 'Signing requires a concrete 40-hex certificate thumbprint' }
if ($null -ne $DevelopmentCertificate -and $CertificateThumbprint) { throw 'Specify either test certificate or production thumbprint, never both' }
$outPath = [IO.Path]::GetFullPath($OutputFile)
if ([IO.Path]::GetExtension($outPath).ToLowerInvariant() -ne $ext) { throw 'Source and output document extensions must match' }
if ([StringComparer]::OrdinalIgnoreCase.Equals($inputPath,$outPath)) { throw 'Refusing in-place modification of original document' }
if (Test-Path -LiteralPath $outPath) { throw 'Refusing to overwrite an existing output file' }
$cert = $DevelopmentCertificate
if ($null -eq $cert) {
    # GitHub Windows runners and hardened hosts may not mount the Cert: PSDrive.
    # Open only the Windows CurrentUser/My X509Store through .NET instead.
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $matches = @($store.Certificates | Where-Object { $_.Thumbprint -eq $CertificateThumbprint })
        if ($matches.Count -ne 1) { throw 'Selected certificate not found uniquely in Windows CurrentUser/My' }
        # Clone the certificate context so it survives store.Close() without
        # exporting or loading any private-key bytes into this process.
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($matches[0])
    } finally { $store.Close() }
}
if (-not $cert.HasPrivateKey) { throw 'Selected certificate has no signing key' }
$now = [DateTime]::UtcNow
if ($cert.NotBefore.ToUniversalTime() -gt $now -or $cert.NotAfter.ToUniversalTime() -lt $now) {
    throw 'Selected signing certificate is currently expired or not yet valid'
}
$stage = Join-Path ([IO.Path]::GetDirectoryName($outPath)) ('.opc-'+[Guid]::NewGuid().ToString('N')+$ext)
try {
    [IO.File]::Copy($inputPath,$stage)
    $package = [System.IO.Packaging.Package]::Open($stage,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        $main = Inspect-OfficePackage -Package $package -Ext $ext
        $manager = [System.IO.Packaging.PackageDigitalSignatureManager]::new($package)
        if ($manager.Signatures.Count -gt 0) { throw 'Already signed package: counter-signing requires a separate review' }
        $manager.CertificateOption = [System.IO.Packaging.CertificateEmbeddingOption]::InSignaturePart
        $manager.HashAlgorithm = 'http://www.w3.org/2001/04/xmlenc#sha256'
        $signedParts = New-Object 'System.Collections.Generic.List[System.Uri]'
        foreach ($part in $package.GetParts()) { $signedParts.Add($part.Uri) }
        # The OPC package signature origin and package-relationship parts are created
        # during Sign(). Sign all existing content plus the relationship additions
        # mandated in the official WindowsBase reference algorithm.
        $origin = $manager.SignatureOrigin
        $signedParts.Add($origin)
        $signedParts.Add([System.IO.Packaging.PackUriHelper]::GetRelationshipPartUri($origin))
        $signedParts.Add([System.IO.Packaging.PackUriHelper]::GetRelationshipPartUri([Uri]::new('/',[UriKind]::Relative)))
        $signature = $manager.Sign($signedParts,[System.Security.Cryptography.X509Certificates.X509Certificate]$cert)
        if ($null -eq $signature) { throw 'OPC provider did not produce a signature' }
    } finally { $package.Close() }
    $signedPackage = [System.IO.Packaging.Package]::Open($stage,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try { $state = Read-SignatureState -Package $signedPackage -Ext $ext }
    finally { $signedPackage.Close() }
    if (-not $state.integrity_pass) { throw ('Signed document failed readback integrity: ' + ($state | ConvertTo-Json -Compress -Depth 5)) }
    # Hash the verified staging file before publishing the destination.
    # Windows PowerShell on a minimal runner might not expose Get-FileHash.
    # Using .NET avoids a cmdlet dependency and leaves the output absent if
    # hashing fails.
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $inputStream = [System.IO.File]::OpenRead($stage)
    try {
        $digest = [BitConverter]::ToString($sha.ComputeHash($inputStream)).Replace('-', '').ToLowerInvariant()
    } finally {
        $inputStream.Dispose()
        $sha.Dispose()
    }
    [IO.File]::Move($stage,$outPath)
    $state | Add-Member -NotePropertyName 'file_sha256' -NotePropertyValue $digest
    $state | Add-Member -NotePropertyName 'signed_output' -NotePropertyValue $outPath
    $state | ConvertTo-Json -Depth 6 -Compress
} finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Force }
}
