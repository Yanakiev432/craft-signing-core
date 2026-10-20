#requires -Version 7.0
<#
.SYNOPSIS
  Sign or verify an OOXML OPC package using WindowsBase PackageDigitalSignatureManager.
.DESCRIPTION
  This is OPC/XMLDSig, never PAdES. A signature integrity PASS is NOT proof
  of a qualified electronic signature, trusted publisher, or Office interoperability.
  No private key export. PIN UI is owned by the smartcard provider.
  -SelfSignedTest is deliberately limited to temporary test documents.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Sign', 'Verify')]
    [string]$Mode,
    [Parameter(Mandatory = $true)]
    [string]$InputPath,
    [string]$OutputPath,
    [string]$CertificateThumbprint,
    [switch]$SelfSignedTest
)
$ErrorActionPreference = 'Stop'
function Fail([string]$message) { throw "OPC_SIGNING_NO_GO: $message" }

if (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) { Fail 'Input file does not exist' }
$inputFile = (Resolve-Path -LiteralPath $InputPath).ProviderPath
$extension = [IO.Path]::GetExtension($inputFile).ToLowerInvariant()
if ($extension -notin @('.docx', '.xlsx')) { Fail 'Only .docx or .xlsx OPC packages are supported' }
$beforeHash = (Get-FileHash -LiteralPath $inputFile -Algorithm SHA256).Hash
$signatureStatus = 'NOT_CHECKED'
$qualification = 'NOT_ASSESSED'
$certificateTrust = 'NOT_ASSESSED'
$signatureCount = 0
$documentFamily = if ($extension -eq '.docx') { 'WordCraft' } else { 'GridCraft' }

function Get-FileCert {
    if ($SelfSignedTest) {
        if ($CertificateThumbprint) { Fail 'Test certificate cannot be combined with a real certificate selector' }
        $rsa = [Security.Cryptography.RSA]::Create(2048)
        $req = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
            'CN=Craft TEST ONLY not trusted',
            $rsa,
            [Security.Cryptography.HashAlgorithmName]::SHA256,
            [Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        return $req.CreateSelfSigned(
            [DateTimeOffset]::UtcNow.AddMinutes(-2),
            [DateTimeOffset]::UtcNow.AddMinutes(15)
        )
    }
    if ([string]::IsNullOrWhiteSpace($CertificateThumbprint)) { Fail 'CertificateThumbprint is required for real signing' }
    $thumb = $CertificateThumbprint.Replace(' ','').ToUpperInvariant()
    if ($thumb -notmatch '^[A-F0-9]{40,64}$') { Fail 'Invalid certificate thumbprint' }
    $matches = @(Get-ChildItem Cert:\CurrentUser\My,Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $thumb -and $_.HasPrivateKey })
    if ($matches.Count -ne 1) { Fail 'Exactly one accessible private-key certificate must match the supplied thumbprint' }
    return $matches[0]
}

if ($Mode -eq 'Verify') {
    if ($OutputPath -or $CertificateThumbprint -or $SelfSignedTest) { Fail 'Verify accepts only InputPath and Mode' }
    $pkg = [IO.Packaging.Package]::Open($inputFile, [IO.FileMode]::Open, [IO.FileAccess]::Read)
    try {
        $manager = [IO.Packaging.PackageDigitalSignatureManager]::new($pkg)
        $signatureCount = $manager.Signatures.Count
        if ($signatureCount -eq 0) { Fail 'No OPC digital signatures found' }
        $signatureStatus = $manager.VerifySignatures($false).ToString()
        if ($signatureStatus -ne 'Success') { Fail "OPC integrity failed: $signatureStatus" }
        $trustedResult = $manager.VerifySignatures($true).ToString()
        $certificateTrust = if ($trustedResult -eq 'Success') { 'WINDOWS_CHAIN_VALIDATED' } else { "NOT_TRUSTED_OR_UNDETERMINED:$trustedResult" }
    } finally { $pkg.Dispose() }
}
else {
    if ([string]::IsNullOrWhiteSpace($OutputPath)) { Fail 'OutputPath required for signing' }
    $fullOutput = [IO.Path]::GetFullPath($OutputPath)
    if ($fullOutput -eq $inputFile) { Fail 'In-place signing is forbidden; keep original intact' }
    if (Test-Path -LiteralPath $fullOutput) { Fail 'Refusing to overwrite an existing output' }
    $outputParent = [IO.Path]::GetDirectoryName($fullOutput)
    if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) { Fail 'Output directory does not exist' }
    $cert = Get-FileCert
    Copy-Item -LiteralPath $inputFile -Destination $fullOutput -ErrorAction Stop
    try {
        $pkg = [IO.Packaging.Package]::Open($fullOutput, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite)
        try {
            $manager = [IO.Packaging.PackageDigitalSignatureManager]::new($pkg)
            if ($manager.IsSigned) { Fail 'Input already has signatures; countersign needs separate workflow' }
            $manager.CertificateOption = [IO.Packaging.CertificateEmbeddingOption]::InSignaturePart
            $manager.HashAlgorithm = 'http://www.w3.org/2001/04/xmlenc#sha256'
            $uris = [Collections.Generic.List[Uri]]::new()
            $relationships = [Collections.Generic.List[IO.Packaging.PackageRelationshipSelector]]::new()
            $rootUri = [Uri]::new('/',[UriKind]::Relative)
            foreach ($rel in $pkg.GetRelationships()) {
                $relationships.Add([IO.Packaging.PackageRelationshipSelector]::new(
                    $rootUri, [IO.Packaging.PackageRelationshipSelectorType]::Id, $rel.Id))
            }
            foreach ($part in $pkg.GetParts()) {
                # Relationship parts are represented through explicit OPC selectors.
                if ([IO.Packaging.PackUriHelper]::IsRelationshipPartUri($part.Uri)) { continue }
                $uris.Add($part.Uri)
                foreach ($rel in $part.GetRelationships()) {
                    $relationships.Add([IO.Packaging.PackageRelationshipSelector]::new(
                        $part.Uri, [IO.Packaging.PackageRelationshipSelectorType]::Id, $rel.Id))
                }
            }
            if ($uris.Count -eq 0) { Fail 'Package has no signed content parts' }
            [void]$manager.Sign($uris, $cert, $relationships)
            $signatureCount = $manager.Signatures.Count
            $pkg.Flush()
        } finally { $pkg.Dispose() }
        # Open the final bytes again. Never mistake successful Sign() for validity.
        $reopened = [IO.Packaging.Package]::Open($fullOutput, [IO.FileMode]::Open, [IO.FileAccess]::Read)
        try {
            $check = [IO.Packaging.PackageDigitalSignatureManager]::new($reopened)
            $signatureStatus = $check.VerifySignatures($false).ToString()
            if ($signatureStatus -ne 'Success' -or $check.Signatures.Count -ne 1) {
                Fail "Independent reopened package signature failed: $signatureStatus"
            }
        } finally { $reopened.Dispose() }
    } catch {
        Remove-Item -LiteralPath $fullOutput -Force -ErrorAction SilentlyContinue
        throw
    }
}
$finalFile = if ($Mode -eq 'Sign') { $fullOutput } else { $inputFile }
[pscustomobject]@{
    schema = 'craft.opc-xmldsig.integrity.v1'
    mode = $Mode
    family = $documentFamily
    file = $finalFile
    original_sha256 = $beforeHash
    result_sha256 = (Get-FileHash -LiteralPath $finalFile -Algorithm SHA256).Hash
    signature_count = $signatureCount
    integrity = $signatureStatus
    certificate_trust = $certificateTrust
    qes_qualification = $qualification
    test_self_signed = [bool]$SelfSignedTest
    office_interoperability = 'NOT_TESTED'
} | ConvertTo-Json -Compress
