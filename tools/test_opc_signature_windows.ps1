#requires -Version 5.1
<#
Self-contained Windows OPC signing regression. Creates only disposable test
documents and a short-lived CurrentUser test *leaf* certificate, not a root.
No B-Trust identity, user document, PIN or production timestamp touched.
#>
[CmdletBinding()]
param([string]$ArtifactDirectory = (Join-Path $env:TEMP ('craft-opc-test-'+[Guid]::NewGuid().ToString('N'))))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName WindowsBase
New-Item -Path $ArtifactDirectory -ItemType Directory -Force | Out-Null
$signer = Join-Path $PSScriptRoot 'opc_signature_windows.ps1'
$certificate = $null
$rsa = $null

function Create-OfficeDocument([string]$Path, [string]$Family) {
    $pkg = [System.IO.Packaging.Package]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite)
    try {
        $relationship = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument'
        if($Family -eq 'docx') {
            $main = [Uri]::new('/word/document.xml',[UriKind]::Relative)
            $type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'
            $xml = '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Craft OPC test</w:t></w:r></w:p></w:body></w:document>'
        } else {
            $main = [Uri]::new('/xl/workbook.xml',[UriKind]::Relative)
            $type = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml'
            $xml = '<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>'
        }
        $part = $pkg.CreatePart($main,$type,[System.IO.Packaging.CompressionOption]::Normal)
        $data=[Text.Encoding]::UTF8.GetBytes($xml)
        $stream=$part.GetStream([IO.FileMode]::Create,[IO.FileAccess]::Write)
        try { $stream.Write($data,0,$data.Length) } finally { $stream.Close() }
        [void]$pkg.CreateRelationship([Uri]::new($main.OriginalString.TrimStart('/'),[UriKind]::Relative),[System.IO.Packaging.TargetMode]::Internal,$relationship)
        if($Family -eq 'xlsx'){
            $sheet = $pkg.CreatePart([Uri]::new('/xl/worksheets/sheet1.xml',[UriKind]::Relative),'application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml',[System.IO.Packaging.CompressionOption]::Normal)
            $xml='<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Craft OPC test</t></is></c></row></sheetData></worksheet>'
            $bytes=[Text.Encoding]::UTF8.GetBytes($xml)
            $s=$sheet.GetStream([IO.FileMode]::Create,[IO.FileAccess]::Write)
            try{$s.Write($bytes,0,$bytes.Length)}finally{$s.Close()}
            [void]$part.CreateRelationship([Uri]::new('worksheets/sheet1.xml',[UriKind]::Relative),[System.IO.Packaging.TargetMode]::Internal,'http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet')
        }
    } finally { $pkg.Close() }
}

try {
    # Completely in-memory test leaf; no PFX file and no cert-store changes.
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Craft OPC in-memory fixture', $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1),[DateTimeOffset]::UtcNow.AddHours(2))
    if (-not $certificate.HasPrivateKey) {throw 'In-memory test identity missing private key'}
    foreach($family in @('docx','xlsx')) {
        $original = Join-Path $ArtifactDirectory ("original."+$family)
        $signed = Join-Path $ArtifactDirectory ("signed."+$family)
        $tampered = Join-Path $ArtifactDirectory ("tampered."+$family)
        Create-OfficeDocument $original $family
        $global:LASTEXITCODE = 0
        $json = (& $signer -Mode sign -InputFile $original -OutputFile $signed -DevelopmentCertificate $certificate) | Out-String
        if($LASTEXITCODE -ne 0){throw "$family sign failed with exit $LASTEXITCODE"}
        $result=$json|ConvertFrom-Json
        if(-not $result.integrity_pass){throw "$family produced invalid signature"}
        $verified = ((& $signer -Mode verify -InputFile $signed) | Out-String)| ConvertFrom-Json
        if(-not $verified.integrity_pass){throw "$family verification failed"}
        # Two independent people must be able to sign consecutively without
        # losing the first signer's cryptographic evidence.
        $rsa2 = [System.Security.Cryptography.RSA]::Create(2048)
        $cert2 = $null
        try {
            $request2 = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                'CN=Craft second independent signer', $rsa2,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $cert2 = $request2.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-1),[DateTimeOffset]::UtcNow.AddHours(2))
            $multi = Join-Path $ArtifactDirectory ("two-signers."+$family)
            $global:LASTEXITCODE = 0
            $multijson = (& $signer -Mode sign -InputFile $signed -OutputFile $multi -DevelopmentCertificate $cert2) | Out-String
            if ($LASTEXITCODE -ne 0) { throw "$family second signer operation failed" }
            $multiResult = $multijson | ConvertFrom-Json
            if (-not $multiResult.integrity_pass -or $multiResult.signature_count -ne 2) {
                throw "$family both signatures were not cryptographically accepted"
            }
            $check = ((& $signer -Mode verify -InputFile $multi) | Out-String) | ConvertFrom-Json
            if ($check.signature_count -ne 2 -or -not $check.integrity_pass) {
                throw "$family second signature invalidated first signer"
            }
            Write-Output ("OPC_TWO_INDEPENDENT_SIGNERS=PASS family=$family count=2")
        } finally {
            if ($cert2) { $cert2.Dispose() }
            $rsa2.Dispose()
        }
        # The explicit opt-out creates a Craft-signed policy inside an otherwise
        # unsigned fixture. Other Office editors are NOT contractually bound by
        # Craft's policy, so this is not a Microsoft Office document lock.
        $locked = Join-Path $ArtifactDirectory ("locked."+$family)
        $next = Join-Path $ArtifactDirectory ("unwanted-additional."+$family)
        $lockedResult = ((& $signer -Mode sign -InputFile $original -OutputFile $locked -DevelopmentCertificate $certificate -AdditionalSignatures restrict) | Out-String) | ConvertFrom-Json
        if (-not $lockedResult.integrity_pass -or $lockedResult.signature_count -ne 1) {
            throw "$family locked-policy fixture invalid"
        }
        $blocked = $false
        try {
            & $signer -Mode sign -InputFile $locked -OutputFile $next -DevelopmentCertificate $certificate | Out-Null
        } catch {
            $blocked = $_.Exception.Message.Contains('forbids additional signatures')
        }
        if (-not $blocked -or (Test-Path -LiteralPath $next)) {
            throw "$family Craft-only signature policy failed to reject later signing"
        }
        Write-Output ("OPC_CRAFT_POLICY_LOCK=PASS family=$family")
        [IO.File]::Copy($signed,$tampered)
        $package=[System.IO.Packaging.Package]::Open($tampered,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite)
        try {
            $p= $package.GetPart([Uri]::new($result.main_part,[UriKind]::Relative))
            $stream = $p.GetStream([IO.FileMode]::Open,[IO.FileAccess]::Write)
            try { $stream.Position=0; $stream.WriteByte(33) } finally {$stream.Close()}
        } finally {$package.Close()}
        $negative = (& $signer -Mode verify -InputFile $tampered 2>&1) | Out-String
        if($LASTEXITCODE -eq 0){throw "$family tamper was incorrectly accepted: $negative"}
        # Adding a package relationship after signing must not evade the
        # selector-based multiple-signer integrity policy, even when no
        # actual new OPC content part is introduced.
        $uncoveredRelationship = Join-Path $ArtifactDirectory ("unsigned-relationship."+$family)
        [IO.File]::Copy($signed,$uncoveredRelationship)
        $tamperedPackage = [System.IO.Packaging.Package]::Open(
            $uncoveredRelationship,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite)
        try {
            [void]$tamperedPackage.CreateRelationship(
                [Uri]::new('https://example.invalid/unsigned-addition',[UriKind]::Absolute),
                [System.IO.Packaging.TargetMode]::External,
                'urn:craft:unapproved-external-relationship')
        } finally { $tamperedPackage.Close() }
        $global:LASTEXITCODE=0
        $rejectedRelationship=(& $signer -Mode verify -InputFile $uncoveredRelationship) | Out-String
        if ($LASTEXITCODE -eq 0) {
            throw "$family unsigned relationship was incorrectly accepted: $rejectedRelationship"
        }
        # Adding an unprotected OPC part must also fail (even if the existing
        # XMLDSig cryptographic hash is unchanged).
        $extended = Join-Path $ArtifactDirectory ("unsigned-extra."+$family)
        [IO.File]::Copy($signed,$extended)
        $extraPackage=[System.IO.Packaging.Package]::Open($extended,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite)
        try {
            $uri=[Uri]::new('/wordcraft-gridcraft-unsigned-extra.xml',[UriKind]::Relative)
            $extraPart=$extraPackage.CreatePart($uri,'application/xml')
            $bytes=[Text.Encoding]::UTF8.GetBytes('<extra/>')
            $stream=$extraPart.GetStream([IO.FileMode]::Create,[IO.FileAccess]::Write)
            try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Close()}
        }finally{$extraPackage.Close()}
        $global:LASTEXITCODE=0
        $negativeExtra=(& $signer -Mode verify -InputFile $extended) | Out-String
        if($LASTEXITCODE -eq 0){throw "$family unsigned added part was incorrectly accepted: $negativeExtra"}
        Write-Output ("OPC_TEST_PASS family=$family signed="+$signed+" sha256="+$result.file_sha256+" tamper_rejected=true unsigned_part_rejected=true")
    }
    Write-Output 'OPC_SIGN_VERIFY_TAMPER=PASS'
}
finally {
    if($certificate) { $certificate.Dispose() }
    if($rsa) { $rsa.Dispose() }
    Write-Output 'IN_MEMORY_TEST_IDENTITY_DISPOSED=true'
}
# Both negative controls deliberately set exit=1. Normalize *only after* the
# complete success path so callers and GitHub Actions receive unambiguous PASS.
$global:LASTEXITCODE = 0
