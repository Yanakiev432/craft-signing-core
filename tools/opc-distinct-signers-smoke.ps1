# Disposable two-identity OPC regression. Never touches personal files or B-Trust.
param([Parameter(Mandatory=$true)][string]$FixtureDirectory)
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
Set-StrictMode -Version Latest
Add-Type -AssemblyName WindowsBase
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$target=(Resolve-Path (Join-Path $root 'target')).Path
$fixtures=(Resolve-Path -LiteralPath $FixtureDirectory).Path
if(-not $fixtures.StartsWith($target+'\',[StringComparison]::OrdinalIgnoreCase)){
    throw 'FixtureDirectory must be inside signing-core target.'
}
$working=Join-Path $target ('opc-distinct-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $working -ErrorAction Stop | Out-Null
$env:PATH=(Join-Path $env:USERPROFILE '.cargo\bin')+';'+$env:PATH
$disposable=$null
$identityBefore=@(Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match 'Craft OPC disposable second signer'}).Count
$results=[Collections.Generic.List[object]]::new()
try {
    $args=@{Subject=('CN=Craft OPC disposable second signer '+[Guid]::NewGuid().ToString('N'));
            CertStoreLocation='Cert:\CurrentUser\My';KeyAlgorithm='RSA';KeyLength=2048;
            KeyExportPolicy='NonExportable';Provider='Microsoft Software Key Storage Provider';
            NotBefore=(Get-Date).AddMinutes(-2);NotAfter=(Get-Date).AddHours(2);
            KeyUsage='DigitalSignature';HashAlgorithm='SHA256'}
    $disposable=New-SelfSignedCertificate @args
    if(-not $disposable.HasPrivateKey){throw 'Disposable signing identity has no linked key'}
    foreach($ext in @('docx','xlsx')){
        $source=Join-Path $fixtures ('signed.'+$ext)
        $out=Join-Path $working ('signed-two-identities.'+$ext)
        $baseline=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        & cargo run --locked --quiet --example opc_sign_smoke -- $source $out $disposable.Thumbprint
        if($LASTEXITCODE -ne 0){throw "Second identity signing failed: $ext"}
        & cargo run --locked --quiet --example opc_verify_smoke -- $out
        if($LASTEXITCODE -ne 0){throw "Native verification failed: $ext"}
        $pkg=[IO.Packaging.Package]::Open($out,[IO.FileMode]::Open,[IO.FileAccess]::Read)
        try {
            $manager=[IO.Packaging.PackageDigitalSignatureManager]::new($pkg)
            $integrity=$manager.VerifySignatures($false).ToString()
            $signatures=@($manager.Signatures)
            if($integrity -ne 'Success' -or $signatures.Count -ne 2){
                throw "Independent WindowsBase OPC verification failed: $ext / $integrity / $($signatures.Count)"
            }
            $signers=@($signatures|ForEach-Object{$_.Signer.GetCertHashString()})
            if(@($signers|Sort-Object -Unique).Count -ne 2 -or
               $disposable.Thumbprint -notin $signers){
                throw "Signatures were not made by two distinct identities: $ext"
            }
        } finally { $pkg.Dispose() }
        if((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $baseline){
            throw "Original signed document changed: $ext"
        }
        # A newly injected unsigned part must invalidate the two-signature package.
        $tampered=Join-Path $working ('unsigned-part-after-two.'+$ext)
        [IO.File]::Copy($out,$tampered)
        $mut=[IO.Packaging.Package]::Open($tampered,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite)
        try {
            $uri=[Uri]::new('/craft-unsigned-extra-after-two.xml',[UriKind]::Relative)
            $part=$mut.CreatePart($uri,'application/xml')
            $str=$part.GetStream([IO.FileMode]::Create,[IO.FileAccess]::Write)
            try {
                $payload=[Text.Encoding]::UTF8.GetBytes('<unsigned/>')
                $str.Write($payload,0,$payload.Length)
            } finally { $str.Dispose() }
        } finally { $mut.Dispose() }
        & cargo run --locked --quiet --example opc_verify_smoke -- $tampered 2>$null
        if($LASTEXITCODE -eq 0){throw "Two-signature coverage accepted an unsigned part: $ext"}
        $rejectedOutput=Join-Path $working ('must-not-sign-corrupt.'+$ext)
        & cargo run --locked --quiet --example opc_sign_smoke -- $tampered $rejectedOutput $disposable.Thumbprint 2>$null
        if($LASTEXITCODE -eq 0 -or (Test-Path $rejectedOutput)){
            throw "New signature accepted a corrupt source: $ext"
        }
        $results.Add([ordered]@{format=$ext;signature_count=2;different_signers=$true;
           independent_integrity='PASS';original_preserved=$true;
           unsigned_part_rejected=$true;refused_to_sign_corrupt_source=$true;
           qes='NOT_ASSESSED'})
        Write-Output ("DISTINCT_SIGNERS_"+$ext.ToUpperInvariant()+"=PASS")
    }
} finally {
    if($disposable){
        $path='Cert:\CurrentUser\My\'+$disposable.Thumbprint
        if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Force -ErrorAction Stop}
        if(Test-Path -LiteralPath $path){throw 'Disposable leaf was not removed'}
        $disposable.Dispose()
    }
    $identityAfter=@(Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match 'Craft OPC disposable second signer'}).Count
    if($identityAfter -ne $identityBefore){throw 'Disposable certificate inventory not restored'}
    Write-Output 'DISPOSABLE_CERTIFICATE_REMOVED=PASS'
}
$report=[ordered]@{status='PASS'; schema='craft.opc.multisign.v1'; results=@($results);
    fixtures=$working; microsoft_office='NOT_TESTED'; btrust_hardware='NOT_TESTED'}
$report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $working 'acceptance.json') -Encoding UTF8
Write-Output ('MULTI_IDENTITY_ACCEPTANCE='+ (Join-Path $working 'acceptance.json'))
$global:LASTEXITCODE=0
