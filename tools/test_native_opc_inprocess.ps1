#requires -Version 7.0
param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$base=Split-Path $PSScriptRoot -Parent
$verify=Join-Path $base 'target\debug\examples\opc_native_verify.exe'
$sign=Join-Path $base 'target\debug\examples\opc_native_sign.exe'
if(-not (Test-Path $verify) -or -not (Test-Path $sign)){throw 'Compile native examples first'}
if(Test-Path $OutputDirectory){throw 'Fixture path already exists'}
$created=(& (Join-Path $PSScriptRoot 'test_opc_signature_windows.ps1') -ArtifactDirectory $OutputDirectory|Out-String)
if(-not $created.Contains('OPC_SIGN_VERIFY_TAMPER=PASS')){throw 'Baseline fixture creation failed'}
Add-Type -AssemblyName WindowsBase
function AssertNative([string]$path,[bool]$expected) {
  $global:LASTEXITCODE=0
  & $verify $path 2>&1|Out-Null
  $actual=($LASTEXITCODE -eq 0)
  if($actual -ne $expected){throw "Native OPC verification unexpectedly accepted/rejected $path"}
}
foreach($ext in @('docx','xlsx')){
  foreach($name in @('signed','tampered','unsigned-extra')){
    AssertNative (Join-Path $OutputDirectory "$name.$ext") ($name -eq 'signed')
  }
  foreach($kind in @('unsigned-root-rel','unsigned-meta')){
    $target=Join-Path $OutputDirectory "$kind.$ext"
    [IO.File]::Copy((Join-Path $OutputDirectory "signed.$ext"),$target)
    $pkg=[System.IO.Packaging.Package]::Open($target,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite)
    try {
      if($kind -eq 'unsigned-root-rel'){
        [void]$pkg.CreateRelationship([Uri]::new('https://example.invalid/no-fetch',[UriKind]::Absolute),[System.IO.Packaging.TargetMode]::External,'urn:craft:unsigned-test-relationship')
      } else {
        $part=$pkg.CreatePart([Uri]::new('/package/services/digital-signature/unsigned-extra.psdsxs',[UriKind]::Relative),'application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml')
        $bytes=[Text.Encoding]::UTF8.GetBytes('<unsigned-test/>')
        $stream=$part.GetStream([IO.FileMode]::Create,[IO.FileAccess]::Write)
        try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Close()}
      }
    }finally{$pkg.Close()}
    AssertNative $target $false
  }
}
$cert=$null
try {
  # Disposable CurrentUser certificate in isolated GitHub runner, never Lenovo.
  $cert=New-SelfSignedCertificate -Type Custom -Subject 'CN=Craft disposable native OPC CI identity' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 2048 -KeyExportPolicy NonExportable -KeyUsage DigitalSignature -NotAfter (Get-Date).AddHours(2)
  if(-not $cert.HasPrivateKey){throw 'Disposable test certificate lacks private key'}
  foreach($ext in @('docx','xlsx')){
    $src=Join-Path $OutputDirectory "original.$ext"
    $dst=Join-Path $OutputDirectory "native-signed.$ext"
    $global:LASTEXITCODE=0
    & $sign $src $dst $cert.Thumbprint|Out-Host
    if($LASTEXITCODE -ne 0 -or -not (Test-Path $dst)){throw "Native signing failed: $ext"}
    AssertNative $dst $true
    $independent=(& (Join-Path $PSScriptRoot 'opc_signature_windows.ps1') -Mode verify -InputFile $dst|Out-String)|ConvertFrom-Json
    if(-not $independent.integrity_pass){throw "Independent OPC verifier rejected $ext"}
    Write-Host ("NATIVE_OPC_SIGN_AND_INDEPENDENT_VERIFY_"+$ext.ToUpperInvariant()+"=PASS")
  }
} finally {
  if($cert) {
    Remove-Item -LiteralPath ('Cert:\CurrentUser\My\'+$cert.Thumbprint) -Force -ErrorAction SilentlyContinue
    $cert.Dispose()
  }
}
Write-Host 'NATIVE_OPC_NO_SUBPROCESS=PASS; REAL_BTRUST=NOT_TESTED; QES=NOT_VERIFIED'
