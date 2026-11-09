# Certificate-bound visible DOCX/XLSX acceptance using the SAME previously
# validated B-Trust hardware signer. Only synthetic core/target fixtures.
# Never exports keys, reads PIN or modifies originals. Native PIN UI only.
[CmdletBinding()]
param([ValidateSet('Preflight','Sign')][string]$Mode='Preflight')
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
Set-StrictMode -Version Latest
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixtures=Join-Path $root 'target\office-realistic-interop-20261023'
$priorSigned=Join-Path $fixtures 'sample-core-fixed-btrust.docx'
if(-not (Test-Path $priorSigned -PathType Leaf)){throw 'Previous verified B-Trust source missing'}
Add-Type -AssemblyName WindowsBase
$pkg=[IO.Packaging.Package]::Open($priorSigned,[IO.FileMode]::Open,[IO.FileAccess]::Read)
try {
 $manager=[IO.Packaging.PackageDigitalSignatureManager]::new($pkg)
 if($manager.Signatures.Count -ne 1 -or $manager.VerifySignatures($false).ToString() -ne 'Success'){
  throw 'Existing B-Trust test source not independently valid'
 }
 $thumb=$manager.Signatures[0].Signer.Thumbprint
} finally { $pkg.Dispose() }
$certs=@(Get-ChildItem Cert:\CurrentUser\My |
 Where-Object {$_.Thumbprint -eq $thumb -and $_.HasPrivateKey -and $_.Issuer -match 'B-Trust' -and $_.NotAfter -gt (Get-Date)})
if($certs.Count -ne 1){throw 'Previously proven B-Trust signer is not uniquely present'}
Write-Output ('BTRUST_VISIBLE_PREFLIGHT=PASS;CERT_SUFFIX='+$thumb.Substring(34))
Write-Output 'PIN_CAPTURE=NEVER;TRUST_ROOT_IMPORT=NEVER;QES=NOT_ASSESSED'
if($Mode -eq 'Preflight') {return}
$testRoot=Join-Path $root ('target\native-btrust-visible-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot -ErrorAction Stop | Out-Null
$env:PATH=(Join-Path $env:USERPROFILE '.cargo\bin')+';'+$env:PATH
$resultItems=@()
Push-Location $root
try {
 foreach($ext in @('docx','xlsx')) {
  $source=Join-Path $fixtures ('sample.'+$ext)
  if(-not (Test-Path $source -PathType Leaf)){throw ('Missing synthetic '+$ext)}
  $old=(Get-FileHash $source -Algorithm SHA256).Hash
  $out=Join-Path $testRoot ('BTrust_Visible_CertificateBound_Signed.'+$ext)
  Write-Output ('BTRUST_VISIBLE_SIGN_REQUEST='+$ext.ToUpperInvariant())
  Write-Output 'If your provider opens its own PIN dialog, use it locally. Never provide PIN in ChatGPT.'
  & cargo run --locked --offline --quiet --example office_visible_identity_smoke -- $source $out $thumb
  if($LASTEXITCODE -ne 0){throw ('Native BTrust visual sign returned failure for '+$ext)}
  if((Get-FileHash $source -Algorithm SHA256).Hash -ne $old){throw 'Original was modified'}
  $signed=[IO.Packaging.Package]::Open($out,[IO.FileMode]::Open,[IO.FileAccess]::Read)
  try {
   $verifier=[IO.Packaging.PackageDigitalSignatureManager]::new($signed)
   if($verifier.Signatures.Count -ne 1 -or $verifier.VerifySignatures($false).ToString() -ne 'Success'){
    throw ('Independent Windows OPC verification failed for '+$ext)
   }
   if($verifier.Signatures[0].Signer.Thumbprint -ne $thumb){
    throw ('Wrong signing identity in '+$ext)
   }
  } finally { $signed.Dispose() }
  $resultItems+=@{format=$ext;status='BTRUST_HARDWARE_SIGNATURE_INTEGRITY_PASS';source_sha256=$old;
    signed_sha256=(Get-FileHash $out -Algorithm SHA256).Hash;signature_count=1;original_preserved=$true}
  Write-Output ('BTRUST_VISIBLE_'+$ext.ToUpperInvariant()+'_OPC=PASS')
 }
}finally{Pop-Location}
$report=[ordered]@{schema='craft.native.visible.btrust.acceptance.v1';date=(Get-Date).ToString('o');
 status='HARDWARE_BTRUST_VISIBLE_DOCX_XLSX_OPC_PASS';hardware_operator='provider_only';
 no_private_key_or_pin_capture=$true;documents='synthetic_only';qes_document='NOT_ASSESSED';
 ms_office_interactive='NOT_TESTED';results=$resultItems}
$report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $testRoot 'acceptance.json') -Encoding UTF8
Write-Output ('BTRUST_VISIBLE_ACCEPTANCE='+ (Join-Path $testRoot 'acceptance.json'))
