# Safe local operator acceptance for B-Trust hardware signing on synthetic OPC fixtures.
# Default mode only enumerates eligible candidates; NEVER signs unattended.
[CmdletBinding()]
param(
  [ValidateSet('Preflight','Sign')]
  [string]$Mode='Preflight',
  [string]$FixtureDirectory=''
)
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
Set-StrictMode -Version Latest
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$target=(Resolve-Path (Join-Path $root 'target')).Path
if([string]::IsNullOrWhiteSpace($FixtureDirectory)){
  $latest=Get-ChildItem -LiteralPath $target -Directory -Filter 'opc-live-*' |
          Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if(-not $latest){throw 'No safe OPC fixture: run tools/opc-live-smoke.ps1 first.'}
  $FixtureDirectory=$latest.FullName
}
$fixture=(Resolve-Path -LiteralPath $FixtureDirectory).Path
if(-not $fixture.StartsWith($target+'\',[StringComparison]::OrdinalIgnoreCase)){
  throw 'Refusing any document outside craft-signing-core/target.'
}
foreach($ext in @('docx','xlsx')){
  if(-not(Test-Path (Join-Path $fixture ('unsigned.'+$ext)) -PathType Leaf)){
    throw "Unsigned synthetic $ext fixture missing."
  }
}
$now=Get-Date
$candidates=@(Get-ChildItem Cert:\CurrentUser\My |
  Where-Object { $_.Issuer -match 'B-Trust' -and $_.HasPrivateKey -and $_.NotBefore -lt $now -and $_.NotAfter -gt $now } |
  Sort-Object NotAfter)
Write-Output ('BTRUST_ELIGIBLE_CERTIFICATES='+$candidates.Count)
for($i=0;$i -lt $candidates.Count;$i++){
  Write-Output ('CANDIDATE_INDEX='+($i+1)+';EXPIRES='+$candidates[$i].NotAfter.ToString('yyyy-MM-dd')+
                ';THUMBPRINT_SUFFIX='+$candidates[$i].Thumbprint.Substring(34))
}
Write-Output 'QES_QUALIFICATION=NOT_ASSESSED'
Write-Output 'PIN_HANDLING=WINDOWS_PROVIDER_ONLY'
if($Mode -eq 'Preflight'){
  Write-Output 'HARDWARE_SIGNING=NOT_STARTED'
  return
}
# Must run this Sign mode on the authorized user's interactive Windows desktop.
if($candidates.Count -lt 1){throw 'No current B-Trust private-key certificate found'}
$selection=Read-Host 'Choose the B-Trust certificate index'
$index=0
if(-not [int]::TryParse($selection,[ref]$index) -or $index -lt 1 -or $index -gt $candidates.Count){
  throw 'Signing cancelled: invalid certificate selection'
}
$chosen=$candidates[$index-1]
$confirmation=Read-Host 'Type SIGN to cryptographically sign two SYNTHETIC documents (provider PIN dialog may appear)'
if($confirmation -cne 'SIGN'){throw 'Signing cancelled by operator'}
$runDir=Join-Path $target ('opc-btrust-operator-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runDir -ErrorAction Stop | Out-Null
$env:PATH=(Join-Path $env:USERPROFILE '.cargo\bin')+';'+$env:PATH
Add-Type -AssemblyName WindowsBase
$results=[Collections.Generic.List[object]]::new()
Push-Location $root
try{
  foreach($ext in @('docx','xlsx')){
    $source=Join-Path $fixture ('unsigned.'+$ext)
    $output=Join-Path $runDir ('btrust-synthetic-signed.'+$ext)
    $originalHash=(Get-FileHash $source -Algorithm SHA256).Hash
    & cargo run --locked --quiet --example opc_sign_smoke -- $source $output $chosen.Thumbprint
    if($LASTEXITCODE -ne 0){throw "B-Trust provider refused signing of $ext"}
    if($originalHash -ne (Get-FileHash $source -Algorithm SHA256).Hash){
      throw "Source fixture was modified during $ext signing"
    }
    $pkg=[IO.Packaging.Package]::Open($output,[IO.FileMode]::Open,[IO.FileAccess]::Read)
    try {
      $manager=[IO.Packaging.PackageDigitalSignatureManager]::new($pkg)
      if($manager.Signatures.Count -ne 1 -or $manager.VerifySignatures($false).ToString() -ne 'Success'){
        throw "$ext verification did not pass"
      }
      $signer=$manager.Signatures[0].Signer
      if($signer.Thumbprint -ne $chosen.Thumbprint){throw 'Unexpected certificate in signature'}
    } finally { $pkg.Dispose() }
    $results.Add([ordered]@{format=$ext;opc_integrity='PASS';original_preserved=$true;
       output_sha256=(Get-FileHash $output -Algorithm SHA256).Hash;qes='NOT_ASSESSED'})
    Write-Output ('BTRUST_SYNTHETIC_'+$ext.ToUpperInvariant()+'_OPC=PASS')
  }
} finally {Pop-Location}
$report=[ordered]@{schema='craft.opc.hardware-test.v1';status='OPC_INTEGRITY_PASS';
  evidence=$results.ToArray();hardware_provider='B-Trust via Windows';
  microsoft_office='NOT_TESTED';eidas_QES='NOT_ASSESSED';
  signer_qualified_status='NOT_ASSESSED';pin_processed_by_craft=$false}
$report | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $runDir 'acceptance.json') -Encoding UTF8
Write-Output ('ACCEPTANCE_JSON='+ (Join-Path $runDir 'acceptance.json'))
$global:LASTEXITCODE=0
