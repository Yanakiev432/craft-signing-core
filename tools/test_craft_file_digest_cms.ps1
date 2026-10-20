#requires -Version 7.0
<#
  Ephemeral self-signed fixture only. Never installs certificates or touches
  personal data / hardware keys, never treats cryptographic PASS as eIDAS QES.
#>
[CmdletBinding()]
param([string]$Artifacts)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$tool=Join-Path $PSScriptRoot 'craft_file_digest_cms.ps1'
if(-not $Artifacts){$Artifacts=Join-Path ([IO.Path]::GetTempPath()) ('craft-cms-ci-'+[Guid]::NewGuid().ToString('N'))}
if(Test-Path $Artifacts){throw 'NO_OVERWRITE_EXISTING_TEST_DIRECTORY'}
[void][IO.Directory]::CreateDirectory($Artifacts)
$rsa=[Security.Cryptography.RSA]::Create(2048)
$cert=$null
try {
  $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new(
    'CN=NONQUALIFIED_SYNTHETIC_CRAFT_TEST_IDENTITY',
    $rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,
    [Security.Cryptography.RSASignaturePadding]::Pkcs1)
  $cert=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-10),
                                  [DateTimeOffset]::UtcNow.AddDays(1))
  if(-not $cert.HasPrivateKey){throw 'Ephemeral certificate has no private key'}
  $doc=Join-Path $Artifacts 'disposable-output.svg'
  [IO.File]::WriteAllText($doc,'<svg xmlns="http://www.w3.org/2000/svg"></svg>',[Text.UTF8Encoding]::new($false))
  $originSha=(Get-FileHash -LiteralPath $doc -Algorithm SHA256).Hash
  $sign=(& $tool -Mode sign -InputFile $doc -DevelopmentCertificate $cert | Out-String) | ConvertFrom-Json
  if($sign.cms_signature_created -ne $true -or $sign.qualified_release_ready -ne $false -or $sign.eidas_qes -ne 'NOT_CHECKED'){
    throw 'Synthetic sign result claimed unverified trust or failed to create CMS'
  }
  if((Get-FileHash $doc -Algorithm SHA256).Hash -ne $originSha){throw 'Input file was modified'}
  $verify=(& $tool -Mode verify -InputFile $doc | Out-String) | ConvertFrom-Json
  if($verify.cms_crypto_signature -ne 'PASS' -or $verify.file_hash_binding -ne 'PASS' -or $verify.publisher_certificate_trust -ne 'NOT_CHECKED'){
    throw 'Synthetic verify did not prove integrity separately from trust'
  }
  function Expect-Fail([scriptblock]$Case,[string]$Label) {
    $failed=$false
    try { & $Case | Out-Null }
    catch {$failed=$true}
    if(-not $failed){throw ('FAIL_OPEN: '+$Label)}
  }
  Expect-Fail { & $tool -Mode sign -InputFile $doc -DevelopmentCertificate $cert } 'overwriting signed output'
  Add-Content -LiteralPath $doc -Value 'tampered' -NoNewline
  Expect-Fail { & $tool -Mode verify -InputFile $doc } 'content tampering'
  [IO.File]::WriteAllText($doc,'<svg xmlns="http://www.w3.org/2000/svg"></svg>',[Text.UTF8Encoding]::new($false))
  $changed=Join-Path $Artifacts 'renamed-output.svg'
  [IO.File]::Copy($doc,$changed)
  Expect-Fail { & $tool -Mode verify -InputFile $changed -SignatureFile ($doc+'.craftsig.p7m') } 'name mismatch'
  $signature=$doc+'.craftsig.p7m'
  $raw=[IO.File]::ReadAllBytes($signature)
  $raw[[int]($raw.Length/2)]= $raw[[int]($raw.Length/2)] -bxor 1
  $broken=Join-Path $Artifacts 'tampered.cms'
  [IO.File]::WriteAllBytes($broken,$raw)
  Expect-Fail { & $tool -Mode verify -InputFile $doc -SignatureFile $broken } 'CMS tampering'
  Expect-Fail { & $tool -Mode sign -InputFile $doc } 'missing identity'
  Expect-Fail { & $tool -Mode verify -InputFile $doc -CertificateThumbprint ('0'*40) } 'verify private key'
  $huge=Join-Path $Artifacts 'large.bin'
  $buffer=[byte[]]::new(8*1024*1024)
  [IO.File]::WriteAllBytes($huge,$buffer)
  $big=(& $tool -Mode sign -InputFile $huge -DevelopmentCertificate $cert | Out-String)|ConvertFrom-Json
  $bigValid=(& $tool -Mode verify -InputFile $huge | Out-String)|ConvertFrom-Json
  if($bigValid.file_hash_binding -ne 'PASS' -or $big.file_bytes -ne $buffer.Length){throw 'Large file streaming digest acceptance failed'}
  Write-Output 'CRAFT_FILE_DIGEST_CMS_SIGN_VERIFY=PASS'
  Write-Output 'CMS_TAMPER_SOURCE_TAMPER_RENAME_AND_REPLAY_REJECTED=PASS'
  Write-Output 'NO_KEYS_INSTALLED_NO_PIN_QUALIFIED_EIDAS=NOT_CHECKED'
} finally {
  if($null -ne $cert){$cert.Dispose()}
  $rsa.Dispose()
  if(Test-Path $Artifacts){Remove-Item -LiteralPath $Artifacts -Recurse -Force}
}
