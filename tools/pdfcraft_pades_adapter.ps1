#requires -Version 7.0
<#
  PDFCraft automation adapter. PAdES B-B signing via pdfcraft-cli run --script.
  The certificate remains in the Windows CNG provider; token PIN is never read.
  Real token signing and independent DSS qualification remain separate gates.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][ValidateSet('Sign','Verify')][string]$Mode,
 [Parameter(Mandatory)][string]$InputPath,
 [string]$OutputPath,
 [string]$CertificateThumbprint,
 [string]$PdfCraftCli,
 [switch]$InvisibleSignature
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(-not(Test-Path -LiteralPath $InputPath -PathType Leaf)){throw 'PDF_INPUT_MISSING'}
$inputFull=(Resolve-Path -LiteralPath $InputPath).ProviderPath
if([IO.Path]::GetExtension($inputFull).ToLowerInvariant() -ne '.pdf'){throw 'PDF_EXTENSION_REQUIRED'}
if(-not $PdfCraftCli){$PdfCraftCli=$env:PDFCRAFT_CLI_PATH}
if(-not $PdfCraftCli){throw 'PDFCRAFT_CLI_PATH_REQUIRED'}
if(-not(Test-Path -LiteralPath $PdfCraftCli -PathType Leaf)){throw 'PDFCRAFT_CLI_NOT_FOUND'}
if($Mode -eq 'Sign'){
 if(-not $CertificateThumbprint){throw 'PDF_CERTIFICATE_REQUIRED'}
 if(-not $OutputPath){$OutputPath=Join-Path ([IO.Path]::GetDirectoryName($inputFull)) ([IO.Path]::GetFileNameWithoutExtension($inputFull)+'.signed.pdf')}
 $outputFull=[IO.Path]::GetFullPath($OutputPath)
 if($inputFull -eq $outputFull){throw 'PDF_REFUSE_INPLACE_SIGN'}
 if(Test-Path -LiteralPath $outputFull){throw 'PDF_REFUSE_OVERWRITE'}
 $cert=Get-ChildItem Cert:\CurrentUser\My | Where-Object Thumbprint -eq ($CertificateThumbprint -replace '\s','') | Select-Object -First 1
 if(-not $cert -or -not $cert.HasPrivateKey){throw 'PDF_CERTIFICATE_NOT_AVAILABLE'}
 $sha=[Security.Cryptography.SHA256]::HashData($cert.RawData)
 $identity='windows:'+([Convert]::ToHexString($sha).ToLowerInvariant())
 $signArgs=@{doc=1;id=$identity;out=$outputFull}
 if(-not $InvisibleSignature){$signArgs.page=1;$signArgs.rect=@(55,55,305,135);$signArgs.appearance=@{name=$true;date=$true;labels=$true}}
 $steps=@(
  @{tool='doc_open';args=@{path=$inputFull}},
  @{tool='sign_document';args=$signArgs}
 )
} else {
 if($OutputPath -or $CertificateThumbprint){throw 'PDF_VERIFY_ARGUMENTS_INVALID'}
 $steps=@(
  @{tool='doc_open';args=@{path=$inputFull}},
  @{tool='sign_list';args=@{doc=1}}
 )
}
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('craft-pdf-'+[Guid]::NewGuid().ToString('N')+'.json')
try{
 [IO.File]::WriteAllText($temporary,(ConvertTo-Json -InputObject $steps -Depth 12),[Text.UTF8Encoding]::new($false))
 $result=& $PdfCraftCli run --script $temporary --report 2>&1
 if($LASTEXITCODE -ne 0){throw ('PDFCRAFT_AUTOMATION_FAILED: '+($result -join ' '))}
 if($Mode -eq 'Sign'){
  if(-not(Test-Path -LiteralPath $outputFull -PathType Leaf)){throw 'PDFCRAFT_SIGNED_OUTPUT_MISSING'}
  if((Get-Item -LiteralPath $outputFull).Length -eq 0){throw 'PDFCRAFT_SIGNED_OUTPUT_EMPTY'}
  [pscustomobject]@{status='PDF_SIGNED_UNVERIFIED';output=$outputFull;qualification='NOT_ASSESSED'}
 } else {
  $report=($result -join "`n") | ConvertFrom-Json -Depth 30
  if(-not $report.ok){throw 'PDFCRAFT_VERIFY_EXECUTION_FAILED'}
  $signatureStep=@($report.steps | Where-Object tool -eq 'sign_list') | Select-Object -Last 1
  if(-not $signatureStep){throw 'PDFCRAFT_VERIFY_RESULT_MISSING'}
  $validation=@($signatureStep.result) | Select-Object -First 1
  if(-not $validation -or $validation.count -lt 1){throw 'PDF_UNSIGNED'}
  if(-not $validation.all_valid){throw 'PDF_SIGNATURE_NOT_ALL_VALID'}
  [pscustomobject]@{status='PDF_SIGNATURES_VALID_BY_PDFCRAFT';count=$validation.count;qualification='NOT_ASSESSED'}
 }
} finally {Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue}
