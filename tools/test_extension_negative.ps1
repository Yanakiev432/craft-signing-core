#requires -Version 7.0
<#
  Negative acceptance for the optional extension. Never signs a real document.
  Validates refusal of unsupported PDF and missing certificate for Office.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ExtensionDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$entry=Join-Path $ExtensionDirectory 'craft_signing_extension.ps1'
if(-not(Test-Path -LiteralPath $entry -PathType Leaf)){throw 'ENTRY_MISSING'}
$dir=Join-Path ([IO.Path]::GetTempPath()) ('craft-ext-negative-'+[Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($dir)
try {
  $pdf=Join-Path $dir 'example.pdf'
  $docx=Join-Path $dir 'example.docx'
  [IO.File]::WriteAllBytes($pdf,[byte[]](37,80,68,70,45,49,46,55))
  [IO.File]::WriteAllBytes($docx,[byte[]](80,75,3,4))
  $cases=@(
    @{name='PDF_NOT_SUPPORTED';input=$pdf;pattern='CRAFT_EXTENSION_UNSUPPORTED_FORMAT'},
    @{name='CERT_REQUIRED';input=$docx;pattern='CRAFT_EXTENSION_CERTIFICATE_REQUIRED'}
  )
  foreach($case in $cases){
    $rejected=$false
    try { & $entry -Mode Sign -InputPath $case.input 2>&1 | Out-Null }
    catch { if($_.Exception.Message -like ('*'+$case.pattern+'*')){$rejected=$true}else{throw} }
    if(-not $rejected){throw ('NEGATIVE_CASE_FAILED:'+ $case.name)}
    Write-Output ('NEGATIVE_'+$case.name+'=PASS')
  }
  if(Test-Path -LiteralPath (Join-Path $dir 'example.signed.docx')){throw 'UNEXPECTED_OUTPUT'}
  'NEGATIVE_TESTS=2/2 PASS'
} finally {Remove-Item -LiteralPath $dir -Recurse -Force}
