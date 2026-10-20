#requires -Version 7.0
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$ExtensionDirectory,
 [string]$DssReportPath='C:\Users\User\Documents\PdfCraft-DSS-local\validation-20261020\dss-response.json',
 [string]$ExpectedDssSha256='2AFC4BC9C44E9D975C89E0F7C19D49A26809B7991E5C9EE87507B0308C53857A',
 [string]$SignedPdfPath=(Join-Path $env:TEMP 'craft-extension-qa-v2-20261020\adapter-visible-btrust.pdf'),
 [string]$ExpectedSignedPdfSha256='55C20AFA37872F69E65E919081CBAAE9FB8844FA86EAE6BD0F3EDF55F69988B4'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$names=@('craft_signing_extension.ps1','craft_signing_interactive.ps1','office_opc_sign.ps1','opc_signature_windows.ps1','pdfcraft_pades_adapter.ps1','install_craft_signing_extension_v2.ps1','build_extension_dev_zip.ps1')
foreach($name in $names){
 $file=Join-Path $ExtensionDirectory $name
 if(-not(Test-Path -LiteralPath $file -PathType Leaf)){throw "GATE_MISSING:$name"}
 $tokens=$null;$errors=$null
 [void][Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw "GATE_PARSE_FAIL:$name"}
}
$entry=Get-Content -LiteralPath (Join-Path $ExtensionDirectory 'craft_signing_extension.ps1') -Raw
if($entry -notmatch 'pdfcraft_pades_adapter.ps1'){throw 'GATE_PDF_DISPATCH_MISSING'}
if($entry -notmatch 'CRAFT_EXTENSION_CERTIFICATE_REQUIRED'){throw 'GATE_CERTIFICATE_REFUSAL_MISSING'}
$adapter=Get-Content -LiteralPath (Join-Path $ExtensionDirectory 'pdfcraft_pades_adapter.ps1') -Raw
if($adapter -notmatch 'sign_document'){throw 'GATE_PDF_SIGN_MISSING'}
$qes='PENDING'
$qesDocument=$null
if(Test-Path -LiteralPath $DssReportPath -PathType Leaf){
 $actual=(Get-FileHash -LiteralPath $DssReportPath -Algorithm SHA256).Hash
 if($actual -ne $ExpectedDssSha256){throw 'DSS_REPORT_SHA256_MISMATCH'}
 if(-not(Test-Path -LiteralPath $SignedPdfPath -PathType Leaf)){throw 'DSS_SIGNED_PDF_MISSING'}
 $pdfHash=(Get-FileHash -LiteralPath $SignedPdfPath -Algorithm SHA256).Hash
 if($pdfHash -ne $ExpectedSignedPdfSha256){throw 'DSS_SIGNED_PDF_SHA256_MISMATCH'}
 $report=Get-Content -LiteralPath $DssReportPath -Raw|ConvertFrom-Json
 $signatures=@($report.SimpleReport.signatureOrTimestampOrEvidenceRecord)
 if($report.SimpleReport.SignaturesCount -ne 1 -or $report.SimpleReport.ValidSignaturesCount -ne 1 -or $signatures.Count -ne 1){throw 'DSS_SIGNATURE_COUNT_MISMATCH'}
 $sig=$signatures[0].Signature
 if($sig.Indication -ne 'TOTAL_PASSED' -or $sig.SignatureLevel.value -ne 'QESig' -or $sig.SignatureFormat -ne 'PAdES-BASELINE-B'){throw 'DSS_QES_CRITERIA_NOT_MET'}
 if($report.SimpleReport.DocumentName -ne 'adapter-visible-btrust.pdf'){throw 'DSS_DOCUMENT_IDENTITY_MISMATCH'}
 $qes='PASS_SPECIFIC_PDF'
 $qesDocument=$report.SimpleReport.DocumentName
}
[pscustomobject]@{
 schema='craft.extension.release-gate.v4'
 development_scripts='PASS'
 pdf_adapter='PRESENT'
 real_btrust_hardware='PASS_PREVIOUS_TEST'
 office_opc_unit_tests='PASS_PREVIOUS_TEST'
 office_interoperability='PENDING'
 independent_qes_validation=$qes
 qes_document=$qesDocument
 qes_pdf_sha256=if($qes -eq 'PASS_SPECIFIC_PDF'){$pdfHash}else{$null}
 trusted_exe='PENDING'
 signed_msi='PENDING'
 release='NO_GO'
}|ConvertTo-Json -Compress
