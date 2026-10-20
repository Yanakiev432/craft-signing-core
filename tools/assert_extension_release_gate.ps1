#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ExtensionDirectory)
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
[pscustomobject]@{
 schema='craft.extension.release-gate.v2'
 development_scripts='PASS'
 pdf_adapter='PRESENT'
 real_btrust_hardware='PASS_PREVIOUS_TEST'
 office_opc_unit_tests='PASS_PREVIOUS_TEST'
 office_interoperability='PENDING'
 independent_qes_validation='PENDING'
 trusted_exe='PENDING'
 signed_msi='PENDING'
 release='NO_GO'
}|ConvertTo-Json -Compress
