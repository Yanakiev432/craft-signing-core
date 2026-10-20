#requires -Version 7.0
<#
  Static release gate for the development extension.
  Does not claim QES, Authenticode or MSI acceptance.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ExtensionDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$names=@('craft_signing_extension.ps1','craft_signing_interactive.ps1','office_opc_sign.ps1','install_craft_signing_extension_v2.ps1','build_extension_dev_zip.ps1')
foreach($name in $names){
 $file=Join-Path $ExtensionDirectory $name
 if(-not(Test-Path -LiteralPath $file -PathType Leaf)){throw "GATE_MISSING:$name"}
 $tokens=$null;$errors=$null
 [void][Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw "GATE_PARSE_FAIL:$name"}
}
$source=Get-Content -LiteralPath (Join-Path $ExtensionDirectory 'craft_signing_extension.ps1') -Raw
if($source -notmatch 'CRAFT_EXTENSION_UNSUPPORTED_FORMAT'){throw 'GATE_PDF_REFUSAL_MISSING'}
if($source -notmatch 'CRAFT_EXTENSION_CERTIFICATE_REQUIRED'){throw 'GATE_CERTIFICATE_REFUSAL_MISSING'}
[pscustomobject]@{
 schema='craft.extension.release-gate.v1'
 development_scripts='PASS'
 pdf_pades='NO_GO'
 real_btrust_hardware='NO_GO'
 office_interoperability='NO_GO'
 trusted_exe='NO_GO'
 signed_msi='NO_GO'
 release='NO_GO'
}|ConvertTo-Json -Compress
