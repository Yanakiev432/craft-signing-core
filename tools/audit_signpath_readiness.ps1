#requires -Version 7.0
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$RepositoryDirectory,
 [Parameter(Mandatory)][string]$MsiPath,
 [string]$OutputPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$git=(Get-Command git.exe -ErrorAction Stop).Source
$repo=(Resolve-Path -LiteralPath $RepositoryDirectory).ProviderPath
$msi=(Resolve-Path -LiteralPath $MsiPath).ProviderPath
$commit=(& $git -C $repo rev-parse HEAD).Trim()
$branch=(& $git -C $repo branch --show-current).Trim()
$dirty=@(& $git -C $repo status --porcelain).Count -gt 0
$tags=@(& $git -C $repo tag -l)
$licenses=@(Get-ChildItem -LiteralPath $repo -File|Where-Object {$_.Name -match '^LICEN[CS]E([.-].*)?$'}|Select-Object -ExpandProperty Name)
$signature=Get-AuthenticodeSignature -LiteralPath $msi
$report=[ordered]@{
 schema='craft.signpath.readiness.v1'
 generated_utc=[DateTime]::UtcNow.ToString('o')
 repository_commit=$commit
 branch=$branch
 working_tree_clean=(-not $dirty)
 version_tags=$tags
 license_files=$licenses
 msi_sha256=(Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash
 msi_authenticode=$signature.Status.ToString()
 signpath_approved=$false
 production_release='NO_GO'
 blockers=@()
}
if($dirty){$report.blockers+= 'WORKTREE_DIRTY'}
if($tags.Count -eq 0){$report.blockers+= 'NO_VERSION_TAGS'}
if($licenses.Count -eq 0){$report.blockers+= 'LICENSE_FILES_MISSING'}
if($signature.Status -ne 'Valid'){$report.blockers+= 'MSI_NOT_TRUSTED_SIGNED'}
$report.blockers+='SIGNPATH_APPROVAL_NOT_VERIFIED'
$json=$report|ConvertTo-Json -Depth 6
if($OutputPath){[IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath),$json,[Text.UTF8Encoding]::new($false))}
$json
