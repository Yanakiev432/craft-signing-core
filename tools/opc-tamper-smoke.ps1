# Negative OPC tests: unsigned injected part and changed signed XML MUST be rejected.
# Does not modify signed originals or user documents; creates copies in test fixtures.
param([Parameter(Mandatory=$true)][string]$FixtureDirectory)
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
Set-StrictMode -Version Latest
Add-Type -AssemblyName 'System.IO.Compression'
Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$work=(Resolve-Path -LiteralPath $FixtureDirectory).Path
$target=(Resolve-Path -LiteralPath (Join-Path $root 'target')).Path
if(-not $work.StartsWith($target + '\',[StringComparison]::OrdinalIgnoreCase)){throw 'Fixtures must be inside signing core target/'}
function Verify-File([string]$path,[bool]$shouldPass){
    & cargo run --locked --example opc_verify_smoke -- $path
    $status=$LASTEXITCODE
    if($shouldPass -and $status -ne 0){throw "ORIGINAL_SIGNED_VERIFICATION_FAILED: $path"}
    if(-not $shouldPass -and $status -eq 0){throw "TAMPER_ACCEPTED_UNSAFE: $path"}
}
Push-Location $root
try{
  $docx=Join-Path $work 'signed.docx'
  $xlsx=Join-Path $work 'signed.xlsx'
  Verify-File $docx $true
  Verify-File $xlsx $true
  'POSITIVE_SIGNATURE_VERIFY_PASS=2/2'

  # Repack via Create, not Update: ZipArchive Update can discard OPC-required
  # ZIP data descriptors and yield a false rejection before coverage validation.
  $withExtra=Join-Path $work 'tampered-unsigned-extra-v2.docx'
  $sourceStream=[IO.File]::OpenRead($docx)
  $destStream=[IO.File]::Open($withExtra,[IO.FileMode]::CreateNew)
  $srcZip=[IO.Compression.ZipArchive]::new($sourceStream,[IO.Compression.ZipArchiveMode]::Read,$false)
  $destZip=[IO.Compression.ZipArchive]::new($destStream,[IO.Compression.ZipArchiveMode]::Create,$false)
  try {
    foreach($originalEntry in $srcZip.Entries){
      $entry=$destZip.CreateEntry($originalEntry.FullName,[IO.Compression.CompressionLevel]::Optimal)
      $ins=$originalEntry.Open()
      $outs=$entry.Open()
      try{$ins.CopyTo($outs)}finally{$outs.Dispose();$ins.Dispose()}
    }
    $entry=$destZip.CreateEntry('word/unlinked-extra.xml')
    $writer=[IO.StreamWriter]::new($entry.Open(),[Text.UTF8Encoding]::new($false))
    try{$writer.Write('<?xml version="1.0"?><extra>unsigned part</extra>')}finally{$writer.Dispose()}
  } finally {$destZip.Dispose();$srcZip.Dispose();$sourceStream.Dispose();$destStream.Dispose()}
  Verify-File $withExtra $false
  'UNSIGNED_PART_REJECTION_PASS'

  $changed=Join-Path $work 'tampered-content.xlsx'
  Copy-Item -LiteralPath $xlsx -Destination $changed -ErrorAction Stop
  $zip=[System.IO.Compression.ZipFile]::Open($changed,[System.IO.Compression.ZipArchiveMode]::Update)
  try {
     $entry=$zip.GetEntry('xl/worksheets/sheet1.xml')
     if(-not $entry){throw 'signed worksheet missing'}
     $reader=[System.IO.StreamReader]::new($entry.Open())
     try{$original=$reader.ReadToEnd()}finally{$reader.Dispose()}
     if(-not $original.Contains('Craft test')){throw 'fixture content unexpected'}
     $entry.Delete()
     $entry=$zip.CreateEntry('xl/worksheets/sheet1.xml')
     $writer=[System.IO.StreamWriter]::new($entry.Open(),[System.Text.UTF8Encoding]::new($false))
     try{$writer.Write($original.Replace('Craft test','Tampered content'))}finally{$writer.Dispose()}
  } finally {$zip.Dispose()}
  Verify-File $changed $false
  'SIGNED_CONTENT_TAMPER_REJECTION_PASS'
  'OPC_NEGATIVE_TESTS_PASS=2/2'
} finally {Pop-Location}
# Deliberate negative checks leave child exit code 1; normalize only after ALL assertions.
$global:LASTEXITCODE=0
