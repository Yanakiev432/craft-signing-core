# Live, local OPC integrity test with explicit NON-QES development signing key.
# Creates minimal DOCX/XLSX fixtures under target/; never modifies personal documents.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName 'System.IO.Compression'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$work = Join-Path $root ('target\opc-live-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force -Path $work | Out-Null
$cert = Get-ChildItem 'Cert:\CurrentUser\My' |
  Where-Object { $_.Subject -eq 'CN=Craft Open Source Local Code Signing' -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) } |
  Select-Object -First 1
if (-not $cert) { throw 'Development test certificate missing. Refusing to select any other signing identity.' }

function New-TestPackage([string]$name, [System.Collections.IDictionary]$parts) {
    $path = Join-Path $work $name
    $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::CreateNew)
    $zip = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Create, $false)
    try {
        foreach ($key in $parts.Keys) {
            $entry = $zip.CreateEntry([string]$key)
            $writer = [System.IO.StreamWriter]::new($entry.Open(), [System.Text.UTF8Encoding]::new($false))
            try { $writer.Write([string]$parts[$key]) } finally { $writer.Dispose() }
        }
    } finally { $zip.Dispose(); $stream.Dispose() }
    return $path
}
$docx = [ordered]@{
  '[Content_Types].xml' = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
  '_rels/.rels' = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'
  'word/document.xml' = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Craft test document</w:t></w:r></w:p><w:sectPr/></w:body></w:document>'
}
$xlsx = [ordered]@{
  '[Content_Types].xml' = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'
  '_rels/.rels' = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
  'xl/workbook.xml' = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Test" sheetId="1" r:id="rId1"/></sheets></workbook>'
  'xl/_rels/workbook.xml.rels' = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'
  'xl/worksheets/sheet1.xml' = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Craft test</t></is></c></row></sheetData></worksheet>'
}
Push-Location $root
try {
    foreach ($name in @('docx','xlsx')) {
        $parts = if ($name -eq 'docx') { $docx } else { $xlsx }
        $inputFile = New-TestPackage ("unsigned.$name") $parts
        $outputFile = Join-Path $work ("signed.$name")
        Write-Output "RUNNING_NATIVE_$($name.ToUpperInvariant())"
        & cargo run --locked --example opc_sign_smoke -- $inputFile $outputFile $cert.Thumbprint
        if ($LASTEXITCODE -ne 0) { throw "NATIVE_$($name)_SIGN_OR_VERIFY_FAILED ($LASTEXITCODE)" }
        Write-Output "SIGNED_$($name)_SHA256=$((Get-FileHash $outputFile -Algorithm SHA256).Hash)"
    }
    Write-Output 'LIVE_OPC_ROUNDTRIP_PASS=2/2'
    Write-Output "FIXTURE_DIRECTORY=$work"
} finally { Pop-Location }
