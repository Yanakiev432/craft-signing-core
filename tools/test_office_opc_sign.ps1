#requires -Version 7.0
# Synthetic OPC packaging test only: never touches the B-Trust token or Office user files.
$ErrorActionPreference = 'Stop'
$signer = Join-Path $PSScriptRoot 'office_opc_sign.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) ("craft-opc-test-"+[Guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $root)
function New-OpcFixture([string]$path,[hashtable]$parts) {
    $fs = [IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite)
    try {
        $archive=[IO.Compression.ZipArchive]::new($fs,[IO.Compression.ZipArchiveMode]::Create,$true)
        try {
            foreach($part in $parts.Keys) {
                $entry=$archive.CreateEntry($part)
                $writer=[IO.StreamWriter]::new($entry.Open(),[Text.Encoding]::UTF8)
                try { $writer.Write($parts[$part]) } finally { $writer.Dispose() }
            }
        } finally { $archive.Dispose() }
    } finally { $fs.Dispose() }
}
$relationships='<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="{0}"/></Relationships>'
$typesDoc='<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
$typesCell='<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'
$doc=@{
    '[Content_Types].xml' = $typesDoc
    '_rels/.rels' = [string]::Format($relationships,'word/document.xml')
    'word/document.xml' = '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Craft OPC test</w:t></w:r></w:p></w:body></w:document>'
}
$sheet=@{
    '[Content_Types].xml'=$typesCell
    '_rels/.rels'=[string]::Format($relationships,'xl/workbook.xml')
    'xl/workbook.xml'='<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>'
    'xl/_rels/workbook.xml.rels'='<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'
    'xl/worksheets/sheet1.xml'='<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>Craft OPC test</t></is></c></row></sheetData></worksheet>'
}
$ok=0
try {
    foreach($case in @(@{Ext='docx';Parts=$doc;Tamper='word/document.xml'}, @{Ext='xlsx';Parts=$sheet;Tamper='xl/worksheets/sheet1.xml'})) {
        $src=Join-Path $root ('original.'+$case.Ext)
        $dst=Join-Path $root ('signed.'+$case.Ext)
        New-OpcFixture $src $case.Parts
        $resultText = & $signer -Mode Sign -InputPath $src -OutputPath $dst -SelfSignedTest
        $result=($resultText | Out-String | ConvertFrom-Json)
        if($result.integrity -ne 'Success' -or $result.signature_count -ne 1) { throw "Signing failed for $($case.Ext)" }
        $verifiedText=& $signer -Mode Verify -InputPath $dst
        $verified=($verifiedText | Out-String | ConvertFrom-Json)
        if($verified.integrity -ne 'Success') {throw "Verification failed for $($case.Ext)"}
        # Alter one *signed* part without touching cryptographic private keys.
        $zip=[IO.Compression.ZipFile]::Open($dst,[IO.Compression.ZipArchiveMode]::Update)
        try {
            $entry=$zip.GetEntry($case.Tamper)
            if(!$entry) {throw 'Expected tamper target missing'}
            $entry.Delete()
            $newEntry=$zip.CreateEntry($case.Tamper)
            $writer=[IO.StreamWriter]::new($newEntry.Open(),[Text.Encoding]::UTF8)
            try {$writer.Write('malicious tamper')}finally{$writer.Dispose()}
        }finally{$zip.Dispose()}
        $tamperRejected=$false
        try { $null = & $signer -Mode Verify -InputPath $dst 2>&1 }catch {$tamperRejected=$true}
        if(-not $tamperRejected) {throw "Tampered $($case.Ext) was not rejected"}
        $ok++
        "OPC_TEST_$($case.Ext.ToUpperInvariant())=PASS sign/verify/tamper-rejection"
    }
    "OPC_TESTS=$ok/2 PASS"
}
finally {
    if(Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
}
