# Synthetic Excel visual signature pilot using the same PDFCraft-style image as the Word pilot.
# Adds a SpreadsheetDrawingML oneCellAnchor image above sheet cells (E2 onward).
# An image is NOT a native clickable Excel signature line; acceptance remains separate.
[CmdletBinding()]
param(
 [string]$SyntheticInput='C:\Users\User\Documents\GitHub\craft-signing-core\target\office-realistic-interop-20261023\sample.xlsx',
 [string]$PreviewPath='C:\Users\User\Documents\GitHub\craft-signing-core\target\pdfcraft-office-appearance-2dc971c3fa2b4744acd78cf3e12638be\SignaturePreview.png'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName WindowsBase
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$target=(Resolve-Path (Join-Path $repo 'target')).Path
$src=(Resolve-Path $SyntheticInput).Path
$img=(Resolve-Path $PreviewPath).Path
foreach($p in @($src,$img)){
 if(-not $p.StartsWith($target+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Only synthetic target source allowed'}
}
if([IO.Path]::GetExtension($src) -ine '.xlsx'){throw 'Expected XLSX'}
$folder=Join-Path $target ('pdfcraft-excel-appearance-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $folder|Out-Null
$unsigned=Join-Path $folder 'Excel_PdfCraft_Appearance_Unsigned.xlsx'
$signed=Join-Path $folder 'Excel_PdfCraft_Appearance_Software_Signed.xlsx'
$relNs='http://schemas.openxmlformats.org/package/2006/relationships'
$rNs='http://schemas.openxmlformats.org/officeDocument/2006/relationships'
$sNs='http://schemas.openxmlformats.org/spreadsheetml/2006/main'
$ctNs='http://schemas.openxmlformats.org/package/2006/content-types'
$sheetRid='rIdCraftSignature'+[Guid]::NewGuid().ToString('N')
$drawRid='rIdCraftSignatureImage'
$parts=@(
 'xl/drawings/craftSignatureDrawing1.xml',
 'xl/drawings/_rels/craftSignatureDrawing1.xml.rels',
 'xl/media/CraftSignaturePreview.png')
$inputZip=[IO.Compression.ZipFile]::OpenRead($src)
$outputZip=[IO.Compression.ZipFile]::Open($unsigned,[IO.Compression.ZipArchiveMode]::Create)
$sourceHash=(Get-FileHash $src -Algorithm SHA256).Hash
try {
 if(-not $inputZip.GetEntry('xl/worksheets/sheet1.xml')){throw 'Source needs sheet1'}
 foreach($part in $parts){
  if($inputZip.GetEntry($part)){throw ('Existing part collision '+$part)}
 }
 if($inputZip.GetEntry('xl/worksheets/_rels/sheet1.xml.rels')){throw 'Pilot only supports synthetic worksheet without drawing relationships'}
 foreach($entry in $inputZip.Entries){
  $new=$outputZip.CreateEntry($entry.FullName,[IO.Compression.CompressionLevel]::Optimal)
  $read=$entry.Open()
  try{
   if($entry.FullName -in @('xl/worksheets/sheet1.xml','[Content_Types].xml')){
    $reader=[IO.StreamReader]::new($read)
    try{$raw=$reader.ReadToEnd()}finally{$reader.Dispose()}
    $xml=[Xml.XmlDocument]::new();$xml.PreserveWhitespace=$true;$xml.LoadXml($raw)
    if($entry.FullName -eq 'xl/worksheets/sheet1.xml'){
     if($xml.DocumentElement.NamespaceURI -ne $sNs){throw 'Unexpected worksheet namespace'}
     if(@($xml.DocumentElement.ChildNodes|Where-Object{$_ -is [Xml.XmlElement] -and $_.LocalName -eq 'drawing'}).Count){throw 'Existing drawing'}
     $node=$xml.CreateElement('drawing',$sNs)
     $node.SetAttribute('id',$rNs,$sheetRid)
     $end=$xml.DocumentElement.ChildNodes|Where-Object{$_ -is [Xml.XmlElement] -and $_.LocalName -in @('legacyDrawing','legacyDrawingHF','picture','oleObjects','extLst')}|Select-Object -First 1
     if($end){[void]$xml.DocumentElement.InsertBefore($node,$end)}else{[void]$xml.DocumentElement.AppendChild($node)}
    }else{
     if($xml.DocumentElement.NamespaceURI -ne $ctNs){throw 'Unexpected content-types namespace'}
     $over=$xml.CreateElement('Override',$ctNs)
     $over.SetAttribute('PartName','/xl/drawings/craftSignatureDrawing1.xml')
     $over.SetAttribute('ContentType','application/vnd.openxmlformats-officedocument.drawing+xml')
     [void]$xml.DocumentElement.AppendChild($over)
     if(-not @($xml.DocumentElement.ChildNodes|Where-Object{$_ -is [Xml.XmlElement] -and $_.LocalName -eq 'Default' -and $_.GetAttribute('Extension') -eq 'png'}).Count){
      $typ=$xml.CreateElement('Default',$ctNs);$typ.SetAttribute('Extension','png');$typ.SetAttribute('ContentType','image/png')
      [void]$xml.DocumentElement.AppendChild($typ)
     }
    }
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($xml.OuterXml)
    $write=$new.Open();try{$write.Write($bytes,0,$bytes.Length)}finally{$write.Dispose()}
   }else{
    $write=$new.Open();try{$read.CopyTo($write)}finally{$write.Dispose()}
   }
  }finally{$read.Dispose()}
 }
 $sheetRels=@"
<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="$relNs">
 <Relationship Id="$sheetRid" Type="$rNs/drawing" Target="../drawings/craftSignatureDrawing1.xml"/>
</Relationships>
"@
 $drawingRels=@"
<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="$relNs">
 <Relationship Id="$drawRid" Type="$rNs/image" Target="../media/CraftSignaturePreview.png"/>
</Relationships>
"@
 $drawing=@"
<?xml version="1.0" encoding="utf-8"?>
<xdr:wsDr xmlns:xdr="http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing"
          xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
          xmlns:r="$rNs">
 <xdr:oneCellAnchor>
   <xdr:from><xdr:col>4</xdr:col><xdr:colOff>0</xdr:colOff><xdr:row>1</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:from>
   <xdr:ext cx="4876800" cy="1414275"/>
   <xdr:pic>
    <xdr:nvPicPr><xdr:cNvPr id="1" name="Craft digital signature appearance" descr="PdfCraft-style signed appearance"/><xdr:cNvPicPr><a:picLocks noChangeAspect="1"/></xdr:cNvPicPr></xdr:nvPicPr>
    <xdr:blipFill><a:blip r:embed="$drawRid"/><a:stretch><a:fillRect/></a:stretch></xdr:blipFill>
    <xdr:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="4876800" cy="1414275"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></xdr:spPr>
   </xdr:pic>
   <xdr:clientData/>
 </xdr:oneCellAnchor>
</xdr:wsDr>
"@
 $items=[ordered]@{
  'xl/worksheets/_rels/sheet1.xml.rels'=$sheetRels
  'xl/drawings/craftSignatureDrawing1.xml'=$drawing
  'xl/drawings/_rels/craftSignatureDrawing1.xml.rels'=$drawingRels
 }
 foreach($key in $items.Keys){
  [xml]$probe=$items[$key]
  $bytes=[Text.UTF8Encoding]::new($false).GetBytes($items[$key])
  $e=$outputZip.CreateEntry($key,[IO.Compression.CompressionLevel]::Optimal)
  $w=$e.Open();try{$w.Write($bytes,0,$bytes.Length)}finally{$w.Dispose()}
 }
 $imgEntry=$outputZip.CreateEntry('xl/media/CraftSignaturePreview.png',[IO.Compression.CompressionLevel]::Optimal)
 $stream=[IO.File]::OpenRead($img);$write=$imgEntry.Open()
 try{$stream.CopyTo($write)}finally{$stream.Dispose();$write.Dispose()}
}finally{$inputZip.Dispose();$outputZip.Dispose()}
$cert=Get-ChildItem Cert:\CurrentUser\My|Where-Object{$_.Subject -eq 'CN=Craft Open Source Local Code Signing' -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date)}|Select-Object -First 1
if(-not $cert){throw 'Disposable software signing identity missing'}
$env:PATH=(Join-Path $env:USERPROFILE '.cargo\bin')+';'+$env:PATH
Push-Location $repo
try {
 & cargo run --locked --offline --quiet --example opc_sign_smoke -- $unsigned $signed $cert.Thumbprint
 if($LASTEXITCODE -ne 0){throw 'Native OPC signing failed'}
}finally{Pop-Location}
$pkg=[IO.Packaging.Package]::Open($signed,[IO.FileMode]::Open,[IO.FileAccess]::Read)
try {
 $mgr=[IO.Packaging.PackageDigitalSignatureManager]::new($pkg)
 if($mgr.Signatures.Count -ne 1 -or $mgr.VerifySignatures($false).ToString() -ne 'Success'){throw 'Windows independent OPC integrity failure'}
}finally{$pkg.Dispose()}
$zip=[IO.Compression.ZipFile]::OpenRead($signed)
try {
 foreach($part in $parts){if(-not $zip.GetEntry($part)){throw ('Missing signed visual part '+$part)}}
}finally{$zip.Dispose()}
if((Get-FileHash $src -Algorithm SHA256).Hash -ne $sourceHash){throw 'Original source changed'}
[ordered]@{
 schema='craft.excel.pdfcraft-appearance-pilot.v1'
 status='XLSX_DRAWING_IMAGE_AND_OPC_SIGNED_TEST_CERT_PASS'
 unsigned=$unsigned
 signed=$signed
 signed_sha256=(Get-FileHash $signed -Algorithm SHA256).Hash
 visual_drawing='SpreadsheetDrawingML image at column E / row 2'
 native_office_signatureline='NOT_IMPLEMENTED_IN_XLSX'
 windows_opc='PASS'
 microsoft_excel_import='NOT_TESTED'
 eidas_qes='NOT_ESTABLISHED'
}|ConvertTo-Json -Depth 5|Set-Content (Join-Path $folder 'acceptance.json') -Encoding UTF8
'CRAFT_EXCEL_VISIBLE_PILOT=PASS'
'MANIFEST='+(Join-Path $folder 'acceptance.json')
'SIGNED_EXCEL='+$signed
