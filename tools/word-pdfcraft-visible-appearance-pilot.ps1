# Craft Office visual signature research pilot.
# Appearance layout adapted from PdfCraft sign_ui.rs (96px bordered preview, name-left / details-right).
# Synthetic Word file and development certificate ONLY. Native Office signature-line recognition
# MUST be separately assessed by Microsoft Word; this script does not claim that it works.
[CmdletBinding()]
param(
 [string]$SyntheticInput='C:\Users\User\Documents\GitHub\craft-signing-core\target\office-realistic-interop-20261023\sample.docx'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName WindowsBase
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$target=(Resolve-Path (Join-Path $repo 'target')).Path
$source=(Resolve-Path $SyntheticInput).Path
if(-not ($source.StartsWith($target+'\',[StringComparison]::OrdinalIgnoreCase)) -or
    ([IO.Path]::GetExtension($source) -ine '.docx')){
 throw 'Synthetic DOCX under signing-core target required'
}
if(-not (Test-Path $source -PathType Leaf)){throw 'Source missing'}
$cert=Get-ChildItem Cert:\CurrentUser\My |
 Where-Object {$_.Subject -eq 'CN=Craft Open Source Local Code Signing' -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date)} |
 Select-Object -First 1
if(-not $cert){throw 'Expected disposable local development signing certificate'}
$fixture=Join-Path $target ('pdfcraft-office-appearance-'+([Guid]::NewGuid().ToString('N')))
New-Item -ItemType Directory -Path $fixture -ErrorAction Stop|Out-Null
$preview=Join-Path $fixture 'SignaturePreview.png'
$unsigned=Join-Path $fixture 'Word_PdfCraft_Appearance_Unsigned.docx'
$signed=Join-Path $fixture 'Word_PdfCraft_Appearance_Software_Signed.docx'
$manifest=Join-Path $fixture 'acceptance.json'
$signer='Craft Open Source Local Code Signing'
$stamp=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
# PdfCraft preview pattern: a large name on the left, compact details on the right,
# with thin neutral border, light surface, restrained color and information hierarchy.
$width=1000;$height=290
$bmp=[Drawing.Bitmap]::new($width,$height)
$g=[Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode=[Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.TextRenderingHint=[Drawing.Text.TextRenderingHint]::AntiAliasGridFit
$background=[Drawing.SolidBrush]::new([Drawing.Color]::White)
$ink=[Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(32,42,60))
$muted=[Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(80,91,109))
$hairline=[Drawing.Pen]::new([Drawing.Color]::FromArgb(173,183,195),2)
$divider=[Drawing.Pen]::new([Drawing.Color]::FromArgb(218,224,230),2)
$heading=[Drawing.Font]::new('Segoe UI',24,[Drawing.FontStyle]::Regular,[Drawing.GraphicsUnit]::Pixel)
$body=[Drawing.Font]::new('Segoe UI',26,[Drawing.FontStyle]::Regular,[Drawing.GraphicsUnit]::Pixel)
$large=[Drawing.Font]::new('Segoe UI',37,[Drawing.FontStyle]::Bold,[Drawing.GraphicsUnit]::Pixel)
$small=[Drawing.Font]::new('Segoe UI',20,[Drawing.FontStyle]::Regular,[Drawing.GraphicsUnit]::Pixel)
try {
 $g.FillRectangle($background,0,0,$width,$height)
 $g.DrawRectangle($hairline,2,2,$width-5,$height-5)
 $g.DrawLine($divider,500,25,500,$height-25)
 $g.DrawString('DIGITAL SIGNATURE',$heading,$muted,28,22)
 $g.DrawString('Craft test signer',$large,$ink,[Drawing.RectangleF]::new(26,100,454,90))
 $g.DrawString('Digitally signed by',$small,$muted,529,31)
 $g.DrawString($signer,$body,$ink,[Drawing.RectangleF]::new(529,75,440,86))
 $g.DrawString('Date: '+$stamp,$small,$ink,529,178)
 $g.DrawString('OPC / XML-DSig',$small,$muted,529,223)
 $bmp.Save($preview,[Drawing.Imaging.ImageFormat]::Png)
}finally{
 foreach($obj in @($heading,$body,$large,$small,$divider,$hairline,$ink,$muted,$background,$g,$bmp)){$obj.Dispose()}
}
$wNs='http://schemas.openxmlformats.org/wordprocessingml/2006/main'
$rNs='http://schemas.openxmlformats.org/officeDocument/2006/relationships'
$vNs='urn:schemas-microsoft-com:vml'
$oNs='urn:schemas-microsoft-com:office:office'
$relNs='http://schemas.openxmlformats.org/package/2006/relationships'
$ctNs='http://schemas.openxmlformats.org/package/2006/content-types'
$rid='rIdCraftVisualSignature'+[Guid]::NewGuid().ToString('N')
$id=('{'+[Guid]::NewGuid().ToString('D').ToUpperInvariant()+'}')
$originHash=(Get-FileHash $source -Algorithm SHA256).Hash
# ZIP write no existing DOCX is ever mutated.
$inputZip=[IO.Compression.ZipFile]::OpenRead($source)
$outputZip=[IO.Compression.ZipFile]::Open($unsigned,[IO.Compression.ZipArchiveMode]::Create)
try{
 if(-not $inputZip.GetEntry('word/document.xml')){throw 'DOCX missing document.xml'}
 foreach($entry in $inputZip.Entries){
  $output=$outputZip.CreateEntry($entry.FullName,[IO.Compression.CompressionLevel]::Optimal)
  $data=$entry.Open()
  try{
   if($entry.FullName -eq 'word/document.xml'){
    $reader=[IO.StreamReader]::new($data)
    try{$xmltext=$reader.ReadToEnd()}finally{$reader.Dispose()}
    $doc=[Xml.XmlDocument]::new();$doc.PreserveWhitespace=$true;$doc.LoadXml($xmltext)
    $ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);$ns.AddNamespace('w',$wNs)
    $body=$doc.SelectSingleNode('/w:document/w:body',$ns)
    if(-not $body){throw 'Word XML body missing'}
    $para=$doc.CreateElement('w','p',$wNs)
    $run=$doc.CreateElement('w','r',$wNs)
    $pict=$doc.CreateElement('w','pict',$wNs)
    $shape=$doc.CreateElement('v','shape',$vNs)
    $shape.SetAttribute('id','_x0000_s'+(Get-Random -Minimum 2000 -Maximum 40000))
    $shape.SetAttribute('style','width:330pt;height:95pt')
    $shape.SetAttribute('filled','f')
    $shape.SetAttribute('stroked','f')
    $dataImage=$doc.CreateElement('v','imagedata',$vNs)
    $dataImage.SetAttribute('id',$rNs,$rid)
    $dataImage.SetAttribute('title',$oNs,'Craft digital signature appearance')
    [void]$shape.AppendChild($dataImage)
    $line=$doc.CreateElement('o','signatureline',$oNs)
    $line.SetAttribute('ext',$vNs,'edit')
    $line.SetAttribute('id',$id)
    $line.SetAttribute('provid','{00000000-0000-0000-0000-000000000000}')
    $line.SetAttribute('issignatureline','t')
    $line.SetAttribute('showsigndate','t')
    $line.SetAttribute('allowcomments','f')
    $line.SetAttribute('suggestedsigner','Craft test signer')
    $line.SetAttribute('suggestedsigner2','Craft Open Source')
    [void]$shape.AppendChild($line)
    [void]$pict.AppendChild($shape);[void]$run.AppendChild($pict);[void]$para.AppendChild($run)
    $section=$body.SelectSingleNode('w:sectPr',$ns)
    if($section){[void]$body.InsertBefore($para,$section)}else{[void]$body.AppendChild($para)}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($doc.OuterXml)
    $dest=$output.Open();try{$dest.Write($bytes,0,$bytes.Length)}finally{$dest.Dispose()}
   }elseif($entry.FullName -eq 'word/_rels/document.xml.rels'){
    $reader=[IO.StreamReader]::new($data)
    try{$xmltext=$reader.ReadToEnd()}finally{$reader.Dispose()}
    $doc=[Xml.XmlDocument]::new();$doc.PreserveWhitespace=$true;$doc.LoadXml($xmltext)
    if($doc.DocumentElement.NamespaceURI -ne $relNs){throw 'Unexpected relationships namespace'}
    if(@($doc.DocumentElement.ChildNodes|Where-Object{$_ -is [Xml.XmlElement] -and $_.GetAttribute('Id') -eq $rid}).Count -gt 0){throw 'Duplicate relationship ID'}
    $link=$doc.CreateElement('Relationship',$relNs)
    $link.SetAttribute('Id',$rid)
    $link.SetAttribute('Type','http://schemas.openxmlformats.org/officeDocument/2006/relationships/image')
    $link.SetAttribute('Target','media/CraftSignaturePreview.png')
    [void]$doc.DocumentElement.AppendChild($link)
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($doc.OuterXml)
    $dest=$output.Open();try{$dest.Write($bytes,0,$bytes.Length)}finally{$dest.Dispose()}
   }elseif($entry.FullName -eq '[Content_Types].xml'){
    $reader=[IO.StreamReader]::new($data)
    try{$xmltext=$reader.ReadToEnd()}finally{$reader.Dispose()}
    $doc=[Xml.XmlDocument]::new();$doc.PreserveWhitespace=$true;$doc.LoadXml($xmltext)
    if(-not @($doc.DocumentElement.ChildNodes|Where-Object{$_ -is [Xml.XmlElement] -and $_.LocalName -eq 'Default' -and $_.GetAttribute('Extension') -eq 'png'}).Count){
      $typ=$doc.CreateElement('Default',$ctNs);$typ.SetAttribute('Extension','png');$typ.SetAttribute('ContentType','image/png')
      [void]$doc.DocumentElement.AppendChild($typ)
    }
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($doc.OuterXml)
    $dest=$output.Open();try{$dest.Write($bytes,0,$bytes.Length)}finally{$dest.Dispose()}
   }else{
    $dest=$output.Open();try{$data.CopyTo($dest)}finally{$dest.Dispose()}
   }
  }finally{$data.Dispose()}
 }
 if(-not $inputZip.GetEntry('word/_rels/document.xml.rels')){throw 'Synthetic source needs document relationship part'}
 $imageEntry=$outputZip.CreateEntry('word/media/CraftSignaturePreview.png',[IO.Compression.CompressionLevel]::Optimal)
 $imgData=[IO.File]::OpenRead($preview);$imgOut=$imageEntry.Open()
 try{$imgData.CopyTo($imgOut)}finally{$imgOut.Dispose();$imgData.Dispose()}
}finally{$outputZip.Dispose();$inputZip.Dispose()}
# Sign with the isolated TEST software signer, then verify before using any Office preview.
$env:PATH=(Join-Path $env:USERPROFILE '.cargo\bin')+';'+$env:PATH
Push-Location $repo
try {
 & cargo run --locked --offline --quiet --example opc_sign_smoke -- $unsigned $signed $cert.Thumbprint
 if($LASTEXITCODE -ne 0){throw 'Software OPC signing rejected pilot'}
}finally{Pop-Location}
$pkg=[IO.Packaging.Package]::Open($signed,[IO.FileMode]::Open,[IO.FileAccess]::Read)
try {
 $mgr=[IO.Packaging.PackageDigitalSignatureManager]::new($pkg)
 if($mgr.Signatures.Count -ne 1 -or $mgr.VerifySignatures($false).ToString() -ne 'Success'){throw 'Signed Word appearance failed independent Windows OPC validation'}
}finally{$pkg.Dispose()}
$z=[IO.Compression.ZipFile]::OpenRead($signed)
try {
 $e=$z.GetEntry('word/document.xml')
 $r=[IO.StreamReader]::new($e.Open());try{$body=$r.ReadToEnd()}finally{$r.Dispose()}
 [xml]$xml=$body
 $ns=[Xml.XmlNamespaceManager]::new($xml.NameTable);$ns.AddNamespace('o',$oNs);$ns.AddNamespace('v',$vNs)
 $line=$xml.SelectSingleNode('//o:signatureline',$ns)
 $img=$xml.SelectSingleNode('//v:shape/v:imagedata',$ns)
 if(-not $line -or $line.GetAttribute('id') -ne $id -or -not $img){throw 'VML signature line and appearance lost after signing'}
 if(-not $z.GetEntry('word/media/CraftSignaturePreview.png')){throw 'Embedded visible image missing'}
}finally{$z.Dispose()}
if((Get-FileHash $source -Algorithm SHA256).Hash -ne $originHash){throw 'Synthetic input changed'}
$result=[ordered]@{
 schema='craft.office.pdfcraft-appearance-pilot.v1'
 date=(Get-Date).ToString('o')
 state='DOCX_IMAGE_AND_O_SIGNATURELINE_OPC_SIGNED_TEST_CERT_PASS'
 source_path=$source
 source_sha256=$originHash
 rendered_preview=$preview
 unsigned_output=$unsigned
 signed_output=$signed
 signed_sha256=(Get-FileHash $signed -Algorithm SHA256).Hash
 source_preserved=$true
 word_media_png='PRESENT'
 word_signatureline_element='PRESENT'
 windows_opc_integrity='PASS'
 pdfcraft_design_model='name-left / details-right / neutral bordered 96px'
 no_user_private_key=$true
 certificate_trust='TEST_SIGNER_ONLY'
 office_native_signatureline_interactivity='NOT_TESTED_ON_MS_WORD'
 microsoft_word_visual_rendering='NOT_TESTED_ON_MS_WORD'
 eidas_qes='NOT_ESTABLISHED'
}
$result|ConvertTo-Json -Depth 5|Set-Content $manifest -Encoding UTF8
'CRAFT_WORD_VISIBLE_PILOT=PASS'
'MANIFEST='+$manifest
'SIGNED_WORD='+$signed
