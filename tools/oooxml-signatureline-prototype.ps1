# Experimental true OOXML Word signature-line element on SYNTHETIC DOCX only.
# Not a claim that Microsoft Word displays or accepts the line.
# No personal docs, no PIN, no token, no installed app changes.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName WindowsBase
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$target=(Resolve-Path (Join-Path $root 'target')).Path
$fixture=Get-ChildItem $target -Directory -Filter 'opc-live-*'|
 Sort-Object LastWriteTime -Descending|Where-Object {Test-Path (Join-Path $_.FullName 'unsigned.docx')}|Select-Object -First 1
if(-not $fixture){throw 'No synthetic unsigned DOCX fixture'}
$source=Join-Path $fixture.FullName 'unsigned.docx'
$work=Join-Path $target ('oooxml-signline-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work |Out-Null
$modified=Join-Path $work 'unsigned-with-signatureline.docx'
$signed=Join-Path $work 'signed-with-signatureline.docx'
$cert=Get-ChildItem Cert:\CurrentUser\My|Where-Object {$_.Subject -eq 'CN=Craft Open Source Local Code Signing' -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date)}|Select-Object -First 1
if(-not $cert){throw 'Disposable development certificate missing'}
$guid=[Guid]::NewGuid().ToString('D').ToUpperInvariant()
$wNs='http://schemas.openxmlformats.org/wordprocessingml/2006/main'
$vNs='urn:schemas-microsoft-com:vml'
$oNs='urn:schemas-microsoft-com:office:office'
$sourceZip=[IO.Compression.ZipFile]::OpenRead($source)
$destZip=[IO.Compression.ZipFile]::Open($modified,[IO.Compression.ZipArchiveMode]::Create)
try{
 foreach($ent in $sourceZip.Entries){
  $new=$destZip.CreateEntry($ent.FullName,[IO.Compression.CompressionLevel]::Optimal)
  if($ent.FullName -eq 'word/document.xml'){
   $reader=[IO.StreamReader]::new($ent.Open())
   try{$orig=$reader.ReadToEnd()}finally{$reader.Dispose()}
   $xml=[Xml.XmlDocument]::new();$xml.PreserveWhitespace=$true;$xml.LoadXml($orig)
   $ns=[Xml.XmlNamespaceManager]::new($xml.NameTable)
   $ns.AddNamespace('w',$wNs)
   $body=$xml.SelectSingleNode('/w:document/w:body',$ns)
   if(-not $body){throw 'Word document body missing'}
   # actual Office namespace signatureline child of the VML rectangular shape
   $p=$xml.CreateElement('w','p',$wNs)
   $r=$xml.CreateElement('w','r',$wNs)
   $pict=$xml.CreateElement('w','pict',$wNs)
   $shape=$xml.CreateElement('v','rect',$vNs)
   $shape.SetAttribute('id','_x0000_s1025')
   $shape.SetAttribute('style','width:240pt;height:60pt')
   $shape.SetAttribute('filled','f')
   $shape.SetAttribute('stroked','t')
   $line=$xml.CreateElement('o','signatureline',$oNs)
   [void]$line.SetAttribute('ext',$vNs,'edit')
   [void]$line.SetAttribute('id','{'+$guid+'}')
   [void]$line.SetAttribute('provid','{00000000-0000-0000-0000-000000000000}')
   [void]$line.SetAttribute('issignatureline','t')
   [void]$line.SetAttribute('suggestedsigner',$oNs,'Craft Synthetic Test Signer')
   [void]$shape.AppendChild($line)
   [void]$pict.AppendChild($shape)
   [void]$r.AppendChild($pict)
   [void]$p.AppendChild($r)
   $sect=$body.SelectSingleNode('w:sectPr',$ns)
   if($sect){[void]$body.InsertBefore($p,$sect)}else{[void]$body.AppendChild($p)}
   $outbytes=[Text.UTF8Encoding]::new($false).GetBytes($xml.OuterXml)
   $stream=$new.Open()
   try{$stream.Write($outbytes,0,$outbytes.Length)}finally{$stream.Dispose()}
  }else{
   $sin=$ent.Open();$sout=$new.Open()
   try{$sin.CopyTo($sout)}finally{$sin.Dispose();$sout.Dispose()}
  }
 }
}finally{$destZip.Dispose();$sourceZip.Dispose()}
$env:PATH=(Join-Path $env:USERPROFILE '.cargo\bin')+';'+$env:PATH
Push-Location $root
try{
 & cargo run --locked --quiet --example opc_sign_smoke -- $modified $signed $cert.Thumbprint
 if($LASTEXITCODE -ne 0){throw 'Native signing failed on VML fixture'}
}finally{Pop-Location}
$z=[IO.Compression.ZipFile]::OpenRead($signed)
try{
 $entry=$z.GetEntry('word/document.xml')
 if(-not $entry){throw 'Document.xml missing after signing'}
 $read=[IO.StreamReader]::new($entry.Open())
 try{$contents=$read.ReadToEnd()}finally{$read.Dispose()}
 [xml]$check=$contents
 $n=[Xml.XmlNamespaceManager]::new($check.NameTable)
 $n.AddNamespace('o',$oNs)
 $lineNode=$check.SelectSingleNode('//o:signatureline',$n)
 if(-not $lineNode -or $lineNode.GetAttribute('id') -ne ('{'+$guid+'}')){throw 'Persistent Word OOXML signature-line node missing after signing'}
}finally{$z.Dispose()}
$pkg=[IO.Packaging.Package]::Open($signed,[IO.FileMode]::Open,[IO.FileAccess]::Read)
try {
 $m=[IO.Packaging.PackageDigitalSignatureManager]::new($pkg)
 if($m.Signatures.Count -ne 1 -or $m.VerifySignatures($false).ToString() -ne 'Success'){throw 'Independent WindowsBase validation failed'}
}finally{$pkg.Dispose()}
$report=[ordered]@{
 status='SYNTHETIC_VML_SIGNATURELINE_AND_OPC_PASS'
 date=(Get-Date).ToString('o')
 source_sha256=(Get-FileHash $source -Algorithm SHA256).Hash
 modified_sha256=(Get-FileHash $modified -Algorithm SHA256).Hash
 signed_sha256=(Get-FileHash $signed -Algorithm SHA256).Hash
 signatureline_id=$guid
 ooxml_signatureline_element='PRESENT'
 WindowsBase_OPC_integrity='PASS'
 microsoft_word_rendering='NOT_TESTED'
 native_app_integration='NOT_IMPLEMENTED'
 xlsx_signatureline='NOT_IMPLEMENTED'
 qes='NOT_ASSESSED'
}
$report|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $work 'acceptance.json') -Encoding UTF8
'OOXML_SIGNATURELINE_STRUCTURAL_TEST=PASS'
'OPC_SIGNATURE_WITH_SIGNATURELINE=PASS'
"REPORT=$(Join-Path $work 'acceptance.json')"
