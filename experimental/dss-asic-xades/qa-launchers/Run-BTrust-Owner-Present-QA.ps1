param(
    [ValidateSet('WordCraft','GridCraft')]
    [string]$App = 'WordCraft'
)
$ErrorActionPreference='Stop'
# Deliberately user-invoked. This file is NEVER auto-run.
# The B-Trust service provider owns all PIN prompts; Craft never reads a PIN.
if(-not [Environment]::UserInteractive){
    throw 'Owner-present signing requires an interactive Windows desktop.'
}
$DssRoot=Split-Path -Parent $PSCommandPath
$Base=Split-Path -Parent $DssRoot
$GuiRoot=Join-Path $Base 'GUI-QA-20261107\Portable-QA'
$Extension=if($App -eq 'WordCraft'){'docx'}else{'xlsx'}
$Document=Join-Path (Join-Path $GuiRoot $App) ('QES_QA_UNSIGNED_ORIGINAL.'+$Extension)
$Project=Join-Path $DssRoot 'bridge'
$Maven=Join-Path $DssRoot 'tools\apache-maven-3.9.11\bin\mvn.cmd'
$Dotnet='C:\Users\User\.dotnet\dotnet.exe'
$Sidecar=Join-Path $DssRoot 'sidecar\bin\Release\net8.0\CraftDisposableSigner.dll'
foreach($required in @($Document,$Maven,$Dotnet,$Sidecar)){
    if(-not (Test-Path -LiteralPath $required -PathType Leaf)){
        throw 'QA prerequisites missing; no signing attempted.'
    }
}
Add-Type -AssemblyName System.Security
$Candidates=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
foreach($c in (Get-ChildItem Cert:\CurrentUser\My)){
    if(($c.Issuer -like '*B-Trust*Operational Qualified CA*') -and
       $c.HasPrivateKey -and
       ($c.NotBefore -le (Get-Date)) -and
       ($c.NotAfter -gt (Get-Date)) -and
       ($null -ne $c.Extensions['1.3.6.1.5.5.7.1.3'])){
        $null=$Candidates.Add($c)
    }
}
if($Candidates.Count -lt 1){
    throw 'No eligible B-Trust public certificate candidates were found; no signing attempted.'
}
$Picked=[System.Security.Cryptography.X509Certificates.X509Certificate2UI]::SelectFromCollection(
    $Candidates,
    'Craft — B-Trust QA certificate',
    'Изберете лично един B-Trust сертификат. Отказът прекратява теста.',
    [System.Security.Cryptography.X509Certificates.X509SelectionFlag]::SingleSelection
)
if($Picked.Count -ne 1){
    Write-Output 'Cancelled: no certificate chosen, nothing signed.'
    exit 2
}
# The user has actively chosen one certificate in Windows UI.
# The .NET provider will check QC certificate policy, chain and revocation,
# then ask for a SECOND explicit Windows confirmation before any key operation.
$Cert=$Picked[0]
$OutputFolder=Join-Path $DssRoot 'outputs\BTrust-Owner-Present-QA'
New-Item -ItemType Directory -Path $OutputFolder -Force|Out-Null
$Stamp=(Get-Date).ToString('yyyyMMdd-HHmmss')
$NewOutput=Join-Path $OutputFolder ($App+'-BTrust-TEST-'+$Stamp+'.asics')
if(Test-Path $NewOutput){throw 'Output collision: refuse overwrite.'}
$PublicTempDir=Join-Path $DssRoot 'owner-public-certificate-temporary'
New-Item -ItemType Directory -Path $PublicTempDir -Force|Out-Null
$PublicCert=Join-Path $PublicTempDir ([guid]::NewGuid().ToString('N')+'.cer')
$SourceHash=(Get-FileHash -Algorithm SHA256 $Document).Hash
try{
    $null=Export-Certificate -Cert $Cert -FilePath $PublicCert -Type CERT
    $env:DSS_QA_DOTNET_HOST=$Dotnet
    $env:DSS_QA_SIDECAR_DLL=$Sidecar
    $env:DOTNET_ROOT='C:\Users\User\.dotnet'
    $Arguments='--sign-btrust-owner-qa '+$Document+' '+$NewOutput+' '+$PublicCert+' '+$Cert.Thumbprint+' --owner-confirmation-required'
    Write-Output ('QA mode: '+$App)
    Write-Output 'Следва второ потвърждение в Windows и евентуален ПИН прозорец на доставчика.'
    Write-Output 'Продължавайте само ако лично сте пред компютъра и желаете реален подпис върху тестовия файл.'
    Push-Location $Project
    try{
        $OldError=$ErrorActionPreference
        $ErrorActionPreference='Continue'
        try {
            $Result=& $Maven -B -ntp -q 'exec:java' '-Dexec.mainClass=org.craftopensource.eidasqa.CraftExternalDssQa' ('-Dexec.args='+$Arguments) 2>&1|Out-String
            $Code=$LASTEXITCODE
        } finally {$ErrorActionPreference=$OldError}
    }finally{Pop-Location}
    if($Code -ne 0 -or -not(Test-Path $NewOutput)){
        Write-Output 'No accepted signature file was produced. The operation was cancelled, refused, or failed.'
        exit 3
    }
    if((Get-FileHash -Algorithm SHA256 $Document).Hash -ne $SourceHash){
        throw 'The unsigned original changed unexpectedly; do not accept the result.'
    }
    if(($Result -notmatch 'DSS_CRYPTOGRAPHIC_SIGNATURE_INTACT=true') -or
       ($Result -notmatch 'DSS_CRYPTOGRAPHIC_ALL_SIGNED_DATA_VALID=true')){
        throw 'DSS did not confirm cryptographic integrity; output requires investigation.'
    }
    Write-Output ('Cryptographic QA PASS: '+$NewOutput)
    Write-Output 'WARNING: eIDAS qualified status, trusted timestamp and EU Trusted List verification NOT YET ACCEPTED.'
    Write-Output 'Do not treat this local QA result as an independently qualified-signature validation report.'
    exit 0
}finally{
    Remove-Item -LiteralPath $PublicCert -Force -ErrorAction SilentlyContinue
    Remove-Item Env:DSS_QA_DOTNET_HOST,Env:DSS_QA_SIDECAR_DLL -ErrorAction SilentlyContinue
    # No private key or PIN is ever exported or managed here.
}
