#requires -Version 5.1
# Read-only Windows CurrentUser/My certificate metadata for Craft native picker.
# Never acquire a signing key, request PIN, export private keys, or mutate stores.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# Certificate subjects may contain Cyrillic and other Unicode characters.
# Emit deterministic UTF-8 for the Rust JSON decoder.
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$store = [Security.Cryptography.X509Certificates.X509Store]::new(
  [Security.Cryptography.X509Certificates.StoreName]::My,
  [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
try {
  $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
  $list = @(
    foreach ($cert in $store.Certificates) {
      if ($cert.Thumbprint -notmatch '^[0-9a-fA-F]{40}$') { continue }
      [pscustomobject]@{
        thumbprint = $cert.Thumbprint.ToLowerInvariant()
        subject = $cert.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        issuer = $cert.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
        expires = $cert.NotAfter.ToUniversalTime().ToString('yyyy-MM-dd')
        has_private_key = [bool]$cert.HasPrivateKey
        valid_now = ($cert.NotBefore.ToUniversalTime() -le [DateTime]::UtcNow -and $cert.NotAfter.ToUniversalTime() -ge [DateTime]::UtcNow)
      }
    }
  )
  ConvertTo-Json -InputObject $list -Depth 4 -Compress
} finally { $store.Close() }
