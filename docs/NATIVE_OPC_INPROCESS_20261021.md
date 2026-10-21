# Experimental fully in-process Windows OPC signer/verifier

This isolated branch implements an ABI-stable Rust/C++ Windows OPC adapter through
Microsoft's documented COM Packaging interfaces. Runtime calls do not spawn
PowerShell, CMD, or any other subprocess. The key stays in Windows CurrentUser/My
and the provider's official PIN UI is the only potentially interactive external UI.

## Implementation status and limits
- Signing selects a **specific** Windows store certificate by its SHA-1 thumbprint,
  never by ambiguous subject text. Output must not exist and the original is
  never overwritten. The result is re-opened through Windows OPC before being
  moved into place. No private keys or PINs are handled by Rust/C++.
- Native verification checks the OPC XML signature and authenticates every
  ordinary package part. It rejects unsigned added parts, unsigned relationships
  and fake, unlinked signature metadata; the CI includes negative fixtures.
- This is a **source prototype**, not proven compatible with Word/Excel or a
  qualified B-Trust smart-card signature. Do not merge into app Review controls
  before the CI native signed-document interoperability tests pass.
- OPC signature integrity does NOT prove X.509 certificate chain/trust,
  revocation, eIDAS qualified signing, trusted timestamping, or PAdES status.
- Some valid packages with external certificate parts or advanced relationship
  structures may conservatively fail until independently reviewed support is
  implemented. Fail closed rather than bypassing signature coverage checks.
- Test signing uses a disposable software certificate, restricted to the
  ephemeral GitHub Windows runner; it must not use the owner's Windows store.
- The legacy PowerShell-based OPC module is retained unchanged for comparison,
  but this new adapter never invokes it at runtime.

Official Microsoft COM documentation:
https://learn.microsoft.com/en-us/windows/win32/api/msopc/nn-msopc-iopcdigitalsignaturemanager
https://learn.microsoft.com/en-us/windows/win32/api/msopc/nf-msopc-iopcdigitalsignaturemanager-sign
