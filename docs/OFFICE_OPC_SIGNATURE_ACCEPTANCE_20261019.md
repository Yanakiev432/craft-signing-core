# WordCraft / GridCraft Office OPC Signature Engineering Acceptance
Date: 2026-10-19
Work branch: feature/opc-xml-dsig-signer

## Implemented
- Windows OPC/XMLDSig signer and verifier in tools/opc_signature_windows.ps1 using Microsoft WindowsBase PackageDigitalSignatureManager.
- Shared Rust facade src/opc_windows.rs with a source-embedded Windows helper, exact selected certificate fingerprint, no PIN processing, explicit no-overwrite output, and temporary staged helper lifetime.
- DOCX and XLSX content-family validation by internal officeDocument relationship and main part.
- SHA-256 XMLDSig cryptographic signature applied to original OPC content and relationships. Whole-package coverage verified; unknown added content parts fail closed.
- No signing in memory of original file; copy to output, sign staged, verify, move atomically only on success.
- Verification reports integrity separately from unknown issuer trust, qualified electronic signature and qualified timestamp.

## Direct Lenovo test — verified
Command:
  pwsh -NoProfile -File tools/test_opc_signature_windows.ps1 -ArtifactDirectory C:\Users\User\Documents\PdfCraft-builds\OPC-MEMORY7-TEST-20261019

Actual output:
  OPC_TEST_PASS family=docx signed=...\signed.docx sha256=19414713e73499e28dda0f7f8eaeffe3359f82848df337330b90c0bc0eb69712 tamper_rejected=true unsigned_part_rejected=true
  OPC_TEST_PASS family=xlsx signed=...\signed.xlsx sha256=81a72ed356c44cff786adb597e9a0fd33cd457e99bca6c8af735c1128a4770d2 tamper_rejected=true unsigned_part_rejected=true
  OPC_SIGN_VERIFY_TAMPER=PASS
  IN_MEMORY_TEST_IDENTITY_DISPOSED=true

Both files were signed with an ephemeral, self-signed RSA certificate created **only in memory** using CertificateRequest. No Windows personal store certificate was imported, no real smart-card key or PIN used. Readback verifies a separate file-opening operation, not independent Office implementation interoperability.

Shared Rust local tests: 6/6 PASS. Windows GNU x64 cargo check PASS. The Windows Rust facade has not yet been exercised through actual WordCraft / GridCraft CLIs as of this checkpoint.

## Conditions for full user acceptance
1. WordCraft native GUI or CLI: sign a nontrivial DOCX through shared wrapper using a selected B-Trust signing identity (vendor PIN UI); verify after save/reopen; reject changed content and added unknown package parts.
2. GridCraft native GUI or CLI: same for XLSX, including at least one formula and relation to a worksheet.
3. Validate Office interoperability using actual Microsoft Word and Excel if available; no Office installation detected locally as of 2026-10-19. Unsupported tooling alone cannot prove Office UI signatures.
4. Independent qualification determination: certificate-chain/historical TSL, qualified certificate/secret key status, revocation and any trusted timestamp must be separately validated. A PackageDigitalSignatureManager.VerifySignatures(Success) is an *integrity* result only and is not QES.
5. Trusted Windows release and PDF PAdES-B-T/B-LT/B-LTA are independent external gates, not met by this test.

Microsoft technical API: https://learn.microsoft.com/en-us/dotnet/api/system.io.packaging.packagedigitalsignaturemanager.sign
