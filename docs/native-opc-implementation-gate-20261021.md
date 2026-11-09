# Native OPC signing implementation gate

Status: NOT IMPLEMENTED. This file records verified API surface and acceptance criteria, not a QES certification.

## Verified on Lenovo
- Windows SDK 10.0.26100.0 `um/msopc.h` declares `IOpcFactory`, `IOpcDigitalSignatureManager`, `IOpcSigningOptions`, `IOpcSignaturePartReferenceSet`.
- `IOpcDigitalSignatureManager::Sign` takes a `CERT_CONTEXT*`, options and output signature; `Validate` returns `OPC_SIGNATURE_VALIDATION_RESULT` (0 valid, -1 invalid).
- `IOpcFactory` supports `ReadPackageFromStream`, `WritePackageToStream`, `CreateDigitalSignatureManager`.
- Existing PowerShell/WindowsBase tests PASS for DOCX and XLSX, including independent signatures and tamper rejection. They are reference tests, not native Rust tests.

## Required implementation
1. In-process OPC COM bridge (Rust `windows` bindings or MSVC C++ shim), no child process, no PowerShell, no CMD.
2. Validate DOCX/XLSX package type, main officeDocument relationship, extension and every content/relationship part.
3. Resolve explicit Windows CurrentUser/My certificate by thumbprint, retain private key in CNG/CSP/token and allow provider PIN UI; never auto-select first identity.
4. Sign all non-signature content parts, stable relationship selectors and SHA-256 digests; support second independent signature without invalidating first.
5. Reject unsigned added parts, modified relationship targets, malformed signatures, unknown policy and invalid previous signatures.
6. Write to a new staging file, independently reopen and verify, publish only after success, never overwrite original or existing destination.
7. Return separate statuses for OPC integrity, Windows chain policy, revocation, qualified timestamp and EU QES. Unknown is not PASS.
8. Connect actual Sign/Verify actions in WordCraft and GridCraft Review; provide certificate choice and explicit destination; disable placeholder success messages.
9. Run integration tests with disposable identities and DOCX/XLSX; independently test Microsoft Office interoperability. B-Trust physical-token test only with user interaction/consent.
10. Do not replace installed Craft applications until all acceptance gates pass.

## Last tests
- `tools/test_opc_signature_windows.ps1`: PASS for DOCX/XLSX, independent signers, policy lock, tamper and unsigned-part rejection.
- `tools/test_office_opc_sign.ps1`: 2/2 PASS sign/verify/tamper.
- `cargo test`: 9/9 PASS.
