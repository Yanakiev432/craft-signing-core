# Windows native OPC multi-signature acceptance — 2026-10-23

**Scope:** Synthetic DOCX/XLSX fixtures on Yanakiev-Lenovo. The originals and personal files remain unchanged. This is a cryptographic OPC/XMLDSig integrity result, **not** an eIDAS qualification determination.

## Evidence

- `cargo test --locked --quiet`: 10/10 PASS.
- `tools/opc-live-smoke.ps1`: first signature and native reopening/verification 2/2 PASS.
- `tools/opc-tamper-smoke.ps1`: modification to signed XLSX and added unsigned DOCX part rejected, 2/2 PASS; script success exit normalized after expected negative results.
- Append second native signature using the same development certificate: 2/2 PASS, both signatures subsequently verified.
- `tools/opc-distinct-signers-smoke.ps1`: **two different software signing certificates**, DOCX 2/2 signatures PASS, XLSX 2/2 signatures PASS; independent WindowsBase `PackageDigitalSignatureManager.VerifySignatures(false)` returned `Success`.
- An appended, unsigned part is rejected after the two signatures in both formats; signing an already-corrupted package is refused without creating an output.
- A separate test leaf was generated in CurrentUser/My with a non-exportable software key and deleted in `finally`; no trust roots changed or keys exported.

## Design decisions

The first signing implementation deliberately refused existing signed documents with `ERROR_ALREADY_EXISTS`, despite a UI option promising additional signatures. This branch validates existing signatures before appending, excludes existing signature metadata parts from new part references, and reopens the output requiring exactly `priorCount + 1` verified signatures. This follows the OPC signature origin design and avoids signing signature-origin-to-signature relationships that would invalidate an earlier signer.

The native validator continues rejecting unsigned parts and altered bytes. Each output is a *new* file, never an in-place overwrite.

## Unresolved acceptance gates

- Hardware B-Trust/other qualified device signing: **NOT_TESTED** in this change.
- Microsoft Word/Excel interoperability: **NOT_TESTED** (Microsoft Office not installed on test host).
- eIDAS qualified signature identity, revocation, timestamp and certificate policy: **NOT_ASSESSED**.
- Persistent visible OOXML signature-line object: **NOT_IMPLEMENTED**.
- Publicly trusted Windows EXE/MSI publisher certificate: **NOT_AVAILABLE**.

Do not merge or publish a qualified-signature claim from these tests alone.
