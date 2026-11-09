# OPC ZIP portability / B-Trust Office signing — acceptance (2026-10-23)

**Scope:** local development of Craft Signing Core on Yanakiev-Lenovo. This is a source-code test, not a certified public release.

## Root cause
Windows `IOpcFactory::WritePackageToStream` with `OPC_WRITE_DEFAULT` emitted ZIP64 (reader version 4.5) even for small DOCX/XLSX. `OPC_WRITE_FORCE_ZIP32` removed ZIP64, but retained a streaming data-descriptor ZIP layout (`flag_bits=8`). Local LibreOffice could not load representative signed DOCX generated in either layout. An equivalent ZIP rewrite with seekable ZIP entries (`flag_bits=0`) preserved every uncompressed document part and native Windows OPC signature integrity and restored DOCX import.

## Production candidate in this branch
- Native C++ now calls `OPC_WRITE_FORCE_ZIP32`, failing closed if ZIP32 limits cannot be satisfied.
- Windows Rust signing bridge signs a unique temporary file, performs native cryptographic OPC verification, rewrites the signed ZIP in-process using Rust `zip` 3.0.0 (no Python, shell or external process), re-verifies every signature with native Windows OPC, checks unchanged signature count and publishes only the fully verified output.
- Temporary staging files are removed whether the attempt succeeds or fails. The source is never overwritten. Only Stored/Deflated ZIP entries accepted; empty, duplicate, relative-traversal or oversized ZIP32 entries rejected.
- This ZIP-container normalization **does not authorize any modification of the signed XML/OPC data**; cryptographic validation after rewrite is mandatory.

## Executed acceptance
- `cargo test --offline`: 10/10 PASS.
- Representative DOCX and XLSX from locally installed LibreOffice, signed through **the owner's genuine B-Trust Windows cryptographic certificate provider**: Windows native OPC and independent `WindowsBase PackageDigitalSignatureManager.VerifySignatures(false)`, 2/2 PASS; original input unchanged.
- Those two signed Office outputs opened and rendered into PDFs with LibreOffice headless: 2/2 PASS, original input unchanged. Do not equate rendering with LibreOffice's certification of QES.
- Regression with a **second, distinct disposable software certificate** on DOCX and XLSX: 2/2 PASS, WindowsBase independent integrity, signed originals preserved, added unsigned part rejected and attempt to sign corrupt source refused; test-only certificate removed in `finally`.
- `tools/test_opc_zip_portability.py` run against both B-Trust signed output files: 2/2 PASS. ZIP min-reader version at most 2.0, no data descriptor flags; decompressed document parts byte-identical to original, only signing metadata added.

## Evidence (host-local, do not commit personal signed documents)
- `target/office-realistic-interop-20261023/sample-core-fixed-btrust.docx`: SHA256 `ce165382b3dbced4c01e2b1e98c562938f13008f275963ad921268e1b0a8f0f3`.
- `target/office-realistic-interop-20261023/sample-core-fixed-btrust.xlsx`: SHA256 `20a78d0f1da30dd0e7a271e326b4ea6f4c7085e8c8af99b35a1f320f883ce019`.
- `target/opc-distinct-9d3ae5c1db0744d3bd57ab4e3f9c6ece/acceptance.json`: negative and two-signer regression.
- The Office import test produced PDFs in `target/office-realistic-interop-20261023/lo-fixed-btrust-docx` and `lo-fixed-btrust-xlsx`.

## Explicit release blockers
- **Microsoft Word and Excel are not installed here**; real Microsoft Office round-trip, signature dialogs, and rendered visible signature-line objects remain untested.
- DSS independently validated the signer **certificate** (`PASSED`; `QC for eSig with QSCD`), but the DSS 6.5.1 REST document endpoint returned HTTP 500 for Office OPC ZIP documents. That service does not establish QES document-level validation for this format.
- New core code is not included in installed Craft Suite 1.0.4 until WordCraft/GridCraft binaries are rebuilt and their installer independently accepted.
- The GitHub PR must remain **draft** until quality, security, integration, and actual Microsoft Office interoperability review.
- Public Windows EXE/MSI signing is still unavailable: local MSIX preview packages are development-signed only.

Source branch: `fix/opc-force-zip32-20261023`; intended review base: `fix/opc-multisign-gate-20261023`.
