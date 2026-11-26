# Native OPC verification stage report — 2026-11-26

Source QA only. The existing native strict acceptance policy is unchanged. A new Rust report exposes the exact stop stage and original HRESULT; no partial result can yield strict PASS. Trust, revocation and QES remain unassessed. The old native entry point delegates to the same implementation.

Windows CPU-only, locked offline build: 44 library tests passed, 0 failed, 5 ignored (real signed-module fixtures); scoped Rust formatting passed. Whole-repository rustfmt check has pre-existing unrelated differences and was not applied.

The compiled opc_inspect_smoke example was executed against 16 existing local synthetic/reference fixtures, all unchanged:
- 2 intact Craft-generated DOCX/XLSX: strict_pass, exit 0, one signature each.
- 2 tampered counterparts: signature_validation, exit 1.
- 4 Apache POI legacy SHA-1 signed fixtures: part_coverage, exit 1.
- 4 Apache POI legacy SHA-1 signed fixtures: signature_validation, exit 1 (including MS Office 2010 DOCX/XLSX and XAdES-X-L).
- 1 POI RSA-SHA512 fixture: signature_enumeration, HRESULT 0x803D0000, exit 1.
- 3 unsigned fixtures: no_signature, exit 1.

The exact stop stage resolves the previous ambiguity: lack of part coverage is not the first failure for all Office fixtures. Stage names are diagnostic, not claims that a failed signature is necessarily cryptographically corrupt. No signed package, certificate, or personal document is committed. No installed module, trust store, official host, or production release modified.

Next: versioned broker/host structured report transport, real modern Office-authored SHA-256 signatures, independent trust/revocation/QES evaluation. This does not establish complete relationship coverage or full Office interoperability. Production NO-GO.