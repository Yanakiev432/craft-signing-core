# Craft Signing Core

**Status: v0.1 API contracts, not a standalone production signer.**

Shared Rust interfaces for digital-signature providers in PdfCraft, WordCraft and CellCraft.

- Providers: Windows CNG (including USB tokens), macOS Keychain, PKCS#11, PKCS#12, remote.
- Separates signing identity/key access from document format.
- Separates content integrity, chain trust, revocation and timestamp outcomes.
- Document adapters must implement PDF/PAdES and OOXML/XMLDSig separately.

## Proven working implementation

PdfCraft 0.8.0 currently implements B-Trust USB/CNG signing and PDF PAdES validation in its own source tree. The Oct 17 Windows-root trust fix was tested in PdfCraft, **not in this standalone crate**. The extraction/integration milestone is still open.

## Next milestones

1. Extract Windows CNG and PKCS#11 provider implementations and tests from the PdfCraft integration.
2. Implement PdfCraft PAdES adapter and end-to-end signing/verification tests.
3. Implement separate WordCraft/CellCraft OOXML/XMLDSig adapters.
4. Verify certificate policy, revocation and qualified-signature requirements; never claim eIDAS QES from chain trust alone.

No PINs, private keys, signed personal documents or certificates are committed.

## Test

`cargo test`

## License and attribution

MIT OR Apache-2.0. Architecture inspired by [PdfCraft](https://github.com/storytold/pdfcraft) (MIT OR Apache-2.0). No upstream source files copied here.

## Windows trust-store adapter (experimental)

`windows_trust::trusted_root_der()` reads the existing Windows CurrentUser and LocalMachine Root stores without modifying them. This read-only extraction is useful to a PdfCraft-style verifier but does **not** replace Windows chain-policy evaluation, revocation/Disallowed checks or eIDAS qualification. Hardware signing remains in the original PdfCraft implementation; it is **not yet extracted** into this crate.

## Windows CNG RSA adapter

On Windows, `windows_cng::WindowsCngProvider` enumerates CurrentUser Personal certificates and selects an identity by the SHA-256 hash of its DER certificate. `sign` acquires the Windows key **interactively**, hashes the supplied message, and requests RSA PKCS#1 v1.5 signing from CNG. It does not export the key.

**Important:** This implementation is compile-checked, not hardware-validated. Do not treat its presence as a qualified-signature or interoperability certification. It does not implement RSA-PSS, ECDSA signature conversion, PKCS#11 or OOXML signatures. No signing operation was run during extraction.
