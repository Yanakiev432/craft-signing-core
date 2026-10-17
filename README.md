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
