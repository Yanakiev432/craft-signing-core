# DSS XAdES-B external sidecar and Windows RSA-CNG acceptance (2026-11-07)

The integration uses EC DSS 6.5.1, Java, and an isolated .NET 8 sidecar. The output is a separate ASiC-S container (.asics) with XAdES Baseline-B, not a signature embedded in an Office DOCX/XLSX document.

DSS constructs canonicalized raw ToBeSigned SignedInfo bytes and selects only a PUBLIC certificate. The sidecar signs with RSA SHA-256 PKCS#1 v1.5. DSS verifies the returned signature with the public key, creates the ASiC-S container, validates the result and refuses existing output paths.

Two different software QA key providers were exercised:

1. Temporary self-issued test PKCS#12 file, kept accessible only to the .NET helper, with a random per-run environment password and deleted afterward.
2. Actual Windows CurrentUser/My self-issued Craft local software certificate with RSACng, RSA 3072; only this exact test subject/issuer is allowed. No hardware B-Trust certificate is accessible through the enabled test mode.

Confirmed results:
- .NET 8 Release build PASS, zero warnings/errors.
- Maven DSS Java build PASS.
- DOCX and XLSX XAdES-B through external ephemeral key PASS.
- DOCX and XLSX XAdES-B through Windows RSACng software test identity PASS.
- Windows helper wrong thumbprint refused (exit 67).
- Windows helper wrong public certificate SHA256 refused (exit 69).
- Windows helper occupied output refused (exit 66, file unchanged).
- Windows helper invalid safety flag refused (exit 64).
- Windows helper positive test certificate accepted.
- DSS full validation on Windows mode: DOCX and XLSX signed output cryptographic PASS.
- Tampered embedded DOCX/XLSX payloads: two failures correctly detected as TOTAL_FAILED.
- Original unsigned documents unchanged. No user PIN, no real B-Trust signing.

The two self-issued Windows-mode outputs have ETSI result INDETERMINATE and qualification NA. Both are expected for nonqualified test certificates. Never interpret crypto integrity alone as a qualified eIDAS signature.

## Local test fingerprints (non-personal test artifacts only)

| Case | SHA-256 |
|---|---|
| TEMP_PKCS12_WORD | bc4423843d71fd333f63324243d25da1985751647fc2d59536e2a6ca6a12bb1d |
| TEMP_PKCS12_GRID | f58295a8c203713d8f103b40178dd7b0d3606dab8d9414c19caf7e03a0e06dfe |
| WINDOWS_CNG_WORD | acd751bee0e1c242a08a6c7525e53a95154ea85fbf8d3311053a7cb621ae4cd5 |
| WINDOWS_CNG_GRID | e0170b1f2e03011b37e4e24abac1beb994156fafa4b730c86d83316f806a9b3e |


## Unfinished release gates

- Real B-Trust hardware middleware and PIN prompt with the owner explicitly present, and separate audit evidence.
- EU Trusted List, qualified certificate and QSCD checks, revocation and trusted timestamps.
- XAdES Baseline-T or later profiles for trusted time evidence.
- WordCraft/GridCraft UI integration for explicit separate external ASiC-S output.
- Trusted Authenticode publisher and product MSI release approval.

This source cannot claim QES status, is test-only, and must not be installed or published as a production release.
