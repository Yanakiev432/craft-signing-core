# Craft DSS XAdES/ASiC interoperability QA

Status: EXPERIMENTAL / TEST ONLY. Uses European Commission DSS 6.5.1.

The experimental second Office signing mode wraps the unchanged DOCX/XLSX binary in an ASiC-S (.asics) container with XAdES Baseline-B. It is distinct from a native Office OPC/XMLDSig signature inside DOCX/XLSX. Do not conflate the formats.

## Security boundary

The bridge never opens Windows CurrentUser certificates and never invokes MS-CAPI. A direct MS-CAPI experiment was abandoned after a 185-second timeout, with no signed file. This proof-of-concept accepts only a disposable PKCS#12 whose self-issued subject contains CN=Craft Open Source Disposable XAdES QA Only. All real B-Trust certificates are rejected by design. Its password is read from the local DSS_QA_PKCS12_PASSWORD environment variable, never from CLI arguments or the repository.

Commands:
- --self-test : verifies the Java entrypoint.
- --sign-software-test SOURCE.docx|xlsx NEW_OUTPUT.asics DISPOSABLE.p12 --disposable-pkcs12-test-only : writes a new file and refuses overwrites or other keys.
- --inspect FILE.asics : checks expected ZIP/XAdES XML structure ONLY, not cryptographic validity.
- --validate FILE.asics : DSS SignedDocumentValidator checks cryptographic signature and covered signed data; outputs ETSI indication and qualification separately and exits nonzero for tampering.

Requirements: Java 17+ and Maven 3.9+.
Build: mvn -B -ntp -DskipTests package

## Verified disposable tests, November 7 2026

- Maven build and DSS module entrypoint PASS.
- DOCX and XLSX in ASiC-S with XAdES Baseline-B created PASS.
- DSS cryptographic signature value and signed data PASS for both originals.
- Tampered embedded payloads detected in both cases (TOTAL_FAILED and nonzero exit).
- Original DOCX/XLSX SHA-256 unchanged.
- Ephemeral PKCS#12/password removed after execution.
- ETSI indications for self-issued certificates: INDETERMINATE; signature qualifications: NA.

See docs/QA_REPORT_20261107.md.

## Unfinished release gates

- User-present hardware B-Trust integration, native provider PIN UI.
- EU Trusted List and qualified certificate/QSCD validation, path, revocation and trusted signing time.
- Trusted timestamp (XAdES Baseline-T) and long-term LT/LTA evidence where required.
- Independent external validator interoperability.
- Separate product GUI option: native Office OPC signature OR external XAdES/ASiC-S.
- Trusted code signing for MSI/EXE and explicit approval before production rollout.

The proof-of-concept does NOT issue or establish an eIDAS-qualified electronic signature. No production apps have been replaced.

DSS documentation: https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html
DSS core licensing: LGPL-2.1; preserve notices and comply with dependencies' licenses before distribution.
