# Craft DSS XAdES/ASiC interoperability QA

Status: EXPERIMENTAL / TEST ONLY. Uses European Commission DSS 6.5.1.

The experimental second Office signing mode wraps the unchanged DOCX/XLSX binary in an ASiC-S (.asics) container with XAdES Baseline-B. It is distinct from a native Office OPC/XMLDSig signature inside DOCX/XLSX. Do not conflate the formats.

## Security boundary

The original direct DSS MS-CAPI-token enumeration experiment timed out after 185 seconds. The separate .NET 8 sidecar now has two isolated and strictly restricted test paths: a disposable PKCS#12 test key, or the exact self-issued local Craft software certificate in Windows CurrentUser/My. The Java component never loads a private key or reads the disposable key password. The .NET helper refuses every other certificate, including B-Trust. The local store test certificate was identified as RSACng with a 3072-bit RSA key.

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


## External Windows software provider, no B-Trust access (2026-11-07)

The tested separate process is implemented in sidecar/Program.cs, compiled with .NET 8.
The Java bridge is src/main/java/org/craftopensource/eidasqa/CraftExternalDssQa.java.

Two QA commands are available:

- CraftExternalDssQa --sign-external-test: accepts one disposable self-issued PKCS#12 and a public certificate. Only the .NET child process reads the ephemeral password.
- CraftExternalDssQa --sign-windows-local-test: accepts one explicitly selected self-issued Craft Open Source Local Code Signing software certificate. Its Windows CurrentUser/My private key is RSACng and is not exported. All other certificates are refused.

Both modes send raw SignedInfo bytes to the sidecar, receive raw RSA-SHA256 signature bytes, independently check the signature against the selected public certificate, and reject modified or colliding inputs. A complete ASiC-S XAdES Baseline-B is created and verified before publishing new output.

Tests: 2/2 external temporary PKCS#12 DOCX/XLSX positive, 2/2 Windows RSACng DOCX/XLSX positive, 5/5 Windows signer guardrail tests, 4/4 XAdES original/tampered Windows tests. No B-Trust PIN or hardware operation took place. See docs/EXTERNAL_SIGNER_QA_20261107.md.

Not production-ready: provider-owner PIN workflow, EU Trusted List/QSCD validation, trusted timestamp, UI integration, and trusted installer code signing remain open.
