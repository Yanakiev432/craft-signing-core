# DSS ↔ Windows CNG/CSP signing boundary (QA design, 2026-11-07)

## Architectural decision

Retain two different user-visible output modes:

1. Native Office OPC/XMLDSig within DOCX/XLSX, backed by the existing native Windows OPC signer.
2. External ASiC-S container with XAdES Baseline-B or higher, using DSS 6.5.1 for format handling and a separate Windows CNG/CSP process solely for the private-key operation.

Do not mislabel native Office XMLDSig as XAdES. Neither a private-key operation nor a QCP-n-qscd policy OID by itself proves a QES. The eIDAS qualified-status gate remains independent.

## Reason to isolate the provider

The 2026-11-07 DSS MS-CAPI token enumeration experiment timed out at 185 seconds before producing an output. In contrast, the independent disposable PKCS#12 source produced XAdES Baseline-B ASiC-S, validated the cryptographic signature and signed data for both DOCX and XLSX, and rejected tampered ASiC payloads. No real user certificate was accessed in those experiments.

An available Rust core adapter, src/windows_cng.rs, implements SigningProvider.sign(SigningRequest) for a selected Windows CNG identity. It SHA-256/384/512 hashes raw message bytes exactly once and signs RSA PKCS#1 v1.5. The prototype does not yet prove that it operates with this user's B-Trust token.

## Proposed stateless signed-info boundary

1. Resolve the explicitly selected Windows certificate and export its public DER only. Require one unambiguous selected identity; do not enumerate or silently choose another certificate at signing time.
2. DSS constructs XAdES signed properties and obtains the exact ToBeSigned SignedInfo bytes. Bind the selected certificate, signed-data fingerprints, document name, selected algorithm and a unique request ID to the local request.
3. Transfer those raw ToBeSigned bytes to a single-purpose locally launched Windows signer process. The process uses CNG/CSP exclusively for the signature operation. Never export private-key material, collect a PIN in Craft, run PowerShell scripts from arbitrary paths or invoke remote APIs.
4. Match RSA PKCS#1 v1.5 with SHA-256 on both sides. Do not hash twice: DSS supplies raw data-to-sign to the existing Rust SigningProvider, which hashes it once and signs the digest. Return raw signature bytes and the verified public certificate identification.
5. DSS builds SignatureValue with an algorithm matching the certificate and digest, finalizes the ASiC-S XAdES container to a NEW output, and rejects if any required signed references are missing.
6. Reopen the complete output through SignedDocumentValidator. Check both isSignatureIntact and isSignatureValid. Independently verify the signer certificate, trusted-list status, revocation, QSCD and, where applicable, a qualified timestamp. Report distinct integrity, chain, revocation, time and qualification states.

## Failure policy / UI

- Signer process cancellation must terminate its descendants while preserving an existing source document.
- Refuse a destination that already exists, unsupported algorithms/keys, a different active document, unsaved edits, changed certificate, and a changed source fingerprint.
- Keep a bounded wait for the provider's own PIN dialog, never bypass the dialog or turn a timeout into success.
- Disable actual B-Trust key invocation until explicit owner-present hardware acceptance; only disposable software-test identities are enabled in the present QA branch.
- Keep the legacy native Office signing mode fully separate; no silent conversion between DOCX/XLSX and ASiC-S.
- Do not enable production installation, code signing or release publication without a trusted publisher and acceptance report.

## Required tests prior to switching on the provider

- Disposable RSA test key: compare DSS PKCS#12 signature to the proposed Windows CNG sidecar for identical XAdES signed-data validation.
- Positive DOCX/XLSX signed payloads; negative tampering, certificate mismatch, missing PIN, denial, process timeout, output collision, unexpected disk writes and multi-signature flows.
- User-present B-Trust PIN-provider acceptance with test-only documents; independently validated ETSI/eIDAS report and EU Trusted List chain.
- Cross-application Office format compatibility and Adobe/PDF signing remain separate paths.

References: https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html
