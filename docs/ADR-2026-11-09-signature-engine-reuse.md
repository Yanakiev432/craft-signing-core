# ADR-2026-11-09 — Reuse established signature engines; stop duplicated signing QA

Status: ACCEPTED for QA engineering direction only. Not a production approval.

## Observed acceptance evidence (Lenovo, 2026-11-09)
- Real owner-present B-Trust signing succeeded on synthetic DOCX and XLSX via DSS ASiC-S / XAdES Baseline-B.
- Outputs: WordCraft-BTrust-TEST-20261109-100604.asics and GridCraft-BTrust-TEST-20261109-101115.asics.
- Independent DSS cryptographic integrity and signed-data checks: TRUE for both.
- Embedded signer certificate matches Ivan Kostadinov Yanakiev in both; Linda certificate absent.
- **eIDAS qualification: NOT ACCEPTED**. The current lightweight validator reports INDETERMINATE / NA; it instantiates CommonCertificateVerifier without a configured, synchronized TLv6 EU trust-list source. Never promote cryptographic integrity to QES status.

## Existing upstream code to reuse
1. European Commission **DSS 6.5.1** (https://github.com/esig/dss) and its working example implementation (https://github.com/esig/dss-demonstrations). Continue using existing Java DSS bridge for PAdES/XAdES/CAdES/ASiC and evidence/reporting. License: LGPL-2.1. Do not write our own XAdES, ASN.1, OCSP, trusted-list logic.
2. **Microsoft System.IO.Packaging.PackageDigitalSignatureManager**: native Windows OPC signatures for DOCX/XLSX, with Windows X509 provider access. First choice for an in-document Office signing spike, verify with actual Microsoft Word/Excel; API support alone does not prove Office interoperability.
3. **Apache POI SignatureInfo** (https://github.com/apache/poi/blob/trunk/poi-ooxml/src/main/java/org/apache/poi/poifs/crypt/dsig/SignatureInfo.java) and TestSignatureInfo (https://github.com/apache/poi/blob/trunk/poi-ooxml/src/test/java/org/apache/poi/poifs/crypt/dsig/TestSignatureInfo.java): mature reference for Office OPC package signatures, tampering and multi-signature tests. Choose as alternative if Microsoft packaging fails interoperability; do not run two production engines in parallel without justification. Apache-2.0.
4. **pyHanko** (https://github.com/MatthiasValvekens/pyHanko): established PDF PAdES/PKCS#11 reference/fallback; do not replace native PdfCraft 0.19.0 signing without a failing acceptance requirement.
5. **DigiDoc4j** (https://github.com/open-eid/digidoc4j): optional reference for ASiC/EU signatures built upon DSS; do not duplicate DSS in our product.

## Single architecture
Rust Craft GUI → one versioned JSON job request → **signature worker**. Windows certificate selection and PIN exclusively via OS/CNG/B-Trust middleware; private key never exported. Worker dispatch:
- PDF → PdfCraft native PAdES + EU DSS qualification/validation.
- Office embedded signatures → System.IO.Packaging first, Apache POI fallback only on proven interoperability gap.
- European detached/container signatures → existing DSS 6.5.1 ASiC-S/XAdES path.
- Validation → DSS with TLv6 EU LOTL/national trust lists, X509 chain and revocation, trusted timestamp and detailed ETSI report as appropriate.
Clearly distinguish cryptographic integrity, trusted certificate path, qualified status, and timestamp profile. An ASiC-S .asics file is NOT a natively signed .docx/.xlsx.

## Testing budget / stop rules
- Freeze current B-Trust synthetic DOCX/XLSX signature-creation cases as PASS; do not repeat same successful case without changes to signer/cert integration or relevant dependency.
- Exactly one functional smoke case per new integration at the release candidate, with negative tamper verification when document package logic changes.
- Exactly one Word and one Excel opening/verification test for native OPC interoperability, not for ASiC mode.
- Exactly one online TLv6-based DSS qualification report for each signature format when ready. INDETERMINATE must show root cause in the detailed report, not trigger repeated PIN attempts.
- Regression tests run on changed components and at release gates, not each chat turn. No signature or QES claims solely on compilation PASS.
- Do not rebuild old upstream forks; rebase only the minimal UI integration on latest installed official releases.
- No GPU, model training, paid API, reboot, production install, publisher identity misrepresentation or security bypass.

## Next engineering gates
1. Adopt and record source/branch/config for the one Office OPC engine; minimal functional spike against WordCraft 0.16.0 / GridCraft 0.17.0.
2. Configure DSS v6-compatible EU Trusted Lists / LOTL and OCSP/CRL, produce detailed eIDAS validation evidence for already signed B-Trust outputs, **without signing again**.
3. Final GUI workflow + protected signer isolation / cancel, one regression run, Windows publisher code-signing, installer acceptance. Then production deployment only with owner approval.
