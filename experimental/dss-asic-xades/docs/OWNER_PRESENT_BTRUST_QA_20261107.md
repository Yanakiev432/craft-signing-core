# B-Trust owner-present hardware QA: release gate and instructions

Status on November 7 2026: COMPILED AND STATICALLY AUDITED, BUT NOT RUN WITH A B-TRUST PRIVATE KEY.

## Code

- Java: CraftExternalDssQa --sign-btrust-owner-qa, building DSS 6.5.1 ASiC-S with XAdES Baseline-B.
- Windows child: OwnerPresentBTrustQaSigner.Run in the .NET 8 sidecar.
- Windows interactive scripts on Lenovo: Run-BTrust-Owner-Present-QA.ps1, Run-BTrust-WordCraft-QA.cmd, Run-BTrust-GridCraft-QA.cmd.
- Windows certificate chooser: Microsoft X509Certificate2UI.SelectFromCollection with SingleSelection.

No WordCraft/GridCraft official installer or GUI is modified to automatically call this experimental hardware mode.

## Mandatory safety gates before private-key access

1. The operator must be on an interactive Windows desktop and consciously select a SINGLE B-Trust certificate in the system's certificate selection dialog. No default selection.
2. Only one of the nonpersonal unsigned test documents named QES_QA_UNSIGNED_ORIGINAL.docx or QES_QA_UNSIGNED_ORIGINAL.xlsx is accepted. DSS freezes its SHA-256 and the sidecar independently checks that SHA-256 before and after signing.
3. The certificate SHA-1 selector and public DER SHA-256 must both exactly match. Neither value is an authorization secret.
4. The selected certificate must have a B-Trust Operational Qualified CA issuer, valid date range, QCStatements extension, QCP-n-qscd policy 0.4.0.194112.1.2 in ASN.1 CertificatePolicies, and a successful Windows X509Chain online revocation check.
5. The owner is shown a second explicit Windows confirmation, with the test document and selected certificate. Refusal or unattended access exits before any private-key operation.
6. Only after owner confirmation does .NET call GetRSAPrivateKey and SignData. The B-Trust/CNG/CSP middleware owns all PIN entry. Craft must never request, save, log or transmit a PIN.
7. The helper signs DSS ToBeSigned bytes using RSA SHA-256 PKCS#1 v1.5, and returns only the signature bytes. DSS independently verifies the signature, creates a NEW .asics and reopens it for cryptographic validation. Existing output paths are rejected; original Office source is unchanged.
8. A successful cryptographic verification is NOT an eIDAS QES acceptance verdict. EU Trusted Lists, signing-time status, QTSP/QSCD evidence, revocation and trusted timestamp require independent qualified-validation reporting.

## Evidence gathered without any B-Trust signing

- .NET build PASS with zero warnings and errors.
- Java DSS bridge build PASS.
- Windows private-key software provider RSACng QA PASS with local self-issued Craft software certificate, not B-Trust.
- Automated negative tests: B-Trust owner gate with missing authorization flag refused; local self-issued Craft certificate refused as B-Trust; Java B-Trust public preflight refused a local Craft certificate. No output and no PIN.
- B-Trust public-only preflight: two candidate certificates; two passed QCP-n-qscd policy parsing; two passed Windows online X509Chain checks. No private key access.
- Owner-present PowerShell script parsed successfully with zero syntax issues. Windows X509Certificate2UI is available in the owner environment. Neither launcher was executed.

## Explicitly NOT completed

- Actual B-Trust token private-key signing operation with the owner's PIN.
- B-Trust Windows middleware acceptance, cancellation, PIN refusal and timeouts in its real provider UI.
- Independent qualified electronic signature validation against relevant EU Trusted Lists.
- Trusted timestamp / XAdES Baseline-T, LT or LTA.
- Integration of separate ASiC mode into WordCraft or GridCraft Review ribbon.
- Trusted publisher Authenticode and production MSI deployment.

The two manual owner-present launchers are not part of a public release. All owner data must remain on the authorized Lenovo.
