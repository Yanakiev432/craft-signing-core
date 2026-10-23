# Craft visible Office signing QA — 23 October 2026

Scope: Yanakiev-Lenovo, Windows 11, synthetic DOCX/XLSX, source-only candidate, installed Craft Suite 1.0.4 unchanged.

## Acceptance results

| Area | Result |
|---|---|
| Rust signing core | 21/21 tests PASS, Clippy -D warnings PASS |
| WordCraft and GridCraft | cargo check --locked --offline PASS 2/2 |
| Native PNG image / DOCX / XLSX signing | Windows OPC identity/integrity PASS 2/2 (software development certificate) |
| LibreOffice post-fix open + PDF export | PASS 2/2 |
| Malicious input fail-closed | PASS 14/14 (duplicated ZIP, traversal, unsupported compression, DTD, content types, pre-existing drawings, signed inputs) |
| Signed-document tampering | PASS 4/4 (content mutation and unsigned added parts for DOCX + XLSX) |
| Earlier B-Trust ZIP portability | PASS 2/2 |
| New visible graphic with real B-Trust hardware | BLOCKED — provider operation not completed |
| Microsoft desktop Word and Excel on exact new files | NOT TESTED |
| eIDAS QES on whole new document | NOT ESTABLISHED |
| Public release/codesigning | NO-GO |

## Confirmed and repaired defects

1. ZipArchive de-duplicates identical central-directory filenames. A raw ZIP with 11 entries could be presented as 10; a synthetic XLSX with duplicated docProps/core.xml was accepted. Now a ZIP32 End of Central Directory parser checks entry count and offsets before the ZipArchive index is trusted, and rejects any mismatch. The regression now rejects both DOCX and XLSX duplicates.
2. Prefixed worksheet drawing elements, such as x15:drawing, were not captured by exact drawing and x:drawing checks. The source now detects drawing elements regardless of namespace prefix. Added Rust unit test.

## Authoritative reports

- target/native-visible-negative-20261023-fixed1/acceptance.json — PASS 14/14.
- target/native-identity-postfix-20261023/acceptance.json — 2/2 development-cert native signed graphics and independent Windows OPC PASS.
- target/native-visible-postfix-tamper-fixed-20261023/acceptance.json — 4/4 signature tamper rejections PASS.
- target/native-btrust-visible-f26ff9a91f154c01a0f174d4df73490d/acceptance.json — BLOCKED, provider interaction not complete, disposable unsigned staging removed.
- tools/office_visible_adversarial_acceptance.py — reproducible synthetic malformed input tests.
- tools/office_visible_signed_tamper_acceptance.py — reproducible signed-content mutation tests.
- tools/office-visible-btrust-acceptance.ps1 — preflight and real smartcard acceptance.

## Remaining physical and external tests

Run on the interactive Windows desktop from the signing-core repository (PowerShell 7):

    pwsh -NoProfile -File .\tools\office-visible-btrust-acceptance.ps1 -Mode Sign

The script selects the B-Trust thumbprint proven on an earlier, independently verified signed DOCX, then requests a new synthetic DOCX/XLSX signature through the official Windows provider. Enter any PIN **only** into the official SafeNet/B-Trust dialog. The unsuccessful RA-launched interaction has not been counted as PASS. The script never captures PIN or private-key material.

After hardware PASS, open these **exact newly generated files** in full Microsoft Word and Excel on the test PC. Record Office version, presence/placement of visible appearance, signing pane, signature details, and native Word signature-line click behaviour. In Excel the graphic is not a native interactive signature line. The earlier iOS/Google preview and Microsoft Office tests cover different specimens, and do not substitute for this.

Do not merge into main or publicly release before real Office compatibility, exact mouse viewport-to-document position mapping, broader OOXML acceptance and independent qualified document assessment.


## Independent EU DSS coverage and limitations (additional acceptance)

The locally provisioned EU DSS 6.5.1 service at 127.0.0.1:18080 independently confirmed **TOTAL_PASSED / QESig** for the previously signed B-Trust **PDF**. This does not transfer qualification to Word/Excel packages.

Four synthetic Office packages were submitted **only through localhost**, without external document upload:
- Earlier B-Trust-signed DOCX and XLSX.
- Current development-certificate signed visual DOCX and XLSX.

EU DSS returned HTTP 500 for all four inputs; **whole-document Office QES remains NOT ESTABLISHED**. The service did not issue a report demonstrating QESig for the Office containers. This is a validation capability / endpoint failure, not a demonstrated invalid OPC signature. Independent Windows OPC verification and Microsoft desktop Office on earlier specimens are separate gates.

Raw private DSS service responses and a machine summary remain at:
`target/office-dss-20261023-1/acceptance.json`.

The constrained, auditable loopback test program is `tools/office_dss_loopback_acceptance.py`.
PDFCraft's normal local QES wrapper has been fixed separately in [pdfcraft PR #24](https://github.com/Yanakiev432/pdfcraft/pull/24).

## 24 October 2026 — defensive OPC metadata gate and next Office package

- Strengthened the unsigned OOXML writer to parse **all package .rels** using a namespace-aware XML parser before any transformation. Existing digital-signature relationship types are rejected even when signature parts have nonstandard paths and the type has encoded XML attribute characters (for example, `digital&#45;signature`).
- A signed or signature-marked content type also blocks rewriting; the previous ZIP path guards and hardware signer selection remain unchanged.
- Rust unit suite: **24/24 PASS**, Clippy `--all-targets -- -D warnings` **PASS**.
- Synthetic fail-closed negative archive suite: **20/20 PASS** (`target/native-visible-negative-20261024-opc-rel/acceptance.json`).
- Normal positive certificate-bound DOCX and XLSX still generate **2/2 PASS**, independently verified by WindowsBase after signing (`target/native-identity-20261024-opc-rel/acceptance.json`).
- LibreOffice headless re-open and PDF export of the newly generated DOCX and XLSX: **2/2 PASS**.
- Microsoft Office manual acceptance is **deferred to 26 October 2026**, not claimed complete.
- A ready-to-transfer synthetic-only test package is saved at `C:\Users\User\Documents\CRAFT_OFFICE_ACCEPTANCE_20261026.zip`, containing unsigned and signed DOCX/XLSX plus SHA-256 manifest and Bulgarian step-by-step acceptance checklist.
- No final QES certification for Office documents, no new real B-Trust signed visible specimen, no installer release.

## 24 October — explicitly controlled Excel placement and honest UI

- Signing-dialog flow now permits **Choose Digital ID → Continue to signature settings → Sign a separate copy**, without first drawing an unrelated screen rectangle. Drawing remains an optional screen-only guide and is not advertised as the Office insertion coordinate.
- For XLSX, users can explicitly enter an **A1 cell address** on the first sheet. The validated parser accepts `A1` to `XFD1048576` and rejects ranges, formulas, absolute references, leading-zero row numbers and out-of-bounds cells.
- Word currently continues to use the **document-end** placement; there is still no page-coordinate mapping or native Word interactive Sign confirmation.
- Added Rust unit tests for correct A1 parsing and invalid-cell rejection. Shared core now **26/26 PASS** with Clippy warnings-as-errors PASS.
- Verified a real synthetic developer-certificate XLSX generated using the **M12** anchor. Windows OPC signature integrity/identity PASS, OOXML DrawingML reports zero-based column 12 and row 11, and source bytes are unchanged. Evidence: `target/office-custom-cell-20261024/anchor-acceptance.json`.
- Updated offline Office confirmation kit `C:\Users\User\Documents\CRAFT_OFFICE_ACCEPTANCE_20261026_V2.zip` includes Word signed/unsigned, Excel signed/unsigned at E2 and an additional signed Excel graphic at M12. SHA-256 manifest and Bulgarian instructions accompany all five test documents.
- No release to main, no hardware B-Trust attempt and no QES claim for Office files. The manual Office acceptance remains scheduled for **26 October 2026**.
