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
