# Synthetic Word OOXML signature-line prototype — 2026-10-23

Status: **structural prototype PASS; in-app / Microsoft Word interoperability NOT ASSESSED**.

The experimental tool `tools/oooxml-signatureline-prototype.ps1` uses only a temporary synthetic DOCX under `target/opc-live-*/unsigned.docx`, inserts `<o:signatureline>` inside a VML `<v:rect>` element in `word/document.xml`, and signs a separate output with the fixed local software-development identity via the existing native Windows OPC signer. It then opens the resulting signed DOCX and checks:

- The OOXML `o:signatureline` element and generated identifier survived the signing transaction.
- WindowsBase PackageDigitalSignatureManager independently reports one signature with `VerifySignatures(false)=Success`.
- Source and output SHA-256 values are recorded, and original synthetic input is not modified.

Reference: Microsoft Open XML `DocumentFormat.OpenXml.Vml.Office.SignatureLine` and Microsoft `[MS-ODRAWXML]` signature-line specification.

**Unsupported at this stage**: The VML shape is not yet a guaranteed Word-rendered signature line; no Microsoft Word installed, no Office visual or interoperability test, no user-coordinate-to-document geometry conversion, no actual signed-in-app workflow, no persisted XLSX signature line, no B-Trust USB operation, no eIDAS qualification or trusted signing time. Do not deploy this tool on personal documents or merge it as a finished feature.

Test script runs without browser, token PIN, hardware key, or altering installed Craft applications. Run manually after establishing a disposable synthetic OPC fixture:

```powershell
& "C:\Users\User\Documents\GitHub\craft-signing-core\tools\oooxml-signatureline-prototype.ps1"
```

Source branch: `feature/oooxml-signatureline-prototype-20261023`. Keep changes in draft review until Office interoperability is checked.
