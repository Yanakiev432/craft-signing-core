# Office visible signing — certificate-bound native integration

**Status:** source candidate, **not released**; 2026-10-23. Installed Craft Suite 1.0.4 unchanged.

## Verified code path

1. **WordCraft / GridCraft:** The same PDFCraft-style signing preview is shown after selecting a Windows Digital ID. Toggle **Embed this PDFCraft-style appearance** to opt in; the default is the existing invisible native OPC signature.
2. **Craft signing core:** Reads the same selected SHA-1 certificate thumbprint from the Windows CurrentUser/My certificate store, checks linked private key and validity, derives the visible name from its subject (never from untrusted user input), and uses the local device time as untrusted text.
3. **In-process renderer:** SVG layout matching PDFCraft's 1000x290, name left / details right / neutral border, rendered via resvg + Windows Segoe UI system fonts into a bounded PNG. No fonts or PINs are packaged or shared.
4. **Unsigned DOCX:** Adds a VML graphic, PNG relationship, o:signatureline metadata at the end of the document; the Microsoft Word native Sign context action remains unverified.
5. **Unsigned XLSX:** Adds a SpreadsheetDrawingML picture at sheet1 E2; this is a visible graphic, NOT a native Excel Sign control.
6. **Native OPC:** Signs only after embedding, using the selected Windows provider / hardware PIN prompt if applicable; re-verifies the full package; atomically publishes a new file without replacing any existing file.

The GUI marks the drawn screen rectangle not yet mapped to OOXML coordinates. It explicitly describes the fixed placement. It cannot claim arbitrary drag/drop placement, qualified timestamps, QES or MS Office-native signature-line interaction.

## Tests on Yanakiev-Lenovo

- craft-signing-core: 20/20 Rust unit tests PASS (including renderer safety and no implicit signer choice).
- Previous synthetic PNG writer: DOCX + XLSX native XML embedding + independent WindowsBase OPC 2/2 PASS.
- Structure-level acceptance: DOCX + XLSX OPC part relationships, PNG bytes and unmodified original parts PASS; target/native-office-visible-20261023/xml_evidence.json.
- Existing-signed-input rejection: 2/2 PASS, source SHA256 preserved.
- Real cert-bound preview renderer + OPC signing, test software certificate: DOCX + XLSX 2/2 PASS; target/native-identity-appearance-20261023/acceptance.json.
- Independent LibreOffice DOCX and XLSX import/convert to PDF from cert-bound Rust outputs: 2/2 PASS, sources unchanged.
- WordCraft and GridCraft cargo check PASS with the embedded-appearance option compiled.
- The prior B-Trust hardware certificate has been independently validated for DOCX/XLSX plain OPC signatures and on desktop Microsoft Office; it has not yet been used to sign the new visible Rust candidate.
- Independent whole-document eIDAS QES qualification is still open. Microsoft Office testing for these exact new rendered files and the native Sign action is still open.

## Security and gating

- No mutation of personal or signed input documents. Existing signatures block adding a new appearance: to add another signer without invalidation, use invisible OPC multi-signing.
- Signed outputs are created separately and uniquely. Source name in bitmap bound to provider certificate selection. PKI trust is assessed separately from package integrity.
- Max 128 MiB inflated OPC input for this experimental writer, up to 2 MiB PNG, PNG dimensions at most 2000 x 2000; invalid package paths, duplicate entries and unsupported compression rejected.
- Current XML transformations support a constrained set of Word/Excel layouts. Untested complex documents fail closed rather than silently rewriting an existing drawing.
- Do not merge this into production or change installed apps until native Word and Excel UI functional acceptance, more OOXML layout variants, certificate and time audit, and robust place mapping are completed.

This source candidate makes a visible and cryptographically protected appearance; it does not claim native Word/Excel interactive signature lines.
