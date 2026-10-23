# PDFCraft-style visible signing appearance — Office proof of concept

Date: 2026-10-23. Test suite is **synthetic**, signed only with the local software development certificate.

## Reused PDFCraft design

The appearance is derived from the existing PdfCraft signing interface `crates/ui-egui/src/sign_ui.rs`: a 96 px preview with a neutral hairline border, large signer name at left and smaller "Digitally signed by" / name / date lines at right. It is **not** a PDF object copied verbatim into DOCX/XLSX: Office uses distinct OPC package parts.

## Word

The PowerShell test tool `tools/word-pdfcraft-visible-appearance-pilot.ps1` produces an unsigned synthetic DOCX with the visible PNG embedded under `word/media/`, a VML shape in `word/document.xml`, and `o:signatureline` metadata. A separate signed copy is made using the Windows native OPC implementation.

Checked: image and line persist in signed DOCX; WindowsBase verifies the OPC signature; original input SHA-256 unchanged; LibreOffice opens/converts signed DOCX. **The native Word Sign/Signature Setup context action has NOT been established.** A visible line element with preview image is not equivalent to an Office-bound signing experience.

## Excel

`tools/excel-pdfcraft-visible-appearance-pilot.ps1` embeds the same PNG into a new SpreadsheetDrawingML picture anchored at E2. It links worksheet -> drawing -> image via OPC relationships, and independently signs its own synthetic XLSX.

Checked: signed drawing and PNG parts present; WindowsBase verifies OPC signature; original input SHA-256 unchanged; LibreOffice opens/converts signed XLSX. **There is no native Excel `o:signatureline` association, no Sign context action, and no grid-viewport coordinate mapping.** This is a *visible signed graphic*, not a native interactive Office signature line.

## Release gate

Do not merge a production implementation or advertise this as an interactive Office signature line until:
1. Word and Excel tests on real Microsoft Office confirm visual output.
2. Word's context menu for the VML `o:signatureline` is photographed and verified to expose working Sign / Signature Setup, or an alternative native line implementation is chosen.
3. Signing identity/date shown in the graphics are bound to the *real, selected certificate* and the actual signing time; never use synthetic words for production.
4. The visual marker is written into the **unsigned** package *before* creating cryptographic OPC signatures and must not invalidate preexisting signatures.
5. Native in-process Rust/C++ implementations and document-coordinate positioning exist; no PowerShell subprocess in production.
6. Existing signatures, audit logging, timestamp/QES classification and no-overwrite guarantees are re-tested.

No hardware PIN is collected, no personal document modified, no trust-store changes. QES status of the whole signed Office document remains a separate independent eIDAS gate.
