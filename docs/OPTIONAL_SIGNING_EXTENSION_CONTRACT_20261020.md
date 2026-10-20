# Craft Signing Extension — optional add-on architecture

Status: **design and implementation contract; NOT an installable, signed release**.

## Goal
An optional, independently installable Windows signing add-on for existing PDFCraft, WordCraft and GridCraft installations. Do not overwrite, patch, inject into, or re-sign their installed executables. No automatic UI buttons are claimed.

## Version 1: standalone shell integration
- Distribute a separate `CraftSigningExtension.msi` only after trusted signing and installer QA.
- Install a signed `craft-signing.exe` and versioned format adapters under the extension's own directory.
- Register opt-in, per-user Windows Explorer **Send to** integration or a clearly named context-menu verb for supported document files; registration and removal must be reversible and not alter application registrations.
- Command-line entry: `craft-signing sign|verify --input <path> [--output <path>]`; no shell command interpolation of untrusted paths.
- Default output is a new sibling file; never modify or replace the original document without explicit user approval.
- Format adapters: PDF -> PAdES (requires independently validated integration); DOCX/XLSX -> OPC/XMLDSig (requires Office interoperability acceptance).
- Provider UI owns certificate selection and PIN entry. Never export private keys or collect PINs.
- Signing, document-integrity verification, trust-chain validation and **QES qualification** are separate verdicts. Do not label a CMS digest manifest or synthetic OPC signature as qualified.
- Uninstall removes only extension-owned files and shell registration; leave editor installations and user documents untouched.

## Version 2: editor UI integration
- Optional button in each Craft editor only after that editor implements and ships a reviewed, stable extension API or adapter hook.
- No DLL injection, binary patching, unauthorized replacement or impersonation of upstream publisher.

## Existing code to reuse
- `tools/office_opc_sign.ps1`: Windows OPC DOCX/XLSX sign/verify prototype; synthetic tests 2/2 PASS, Office interoperability and qualified status unproven.
- `tools/craft_file_digest_cms.ps1`: separately signed CMS digest manifest; **not** an embedded format signature or QES.
- Existing PDFCraft PAdES/QES work is in the PDFCraft fork; do not assume a stable callable external interface until verified.

## Required acceptance gates
1. Non-destructive standalone sign/verify tests for each file format and tamper rejection.
2. Verify Explorer integration with paths containing spaces, Unicode and special characters; test uninstall/rollback.
3. Verify actual B-Trust provider hardware path with user-present PIN dialog; no PIN capture.
4. Independent validation of resulting format-specific signatures and QES status, including negative cases.
5. Trusted Authenticode EXE and MSI, reproducible source/build provenance and Windows Smart App Control install/launch testing.
6. Confirm extension works with already installed upstream editors without changing them.

Release: **NO-GO** until all relevant gates pass. This document is not evidence that an installer exists.
