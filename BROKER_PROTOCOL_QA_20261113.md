# Craft Signer broker v1 — host-neutral Office read-only protocol

Date: 2026-11-13
Status: **QA contract only; no host installation, GUI integration or publisher approval**.

## Scope and design

This introduces `src/broker_protocol.rs` (Windows-only) into the shared
MIT OR Apache-2.0 `craft-signing-core` library. It is intended for
the native WordCraft and GridCraft first-party Review interfaces.
It is *not* a signed module loader, trust policy, third-party plugin
loader, signing UI, process launcher, or independent eIDAS validator.

An authenticated caller supplies its saved local file path, document
family (`docx` or `xlsx`), dirty flag, and a canonical request UUID.
The `SavedOfficeSnapshot` hashes exactly the saved file. It rejects:

- Dirty or missing documents, non-local / redirected paths, wrong
  extensions, malformed request IDs, and file sizes exceeding 150 MiB.
- Concurrent writers during hashing (Windows `FILE_SHARE_READ`),
  files that change during hashing, unexpectedly grown files, and paths
  exceeding the .NET broker's 1800 UTF-16 code-unit limit.
- Serialization of arbitrary actions or signing parameters:
  `json_request()` emits strictly `document.verify`, `saved:true`,
  `dirty:false`, `sha256AtDispatch`, `sourcePath`, and the expected
  `kind`/protocol/request ID. It never transmits a PIN.
- Broker results with mismatched request UUID or document format,
  contradictory status / process exit code / worker exit code,
  unapproved or extra fields, QES/eIDAS claims, malformed codes,
  missing evidence, or changed source file bytes.

The only possible successful classification is
`OfficeIntegrity::IntegrityPass`: **OPC package signature integrity
only, not certificate trust or qualified eIDAS QES**. A normal
`IntegrityRejected` signals the worker did not verify the package.

## Acceptance

On authorized Windows Lenovo, the following passed in the isolated
branch `qa/typed-craft-signer-broker-v1-20261113`:

- 4/4 `broker_protocol::tests`: strict read-only DOCX IPC,
  wrong format / dirty state / bad UUID / non-local paths,
  forged QES / reply-process mismatch, XLSX format binding,
  byte mutation with identical file length.
- 30/30 `cargo test --lib --offline`.
- `cargo check --lib --offline`.
- `rustfmt --check src/broker_protocol.rs` for the changed source.

Repository-wide `cargo fmt -- --check` reports unrelated,
pre-existing formatting differences in other files; those files were
not modified to avoid an unrelated formatting patch.

## Host integration gate

The existing WordCraft/GridCraft `signer_extension.rs` uses a legacy
`craft.signer/1` manifest and hard-pinned worker SHA-256. It is
**not** the new 0.2.2 signed, independently registered broker.
A host MUST authenticate the installed release's publisher SPKI key,
detached .NET CMS manifest, release registration and broker hash
before executing a broker; merely passing this protocol and
checking a JSON reply is insufficient.

The independently verified 0.2.2 module-discovery model has already
been exercised in the PdfCraft QA fork. The next step is a common
verified-module resolver/host adapter wired to the native Review
interfaces, with explicit owner trust approval and live GUI acceptance.
No system trust store, installed host, token or publisher policy was
changed during this QA.
