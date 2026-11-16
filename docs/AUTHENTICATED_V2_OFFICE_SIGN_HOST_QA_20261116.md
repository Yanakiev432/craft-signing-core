# Authenticated Craft Signer v2 — native Office signing host adapter

Date: 2026-11-16. Status: source-only QA, **production NO-GO**.

## Implemented

The Windows-only `craft_signing_core::office_host_sign::sign_office_via_installed_signer` performs a document-specific `document.sign` request over the authenticated signed-module broker boundary, using only the signed broker executable obtained from `resolve_installed_broker`. It does **not** search PATH or fall back to any unpinned Office executable.

The UI must supply an explicit `OfficeSignChoice::AllowAdditional`, certificate thumbprint, saved Office file, new output destination and cancellation flag. No PIN, private-key bytes, provider callback or shell command is passed through the Rust adapter. `Unconfirmed` and `RestrictAdditional` are refused before module discovery; the current native OPC backend does not support restricting future signatures.

The source is SHA-256-bound; the destination must be new. The Windows broker is assigned to a kernel Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` **before any request bytes are written**, so a cancellation or deadline terminates its process family rather than only the parent. IPC is bounded (16 KiB request, 32 KiB reply). A 340-second host deadline covers the signed broker's own 300-second signing worker deadline. The .NET broker remains responsible for the Windows provider-owned PIN prompt and its own worker cancellation.

The adapter validates the exact request ID, response kind, response status, worker exit, and the new output's native OPC signature using `PreparedOfficeSign::checked_sign_reply`. It rechecks source and output hashes. This is OPC cryptographic integrity, **not** independent certificate trust, revocation or an eIDAS QES classification.

## Machine-verifiable source QA

`cargo test -p craft-signing-core --locked --offline --lib`: **43 passed, 0 failed, 4 ignored**.

`cargo clippy -p craft-signing-core --locked --offline --lib -- -D warnings`: **PASS**.

Four new tests cover: no UI confirmation, unavailable restrictive policy, cancellation before module discovery, and oversized or absent IPC requests. No actual signing process was launched by those tests. The ignored opt-in tests remain separately scoped.

## Next implementation and acceptance

1. Pin the native WordCraft and GridCraft QA branches to this source revision; expose a distinct, explicitly confirmed **v2 Sign new copy** UI path while preserving the old QA branch controls.
2. Test the two host UI code paths and check that no real signing or module trust registration occurred.
3. Build and independently sign a **new** broker/module release, including the explicit additional-signature policy. The 0.2.2 signed binary is immutable and **cannot** satisfy the new field.
4. In an owner-attended session, approve the exact module publisher in the GUI, test native provider-owned B-Trust PIN dialogs, then run independent integrity and EU DSS evidence checks.
5. Seek upstream ArtCraft release acceptance. Until then do not claim the official product ships this code.

The adapter has not been tested with a real provider or B-Trust hardware token. Production is not ready.
