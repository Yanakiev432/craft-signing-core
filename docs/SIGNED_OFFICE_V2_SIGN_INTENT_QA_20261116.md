# Craft Signer v2 — Office signing intent and anti-forgery QA

Date: 2026-11-16. Status: **source-only QA; production NO-GO**.

## Implemented now

The Windows-only `craft_signing_core::broker_protocol::prepare_sign` creates a strictly scoped `document.sign` IPC envelope for the independently authenticated v2 broker. The caller must supply a saved .docx/.xlsx, a **new** absolute local output, a chosen exact 40-hex-character certificate fingerprint, a canonical request ID, and an explicit user-confirmed flag. A PIN, private key, shell command or untrusted worker executable is never encoded.

Validation rejects an unsigned/dirty source, missing consent, invalid certificate fingerprint, format mismatch, source overwrite, occupied target, redirected output parent, reserved Windows device name and unsafe output path. A SHA-256 and saved timestamp bind the source. `PreparedOfficeSign::unchanged` rechecks source and vacant output before dispatch. The broker's response cannot assert eIDAS QES.

`PreparedOfficeSign::checked_sign_reply` allows only the exact `SIGNATURE_CREATED` result for the request ID, document kind and success exit code, then independently verifies at least one native OPC signature in the generated file and rehashes the signed output before/after verification. Source freshness is checked again. A fake broker success, forged QES claim or unsigned output is not accepted.

## Actual machine evidence

Run on Yanakiev-Lenovo in offline, CPU-only Rust with `cargo test -p craft-signing-core --locked --offline --lib`:

- **39 passed, 0 failed, 4 ignored**. The ignored opt-in fixtures are the separate real signed-catalog, installed-module, legacy→newer fixture and .NET broker IPC scenarios; this run does not claim them.
- New signing tests cover user consent and certificate specificity, digest/target identity, existing-destination races, altered source, rejection of forged successful response and an unsigned output.

## Boundaries still open

- This builds a reusable **signing protocol intent and output validator**, NOT the native `OfficeSignUi` v2 Sign button. Current WordCraft/GridCraft GUI Sign is still on its legacy pinned CLI worker; v2 Verify is separate.
- Broker 0.2.2 currently does not expose the GUI's `allow additional signatures` policy, and its `userApproved` boolean cannot by itself prove a real human UI action. Do not claim that either behavior is solved.
- A cancel-safe, process-tree-safe v2 Sign IPC host adapter and native GUI E2E, including certificate-provider-owned PIN prompts, remain to be implemented and accepted.
- Never use real personal keys or hardware PINs in automated QA. The exact 0.2.2 signed package stays immutable; do not silently revise its signed contents.
- No installed Craft app, owner-approved publisher policy, user registration or production document was changed.

This checkpoint should be reviewed as a small protocol contribution before making native signing depend on it.
