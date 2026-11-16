# Signed 0.2.3 Craft Signer — actual Rust host resolver acceptance

Date: 2026-11-16. Status: **PASS in isolated synthetic owner profile; production NO-GO**.

The opt-in Rust test `installed_broker::v023_acceptance::signed_v023_resolver_authenticates_and_rejects_modified_release` uses the actual signed 0.2.3 .NET manifest, detached CMS, public publisher certificate and all three binary payloads. It copies the bytes into a random disposable `tempfile` directory, creates an **explicitly synthetic** publisher policy and active registration **only inside that temporary tree**, and invokes the real Rust `resolve_under` host module-discovery API.

It verifies:

- The authenticated signed 0.2.3 catalog, version, public publisher RSA key and real broker SHA-256 are accepted.
- The authenticated broker, WordCraft CLI and GridCraft CLI remain pinned and locked while the resolver returns its checked handle.
- A substituted registration release name is refused.
- A forged publisher public key is refused.
- An unexpected DLL file in the signed release is refused.
- A byte modification in the copied GridCraft worker is refused.
- No test files are created in the actual user's `Craft\Extensions` approval/registration root.

Independent publisher RSA SPKI SHA-256: `E70FFDFAD52A79E3EDB3C0E1CC74694303109E0CA8C8849A51E5DCF5ED13E0AB`.

## Execution on Lenovo

```powershell
$env:CRAFT_SIGNER_V023_QA_ROOT = 'C:\Users\User\Documents\GitHub\craft-signer-v023-qa-20261116'
cargo test -p craft-signing-core --locked --offline --lib installed_broker::v023_acceptance -- --ignored --nocapture
```

**Result: 1/1 PASS, exit 0**. Default suite: **43 passed, 0 failed, 6 ignored**, and strict Clippy with `-D warnings`: **PASS**.

The two 0.2.3 opt-in tests (separate detached-CMS public verification and actual Rust signed-module resolver) were explicitly executed, not counted as ignored PASS in the default suite. The pre-existing 0.2.1/0.2.2 fixture tests remain separately scoped.

No real Windows certificate provider, B-Trust PIN, production Craft host installation, Windows trust store, owner-approved module policy or real document signing was used. This tests the isolated **discovery boundary**, not installed GUI E2E or eIDAS QES.

**Production gate: NO-GO.**
