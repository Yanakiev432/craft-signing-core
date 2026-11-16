# Fail-closed v0.2.3 minimum version for authenticated Office signing

Date: 2026-11-16. Source-only QA; production remains **NO-GO**.

The authenticated Windows Sign host previously relied on the signed broker rejecting an unrecognized explicit `allowAdditionalSignatures` request field. The immutable signed module v0.2.2 predates this field. Although its rejection would be safe, it would start the broker unnecessarily and produce a generic IPC error.

The host now checks the **cryptographically authenticated signed catalog's** `module_version` after `resolve_installed_broker` and before any signing request is sent. A version strictly below 0.2.3 (e.g. `0.2.2-qa`) is refused with the actionable message `Craft Signer 0.2.3 or newer is required for signed Office v2 signing; no signing attempted`. Invalid, negative, malformed or ambiguously zero-padded versions are refused. Valid `0.2.3-qa`, `0.2.3`, `0.2.4` etc. pass the protocol version check; the signed module's independent catalog and release identity checks still apply.

The read-only v2 **Verify** path has a different host adapter and is unchanged. The source code never interprets the check as explicit owner approval.

On the Lenovo Windows QA branch: default library suite **44 passed, 0 failed, 6 ignored**; strict Rust Clippy `-D warnings`: **PASS**. The ignored signed-fixture tests were scoped separately and are not part of this count.

No real owner approval, module registration, provider PIN, actual Office signing, public distribution or official ArtCraft application was modified.
