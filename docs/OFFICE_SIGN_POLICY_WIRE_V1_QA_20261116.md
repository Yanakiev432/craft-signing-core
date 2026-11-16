# Shared Rust Office signing contract — explicit additional-signatures policy

2026-11-16 — source-only QA update after commit `1756641`. No real signing or installed-module activation.

The `prepare_sign` call now requires an explicit `allow_additional_signatures` argument. Only `true` is currently supported by the native Office CLI; a restrictive policy is rejected before preparing any broker request.

The JSON `document.sign` payload includes `allowAdditionalSignatures: true`, in addition to saved-document digest, kind, request ID, new output location, exact Windows certificate thumbprint, and explicit host UI confirmation. It is bounded to the previously authenticated module protocol v1.

The matching C# broker source requires exactly the same explicit field, rejects missing/false values before worker execution and forwards the supported `--allow-additional-signatures` CLI flag. For read-only `document.verify`, the signing-policy field is forbidden.

This is a source contract, **not** proof that the signed v0.2.2 binary accepts this additional field, and **not** a finished native GUI Sign integration. Tests use only synthetic documents and responses; 0.2.2 hashes and signed QA package remain unchanged.

The next source stage is an authenticated v2 signing host adapter with safe broker+worker process-tree cancellation, followed by a native GUI acceptance that requires separate human certificate confirmation and provider PIN entry. No code-signing, trust registration or production release has been approved.
