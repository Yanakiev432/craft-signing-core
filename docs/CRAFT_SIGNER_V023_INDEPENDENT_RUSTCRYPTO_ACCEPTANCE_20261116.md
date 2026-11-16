# Independent RustCrypto acceptance of signed Craft Signer 0.2.3-qa

Date: 2026-11-16. **Source-only external verification**, not a real owner-approved module or eIDAS QES.

## Evidence

The `signed_module.rs` opt-in test `actual_dotnet_v023_catalog_and_three_payload_hashes_verify_independently` validates the actual developer-signed .NET 0.2.3-qa catalog through RustCrypto CMS, RSA PKCS#1 v1.5 and SHA-256. The trusted public RSA SPKI key was previously pinned independently for the signed 0.2.2 QA catalog:

`E70FFDFAD52A79E3EDB3C0E1CC74694303109E0CA8C8849A51E5DCF5ED13E0AB`

The v0.2.3 manifest's authenticated `moduleVersion` and all three exact worker SHA-256 digests were checked against **actual local binary bytes**:

| Worker | SHA-256 |
|---|---|
| craft-signer-broker.exe | `300A25093A40C997CD45A5DC6AF4F40A63581EFF80BEEAC36EA6257651A9B4D5` |
| wordcraft-cli.exe | `3778AA69845E7E35159AE09CC303046554EDC3DBF12C216114A60585E811E9A6` |
| gridcraft-cli.exe | `E86AD51AED75D54C22B6847921EE805CB1889DB3CA96D467D59AA7616B8E4CA2` |

Negative tests reject changed signed manifest, changed detached CMS, wrong publisher key and modified broker bytes. No executable was launched by the Rust verifier. The code does not load a token or sign documents.

Executed on Lenovo:

```powershell
$env:CRAFT_SIGNER_V023_QA_ROOT = 'C:\Users\User\Documents\GitHub\craft-signer-v023-qa-20261116'
cargo test -p craft-signing-core --locked --offline --lib signed_module::tests::actual_dotnet_v023_catalog_and_three_payload_hashes_verify_independently -- --ignored --nocapture
```

**1 passed, 0 failed**, exit 0. The regular Rust test suite also reports **43 passed, 0 failed, 5 ignored**, and `cargo clippy -p craft-signing-core --locked --offline --lib -- -D warnings` passes. The fifth ignored test is this explicitly opt-in real signed fixture, and has independently been executed successfully.

## Boundaries

- The Authenticode signatures use a local self-signed developer publisher, not a publicly trusted software signing chain.
- 0.2.3 is a new, separately signed test package, not a replacement of original signed 0.2.2 bytes.
- Installed-module GUI acceptance, native B-Trust PIN prompts and EU DSS QES confirmation remain future gates.
- This is **not** permission to approve the publisher policy on the user's behalf.

**Production release: NO-GO.**
