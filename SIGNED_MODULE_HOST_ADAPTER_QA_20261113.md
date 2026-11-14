# Craft Signer v2: independently authenticated native Office host adapter

Date: 2026-11-13
Status: source QA; already consumed in separate WordCraft/GridCraft Review QA branches; not deployed to installed apps.

## Architecture

This QA branch implements three reusable Windows-only pieces in the MIT OR
Apache-2.0 craft-signing-core library:

1. Native detached .NET CMS catalog validation (signed_module.rs). The exact
   publisher public SPKI SHA-256 must already have been independently approved.
   The RustCrypto CMS/X.509 parser and RSA 0.10.0 stable verifier check the
   publisher certificate, certificate dates, signer identity, one SHA-256
   signer, detached id-data content, cryptographic signature and the strict
   three-worker manifest. Only the RSA/SHA-256 no-signed-attributes profile
   emitted by the current signed module is accepted. Other modes fail closed.

2. Installed release authentication (installed_broker.rs). The production
   module root comes from the Windows LocalAppData known folder, not from a
   caller-controlled environment variable. The resolver only reads an
   already-existing owner publisher approval and current module registration.
   It checks the exact signed release leaf, refuses redirected folders and
   unrecognized DLLs, verifies the CMS publisher and validates SHA-256 of all
   three executable worker files, holding read-sharing locks until the host
   drops the returned VerifiedInstalledBroker handle.

3. Read-only verified Office broker execution (office_host.rs). A native host
   background worker may call verify_office_via_installed_signer on a saved
   DOCX or XLSX. The adapter prepares strict v1 document.verify JSON, obtains
   a cryptographically random UUID, enforces saved/dirty and local path guards,
   hashes the original Office bytes, starts ONLY the authenticated installed
   broker with CREATE_NO_WINDOW, sends no PIN or signing parameters, bounds
   the reply to 32768 bytes and the verification to 90 seconds, and checks the
   process outcome, matched request ID and Office response. It independently
   rehashes the source before ever reporting integrity PASS.

A successful Office verification means OPC/XMLDSig package integrity only,
NOT eIDAS QES, certificate chain trust, revocation status or a qualified
timestamp. No private key crosses the Rust broker IPC.

## Executed QA

- 35/35 ordinary Rust library unit tests PASS; zero failed. Four special
  real-artifact tests are marked ignored for ordinary builds.
- 4/4 real-artifact opt-in tests PASS using the exact separately signed
  Craft Signer 0.2.2 developer package, with independently calculated SPKI
  SHA-256 and source artifacts kept outside Git.
- CMS signature verifies; altered manifest, CMS, public certificate and wrong
  publisher pin fail.
- Temporary complete release verifies ALL THREE real signed executable hashes.
  Wrong active release, false owner-approved key, unrecognized injected DLL
  and tampered GridCraft worker fail.
- Signed C# broker receives real Rust-generated read-only DOCX and XLSX
  requests and refuses them with PUBLISHER_NOT_APPROVED, preserving the
  original UUID. Unknown fields fail with UNKNOWN_FIELD.
- No user trust policy, installed module, official host binary, GPU task,
  hardware PIN or Windows certificate store was changed.

## Remaining deployment gates

The trusted host adapter is integrated into the first-party Review QA
branches for WordCraft and GridCraft. Their existing Sign and native Verify
remain independent. The hosts must now consume this new minimum-supported
release guard revision and repeat locked/offline compile and UI tests.

The real end-to-end acceptance still needs owner GUI approval of the local
developer key, registration of the signed 0.2.2 module, protected HTTPS EU
DSS configuration for PDF, and authorized UI/headless testing. No test
asserts a production QES PASS through the installed module.

## Cross-version host resolver QA -- 14 November 2026

The independently signed 0.2.1-qa and 0.2.2-qa package bytes were both
cryptographically validated in a disposable Rust host release store.
The 0.2.1-qa broker has a documented EU DSS unsigned-PDF parser defect;
this library now enforces a minimum compatible module version of 0.2.2.
The floor is validated only AFTER successful CMS publisher and catalog
authentication. This prevents activation of the known-defective old
release even if current.json is pointed at its correctly signed folder.

Executed acceptance:
- 35/35 standard library unit tests PASS; 4 opt-in tests deliberately ignored
  in the default CI/unit runner.
- 4/4 real signed .NET package/CMS/broker cross-language opt-in tests PASS.
- Minimum version parser: 0.2.1-qa and malformed versions rejected.
- Real 0.2.1 + 0.2.2 signed releases: new release accepted, rollback to the
  older release refused even when its detached CMS signature is authentic.
- Signed broker executable locked during verification: overwrite rejected.
- Partial or corrupt active registration: fail closed.
- Production library cargo check --lib --offline: PASS.
- Production library cargo clippy --lib --offline -- -D warnings: PASS.

This is a host COMPATIBILITY FLOOR, not durable global anti-rollback for
all future 0.2.3+ versions. The signed installer retains its independent
atomic-version promotion and downgrade policy. This test used private
temporary directories only; no live user approval policy was created.