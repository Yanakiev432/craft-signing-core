# Craft Signer v2 — three-host Windows QA checkpoint

Date: 2026-11-15
Scope: read-only/synthetic source acceptance on authorized Lenovo,
      Windows x64, CPU-only, Cargo locked and offline.
State: ALL CURRENT SOURCE QA GATES PASS; NOT a production QES release.

## Five independently verified GitHub checkpoints

All local worktrees below are clean. The recorded local commit SHA was
verified against the owning fork's exact remote branch HEAD.

Shared core:
- Repository: Yanakiev432/craft-signing-core
- Branch: qa/typed-craft-signer-broker-v1-20261113
- Core code base SHA: 8428d93bfae3572aa719754ced0e4e6d727790ae
- No core code changes were needed for the new host view-freshness QA.

Separately signed installer:
- Repository: Yanakiev432/craft-signer-installer
- Branch: qa/signed-standalone-v022-20261113
- Source/report SHA: eb0fd1809db8d3aadcc86e42c2fd72ce4115dc25
- Preserved independently signed bounded-source QA executable SHA-256:
  947061BCB99C9D5E20B1ED9F194476BB65B4A905A80CFCEFFDB418ABA9724E94
- Signer: CN=Craft Open Source Local Code Signing.
- Windows signature type: Authenticode; chain status remains UnknownError.
  This local self-signed key is NOT a public production trust root.

WordCraft:
- Repository: Yanakiev432/wordcraft
- Branch: qa/stale-verification-evidence-20261115
- SHA: 0b3c061c3dc97473b2d9c5b701234755c780a3af
- Windows Office signature dialog: 9 unit tests PASS; 0 fail.
- CPU-only Review Sign/Verify/Verify v2 test: 1 PASS.
- Locked offline cargo check (UI and CLI): PASS.

GridCraft:
- Repository: Yanakiev432/gridcraft
- Branch: qa/stale-verification-evidence-20261115
- SHA: cb972b3447658ec274ebc1b38c21438751bc34a4
- Windows Office signature dialog: 9 unit tests PASS; 0 fail.
- CPU-only Review Sign/Verify/Verify v2 test: 1 PASS.
- Locked offline cargo check (UI and CLI): PASS.

PdfCraft:
- Repository: Yanakiev432/pdfcraft (fork remote, NOT upstream origin)
- Branch: qa/pdfcraft-signer-view-freshness-20261115
- SHA: 4d9e75c84c507513f3b6770fa0a37606f1832cce
- Four synthetic asynchronous freshness/UI tests: 4 PASS; 0 fail.
- Signing-client protocol/hash/fail-closed tests: 10 PASS; 0 fail;
  1 opt-in signed .NET interop test intentionally ignored, NOT PASS.
- Locked offline cargo check (PDF signing library and GUI): PASS.

This run: 34 executed Rust tests PASS (9+9+1+1+4+10), zero failures,
one separate opt-in interop test ignored; three GUI/CLI or GUI/sign
offline check commands PASS. This number excludes earlier distinct
core/installer acceptance suites, which were not rerun in this run.

## Security properties accepted at source QA only

- Detached CMS, exact approved publisher public-key pin, three worker
  hashes, minimum compatible signer module version and typed broker IPC
  are handled by the common signed host resolver.
- WordCraft/GridCraft invalidate a successful verification when the
  saved document hash differs across the asynchronous verification
  operation, and on observed view switches or unsaved edits.
- Both Office GUIs use lightweight file metadata freshness checks
  after verification. They do not claim immutable perpetual validity.
- PdfCraft retains pre/post SHA-256 binding for broker verification.
  Its GUI no longer performs a 64 MiB-capable SHA-256 pass on each
  repaint. It monitors active-document switches outside the panel,
  uses a lightweight metadata predicate on frames, and runs a bounded
  SHA-256 refresh asynchronously every 5 seconds while Signatures
  is visible. Failure or a >30-second refresh invalidates the verdict.
- These tests are synthetic source QA only. A changed PDF that forges
  both length and mtime might escape observation between refreshes;
  no unbreakable, continuously immutable file snapshot is claimed.

## Windows owner state verified on 2026-11-15

- Real per-user module registration: ABSENT.
- Real module-specific publisher approval policy: ABSENT.
- Signed QA executable was never activated or installed.
- No private signing key export, token PIN capture, Windows trust-store
  modification, installed Craft app changes, GPU job, training,
  paid API operation or machine reboot was performed.

## Outstanding production gates (NOT PASS)

1. Obtain explicit owner review and approval of the module-specific
   publisher PUBLIC key. Never silently trust the local developer
   certificate in the Windows Root/TrustedPublisher stores.
2. Only after approval, controlled local signed-module install, exact
   package verification, update and rollback checks.
3. Configure a separately verified, pinned local HTTPS EU DSS policy.
4. Validate genuine B-Trust PDF QES, independent eIDAS evidence, byte
   binding and a tampered-PDF negative test through installed broker,
   native PdfCraft UI and CLI. No PIN is ever transmitted through IPC.
5. Complete real signed DOCX/XLSX OPC verification and native GUI UX.
   Office signature integrity alone is NOT proof of eIDAS QES status.
6. Test installer lifecycle, first-party host distribution and future
   publisher-key rotation before any production rollout.

This checkpoint does not authorize the next gate or falsely label
any real signature, native installed app or public Windows publisher
as production QES PASS.