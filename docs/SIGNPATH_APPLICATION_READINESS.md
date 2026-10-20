# SignPath Foundation application readiness — Craft Signing

Status: **DRAFT / NOT SUBMITTED / NOT APPROVED**.

## Project

- Repository: https://github.com/Yanakiev432/craft-signing-core
- License: `MIT OR Apache-2.0`, with `LICENSE-MIT` and `LICENSE-APACHE` in the feature branch.
- Product: optional shared signing contracts and developer tooling for PdfCraft, WordCraft and GridCraft.
- Release channel: **development only**, not production-ready or standalone.
- Pull request: https://github.com/Yanakiev432/craft-signing-core/pull/7

## Verifiable unsigned Windows build

- Workflow: `.github/workflows/craft-msi-dev.yml`.
- Run: https://github.com/Yanakiev432/craft-signing-core/actions/runs/39489680006
- Source commit: `530e679960362fbd00ad06d71a1a631595c03b9f`.
- Workflow conclusion: success; MSI compiled, Authenticode `NotSigned`, artifact uploaded.
- MSI SHA-256: `2CBCBF555E2A9D061820D036FC2915D7BE0629B1B0383BD28C44F5BB26CB20CF`.
- GitHub artifact ID: `12295425528`; artifact expires after seven days.

## Requested service

Request consideration for free open-source Authenticode signing of Windows MSI distribution **only if eligibility is confirmed by SignPath Foundation**. No private keys, PINs or personal signed documents are uploaded. Signing should occur on reviewed source and reproducible CI provenance; final signing workflow remains to be designed with the provider.

## Before submitting

1. Confirm applicant identity, maintainer contact, project eligibility and required SignPath account steps with the project owner.
2. Confirm project copyright attribution and all third-party licensing.
3. Document source-to-MSI provenance, installer payload, tests and release process.
4. Verify provider requirements for project maturity, public release and permitted signing subjects.
5. Do not represent a development artifact as a stable public release.

## Unresolved acceptance gates

- `SIGNPATH_APPROVAL`: PENDING
- `TRUSTED_AUTHENTICODE_MSI`: PENDING
- `OFFICE_INTEROPERABILITY`: PENDING
- `PRODUCTION_RELEASE`: NO_GO