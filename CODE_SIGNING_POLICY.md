# Code signing policy — Craft Signing Extension

**Status (2026-10-20): application preparation only.** SignPath Foundation has not approved this project, and no installer has been signed by SignPath. Public release remains blocked by the Authenticode gate.

**Prospective attribution (conditional on approval):** Free code signing provided by SignPath.io, certificate by SignPath Foundation.

## Source, publisher and roles

- Source: https://github.com/Yanakiev432/craft-signing-core
- Maintainer, author, reviewer and prospective signing approver: repository owner (Yanakiev432).
- Production signing requires a human approval for each release, MFA for repository and SignPath accounts, and a verifiable build from the public repository.
- Never sign unrelated third-party projects with this project's certificate.

## Build and distribution

Only installer artifacts built from reviewed, versioned project sources on a SignPath-approved trusted build system are eligible for production signing. Local Windows development MSI builds are **unsigned** and are not production releases. Source commit, build job, unsigned artifact hash, signing request, signed artifact hash and Authenticode result must be recorded. Pull requests and unreviewed commits must not have production signing access. No private signing keys or token PINs are stored in GitHub.

Until approved and independently verified, any download must be explicitly described as unsigned. The local Authenticode release gate rejects unsigned installers. Do not claim that code signing alone guarantees the absence of Microsoft SmartScreen warnings.

## Privacy and network access

The signing extension runs locally and accesses selected documents and certificates on the user's computer. The local DSS validator may retrieve EU trusted lists and revocation information (OCSP/CRL) over the network; the document itself is sent only to the loopback validation endpoint in the documented local test. Future signing services, updates or telemetry must be disclosed before enabling them. The project does not intentionally upload personal signed documents to SignPath.

## Current release blockers

- Verify repository-wide licensing and all bundled dependency licenses; README says MIT OR Apache-2.0, but a standalone LICENSE file was not found on main during this audit.
- Publish a documented, versioned unsigned development release if allowed by the project's release policy; SignPath expects an already released project.
- Establish a reproducible, trusted CI build and evidence of its source provenance.
- Obtain SignPath Foundation approval and configure a human-approved signing policy.
- Verify signed MSI Authenticode, timestamp, SHA-256 and installation before marking release GO.

References: https://signpath.org/terms and https://signpath.org/apply.html
