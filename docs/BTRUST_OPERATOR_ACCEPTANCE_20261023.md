# B-Trust USB OPC operator acceptance — prepared, NOT executed

Date: 2026-10-23. Purpose: test the actual B-Trust qualified-certificate hardware
provider through Windows native OPC signing on **synthetic** DOCX/XLSX fixtures only.

## Preflight PASS (non-signing)

Run from the repo root in PowerShell 7:

```powershell
& "C:\Users\User\Documents\GitHub\craft-signing-core\tools\btrust-opc-operator-acceptance.ps1" -Mode Preflight
```

Two B-Trust certificates linked to private keys are currently visible in
CurrentUser/My and within their validity periods. No PIN was requested and no
cryptographic signing operation was started.

## Interactive signing protocol (NOT YET EXECUTED)

Run **on the authorized user's local Windows desktop**, not through a headless
agent, service account, scheduled task or remote process without visible PIN UI:

```powershell
& "C:\Users\User\Documents\GitHub\craft-signing-core\tools\btrust-opc-operator-acceptance.ps1" -Mode Sign
```

Choose the intended certificate **by index** and type `SIGN` to authorize
two synthetic documents only. If the hardware provider requests a PIN, enter it
**only in the provider's own Windows dialog**, never in the script or ChatGPT.
Any cancellation or non-zero process exit is a failure, not a PASS.

The script rejects input outside the core's `target\` tree, refuses to overwrite,
checks that the original synthetic fixtures are unchanged, independently reopens
each signed package with WindowsBase, confirms the expected certificate and
cryptographic integrity, and writes a non-secret JSON acceptance report under a
new `target\opc-btrust-operator-*` directory.

## Gates not covered by this test

Cryptographic OPC integrity is different from verifying a qualified electronic
signature. Certificate policy, EU Trusted Lists, revocation, qualified signature
creation device status, and independent eIDAS classification remain
`NOT_ASSESSED`. Microsoft Word/Excel interoperability is `NOT_TESTED`,
because Microsoft Office is not installed on the test machine. The preview
GUI still lacks a persistent OOXML visible signature-line object.

No physical B-Trust signing has been performed in preparing this script.
