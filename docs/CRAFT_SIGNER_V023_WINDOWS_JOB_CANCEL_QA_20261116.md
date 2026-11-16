# Authenticated Office Sign — Windows broker process-family cancellation QA

Date: 2026-11-16. Source-only, explicitly opt-in Windows fixture. **PASS**.

## Scope

The existing signed Office host uses a Windows Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and assigns the authenticated broker **before** any request bytes are sent. A signed broker can spawn a certificate-provider-backed Office worker, so merely terminating the broker parent process would be insufficient.

This additional test compiles a **small local synthetic Rust executable** in a random temporary directory. The fake broker:

1. Reads the bounded synthetic IPC request.
2. Spawns a second copy of itself as a child and writes a test-only child-started marker.
3. Deliberately hangs without returning a reply.
4. The child would write a *survival marker* after four seconds if it escaped the process-family cancellation.

The host's real `invoke_authenticated_sign_broker` is called in a test worker thread, the test waits for proof that the synthetic child actually started, then signals the shared cancellation flag. The test asserts a cancelled result and that the child survival marker **does not appear** after waiting beyond the child's four-second deadline.

No actual signed module, hardware key, private certificate, provider PIN, Office file, owner approval or official Craft installation is accessed. The fixture is compiled as an ephemeral test executable and its binary is **not committed**.

## Actual execution

```powershell
cargo test -p craft-signing-core --locked --offline --lib office_host_sign::windows_job_qa::cancelling_job_terminates_synthetic_broker_and_descendant -- --ignored --nocapture
```

Observed: **1/1 passed, 0 failed**, process exit 0. Default library tests: **44 passed, 0 failed, 7 ignored**; this fixture is one explicitly executed opt-in test, not counted as default PASS. Strict Rust Clippy `-D warnings`: **PASS**.

## Security limits

- This demonstrates the Windows Job/process-tree cancellation boundary for a cooperative synthetic child process with a deliberately unresponsive parent. It is **not** a real B-Trust PIN cancellation or a qualified Office signature acceptance.
- A native certificate-provider popup may involve a system-managed process not necessarily belonging to the broker's job. Its UI lifecycle and cancellation behavior must be tested separately by the owner.
- No change to the existing v0.2.3 signed installer or to WordCraft/GridCraft binaries was necessary. This branch adds an isolated test fixture and a test module declaration only.

**Release gate stays NO-GO** until owner-attended installed-module and upstream ArtCraft acceptance.
