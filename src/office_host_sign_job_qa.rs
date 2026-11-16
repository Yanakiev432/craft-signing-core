//! Isolated Windows process-tree cancellation test for the signed Office host.
//! This compiles a tiny synthetic local executable; it never uses a key/PIN,
//! never touches live publisher approval or installed Craft modules.
use super::*;
use std::sync::Arc;

#[test]
#[ignore = "compiles an isolated synthetic broker and child process; no real signing"]
fn cancelling_job_terminates_synthetic_broker_and_descendant() {
    let dir = tempfile::tempdir().expect("fresh local synthetic process directory");
    let source = dir.path().join("synthetic_job_broker.rs");
    let executable = dir.path().join("synthetic_job_broker.exe");
    let spawned = dir.path().join("child-spawned.txt");
    let survivor = dir.path().join("child-survived.txt");
    let template = r##"
use std::{io::Read, process::Command, thread, time::Duration};
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--child") {
        thread::sleep(Duration::from_secs(4));
        let _ = std::fs::write(r#"@SURVIVED@"#, b"child was not killed");
        return;
    }
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).expect("read synthetic request");
    if input.is_empty() { return; }
    let exe = std::env::current_exe().expect("synthetic executable");
    let child = Command::new(exe).arg("--child").spawn().expect("synthetic child");
    std::fs::write(r#"@SPAWNED@"#, child.id().to_string()).expect("child spawn marker");
    thread::sleep(Duration::from_secs(30));
}
"##;
    let fixture = template
        .replace("@SPAWNED@", &spawned.to_string_lossy())
        .replace("@SURVIVED@", &survivor.to_string_lossy());
    std::fs::write(&source, fixture).expect("write synthetic Rust fixture");
    let compiler = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let code = Command::new(compiler)
        .args([
            "--edition",
            "2024",
            "--crate-name",
            "craft_synthetic_job_qa",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .status()
        .expect("run local Rust compiler");
    assert!(code.success(), "cannot build synthetic Windows broker");

    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancel = Arc::clone(&cancelled);
    let task = thread::spawn(move || {
        invoke_authenticated_sign_broker(&executable, br#"{"synthetic":true}"#, &worker_cancel)
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !spawned.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(40));
    }
    cancelled.store(true, Ordering::SeqCst);
    let reply = task.join().expect("synthetic host task must not panic");
    assert!(
        spawned.exists(),
        "synthetic child never started, no cancellation evidence"
    );
    let error = reply.expect_err("cancelled synthetic signing must fail");
    assert!(
        error.to_ascii_lowercase().contains("cancel"),
        "wrong error for cancelled child process: {error}"
    );
    // If the child escaped the Windows job, it will write after four seconds.
    // The test-only process is blocked at most 30s and can never touch Craft.
    thread::sleep(Duration::from_millis(4_500));
    assert!(
        !survivor.exists(),
        "synthetic signing child survived cancellation of the Windows process job"
    );
}
