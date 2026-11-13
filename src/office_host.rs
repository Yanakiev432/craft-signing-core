//! Read-only native Office host adapter over a fully authenticated Craft
//! Signer module, with bounded IPC and no direct key or PIN handling.
//!
//! This is a synchronous worker function: native GUI callers MUST invoke it
//! from their own background job, not from the render/UI event thread.
use crate::{
    broker_protocol::{OfficeIntegrity, OfficeKind, prepare_verify},
    installed_broker::resolve_installed_broker,
};
use std::{
    io::{Read, Write},
    os::windows::process::CommandExt,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const MAX_REPLY: usize = 32_768;
const VERIFY_TIMEOUT: Duration = Duration::from_secs(90);

fn new_request_uuid() -> Result<String, String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| "Cannot obtain a secure broker request ID")?;
    random[6] = (random[6] & 0x0F) | 0x40;
    random[8] = (random[8] & 0x3F) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        random[0],
        random[1],
        random[2],
        random[3],
        random[4],
        random[5],
        random[6],
        random[7],
        random[8],
        random[9],
        random[10],
        random[11],
        random[12],
        random[13],
        random[14],
        random[15],
    ))
}

/// Verify a saved DOCX/XLSX via the owner-approved and cryptographically
/// authenticated installed Craft Signer module. Never attempts signing.
/// IntegrityPass is OPC integrity only, not eIDAS QES or chain trust.
///
/// Returns an error whenever publisher approval is missing or the module,
/// file, process result or certificate identity cannot be trusted.
pub fn verify_office_via_installed_signer(
    saved_source: &Path,
    kind: OfficeKind,
    unsaved_edits: bool,
) -> Result<OfficeIntegrity, String> {
    if unsaved_edits {
        return Err("Save Office changes before verifying signatures".into());
    }
    // Resolve trusted module and lock *all* its signed worker binaries.
    // A malicious registration, unknown publisher, foreign DLL or changed
    // worker must never be executed, even when it claims a positive result.
    let trusted = resolve_installed_broker()?;
    let request_id = new_request_uuid()?;
    let snapshot = prepare_verify(saved_source, kind, false, &request_id)?;
    let input = snapshot.json_request()?;
    snapshot.unchanged()?;

    let working_directory = trusted
        .executable()
        .parent()
        .ok_or("Signed broker folder is missing")?;
    let mut child = Command::new(trusted.executable())
        .current_dir(working_directory)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Cannot start the authenticated Craft Signer broker")?;

    let reader = match child.stdout.take() {
        Some(pipe) => pipe,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Signed broker stdout pipe is unavailable".into());
        }
    };
    let stdout_reader = match thread::Builder::new()
        .name("craft-signer-office-reply".into())
        .spawn(move || -> Result<Vec<u8>, String> {
            let mut bounded = reader.take((MAX_REPLY + 1) as u64);
            let mut bytes = Vec::new();
            bounded
                .read_to_end(&mut bytes)
                .map_err(|_| "Cannot read signed broker response")?;
            if bytes.is_empty() || bytes.len() > MAX_REPLY {
                return Err("Signed broker response exceeds the maximum permitted size".into());
            }
            Ok(bytes)
        }) {
        Ok(handle) => handle,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Cannot start bounded broker response reader".into());
        }
    };

    // The only input is strict document.verify JSON, not a PIN or identity.
    let write_result = match child.stdin.take() {
        Some(mut input_pipe) => input_pipe.write_all(&input),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "Signed broker stdin unavailable",
        )),
    };
    if write_result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        let _ = stdout_reader.join();
        return Err("Cannot send bounded read-only request to signed broker".into());
    }

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < VERIFY_TIMEOUT => {
                thread::sleep(Duration::from_millis(40));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                return Err("Craft Signer broker exceeded the verification deadline".into());
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                return Err("Craft Signer broker process state is unavailable".into());
            }
        }
    };
    let reply = stdout_reader
        .join()
        .map_err(|_| "Signed broker reader failed")??;
    // The signed broker checks the source hash as well, but the host never
    // reports integrity PASS without independently rehashing exact saved bytes.
    snapshot.checked_reply(&reply, status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cryptographically_random_request_ids_are_canonical_uuid_v4() {
        let first = new_request_uuid().expect("Windows secure randomness");
        let second = new_request_uuid().expect("Windows secure randomness");
        assert_ne!(first, second);
        for id in [first, second] {
            assert_eq!(id.len(), 36);
            let bytes = id.as_bytes();
            for separator in [8, 13, 18, 23] {
                assert_eq!(bytes[separator], b'-');
            }
            assert_eq!(bytes[14], b'4');
            assert!(matches!(bytes[19], b'8' | b'9' | b'a' | b'b'));
        }
    }

    #[test]
    fn unsaved_document_refused_before_module_discovery_or_execution() {
        let result = verify_office_via_installed_signer(
            Path::new("missing-not-a-real-office-document.docx"),
            OfficeKind::Docx,
            true,
        );
        assert!(result.is_err());
        assert!(result.err().is_some_and(|m| m.contains("Save")));
    }
}
