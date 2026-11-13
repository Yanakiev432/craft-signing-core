//! Host-neutral, read-only Craft Signer broker protocol v1 for native Office hosts.
//!
//! This is a **wire contract**, NOT an extension installer or a trusted broker
//! discovery implementation. Callers must authenticate the independently signed
//! module and its executable bytes BEFORE launching anything.
//! The Office broker can confirm OPC integrity, NOT eIDAS qualified status.
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, Metadata, OpenOptions},
    io::Read,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::SystemTime,
};

const MAX_OFFICE_BYTES: u64 = 150 * 1024 * 1024;
const MAX_REQUEST_BYTES: usize = 16_384;
const MAX_RESPONSE_BYTES: usize = 32_768;
// Do not permit concurrent writers during hashing, as required by the broker.
const FILE_SHARE_READ: u32 = 0x0000_0001;
const REPARSE_POINT: u32 = 0x400;
const PROTOCOL: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfficeKind {
    Docx,
    Xlsx,
}

impl OfficeKind {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Docx => "docx",
            Self::Xlsx => "xlsx",
        }
    }
}

/// A snapshot of the *saved* on-disk Office file. Never describe unsaved
/// in-memory editor state as already cryptographically checked.
#[derive(Clone, Debug)]
pub struct SavedOfficeSnapshot {
    source: PathBuf,
    kind: OfficeKind,
    request_id: String,
    sha256: String,
    size: u64,
    modified: SystemTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OfficeIntegrity {
    /// Only package signature integrity, NOT certificate trust or eIDAS/QES.
    IntegrityPass,
    /// The trusted broker ran, but its Office worker refused integrity PASS.
    IntegrityRejected,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BrokerReply {
    protocol_major: u32,
    request_id: String,
    status: String,
    code: String,
    message: String,
    document_kind: Option<String>,
    worker_exit_code: Option<i32>,
    qualified_eidas_status_assessed: Option<bool>,
    pdf_evidence: Option<Value>,
    pdf_verification_configured: Option<bool>,
}

fn uuid_d(id: &str) -> bool {
    let bytes = id.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, &b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

fn local_dos_path(path: &Path) -> Result<PathBuf, String> {
    let source = path
        .to_str()
        .ok_or("Non-Unicode Office path is unsupported")?;
    // std::fs::canonicalize returns an extended path on Windows; the .NET
    // broker refuses that prefix. Strip ONLY a normal extended DOS drive path.
    let dos = source.strip_prefix(r"\\?\").unwrap_or(source);
    let bytes = dos.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return Err("A local, absolute DOS drive path is required".into());
    }
    let normalized = PathBuf::from(dos);
    if !normalized.is_absolute() {
        return Err("A local, absolute DOS drive path is required".into());
    }
    Ok(normalized)
}

fn refuse_links(path: &Path) -> Result<(), String> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        let metadata =
            fs::symlink_metadata(ancestor).map_err(|_| "Cannot inspect Office document path")?;
        if metadata.file_attributes() & REPARSE_POINT != 0 {
            return Err("Linked documents and redirected folders are refused".into());
        }
    }
    Ok(())
}

fn checked_file(path: &Path) -> Result<(Metadata, String), String> {
    refuse_links(path)?;
    let before = fs::metadata(path).map_err(|_| "Cannot stat saved Office file")?;
    if !before.is_file() || !(1..=MAX_OFFICE_BYTES).contains(&before.len()) {
        return Err("Office file must be a saved regular file of at most 150 MiB".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|_| "Cannot lock saved Office document against writers")?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    let mut total_bytes = 0_u64;
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| "Cannot hash Office document")?;
        if n == 0 {
            break;
        }
        total_bytes = total_bytes
            .checked_add(n as u64)
            .ok_or("Office document size overflow")?;
        if total_bytes > MAX_OFFICE_BYTES {
            return Err("Office document grew past the 150 MiB size limit".into());
        }
        hash.update(&buffer[..n]);
    }
    let after = fs::metadata(path).map_err(|_| "Office document disappeared during hashing")?;
    if before.len() != after.len()
        || before.len() != total_bytes
        || before.modified().ok() != after.modified().ok()
    {
        return Err("Saved Office document changed during hashing".into());
    }
    Ok((after, format!("{:x}", hash.finalize())))
}

/// Prepare a read-only document.verify request for a *previously authenticated*
/// Craft Signer broker. Never start a process based on a manifest field here.
pub fn prepare_verify(
    source: &Path,
    kind: OfficeKind,
    dirty: bool,
    request_id: &str,
) -> Result<SavedOfficeSnapshot, String> {
    if dirty {
        return Err("Save Office changes before verifying".into());
    }
    if !uuid_d(request_id) {
        return Err("Expected a canonical UUID request ID".into());
    }
    if !source.is_absolute() {
        return Err("Save the Office document to an absolute local path".into());
    }
    refuse_links(source)?;
    let resolved = source
        .canonicalize()
        .map_err(|_| "Saved Office document is unavailable")?;
    let local = local_dos_path(&resolved)?;
    if local.to_string_lossy().encode_utf16().count() > 1_800 {
        return Err("Office file path exceeds the .NET broker limit".into());
    }
    if !local
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case(kind.extension()))
    {
        return Err("Office file type does not match the requested signer adapter".into());
    }
    let (meta, hash) = checked_file(&local)?;
    Ok(SavedOfficeSnapshot {
        source: local,
        kind,
        request_id: request_id.to_owned(),
        sha256: hash,
        size: meta.len(),
        modified: meta
            .modified()
            .map_err(|_| "Office timestamp is unavailable")?,
    })
}

impl SavedOfficeSnapshot {
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn verified_source(&self) -> &Path {
        &self.source
    }

    /// Re-check exact saved bytes, even if a caller has reused the filename.
    pub fn unchanged(&self) -> Result<(), String> {
        let (metadata, hash) = checked_file(&self.source)?;
        if metadata.len() != self.size
            || metadata.modified().ok() != Some(self.modified)
            || hash != self.sha256
        {
            return Err("Office file changed since verification request".into());
        }
        Ok(())
    }

    /// Strictly the broker's v1 document.verify shape. No userApproved,
    /// certificate thumbprint, outputPath, signing action or PIN.
    pub fn json_request(&self) -> Result<Vec<u8>, String> {
        let payload = serde_json::to_vec(&json!({
            "protocolMajor":PROTOCOL,
            "requestId":self.request_id,
            "action":"document.verify",
            "document":{
                "kind":self.kind.extension(),
                "sourcePath":self.source.to_str().ok_or("Non-Unicode Office path is unsupported")?,
                "sha256AtDispatch":self.sha256,
                "saved":true,
                "dirty":false
            }
        }))
        .map_err(|_| "Cannot encode broker IPC request")?;
        if payload.len() > MAX_REQUEST_BYTES {
            return Err("Broker request exceeded the IPC size limit".into());
        }
        Ok(payload)
    }

    /// Parse one response *after* authenticating and running the exact signed
    /// broker. Always re-hash the saved Office source before displaying a PASS.
    /// The broker process's exit status is an independent consistency check.
    pub fn checked_reply(
        &self,
        output: &[u8],
        exited_successfully: bool,
    ) -> Result<OfficeIntegrity, String> {
        if output.is_empty() || output.len() > MAX_RESPONSE_BYTES {
            return Err("Broker response size is invalid".into());
        }
        let reply: BrokerReply = serde_json::from_slice(output)
            .map_err(|_| "Invalid or ambiguous broker JSON response")?;
        if reply.protocol_major != PROTOCOL
            || reply.request_id != self.request_id
            || reply.document_kind.as_deref() != Some(self.kind.extension())
            || reply.qualified_eidas_status_assessed.unwrap_or(false)
            || reply.pdf_evidence.is_some()
            || reply.pdf_verification_configured.is_some()
            || reply.message.len() > 1024
            || reply.code.len() > 64
            || reply.code.is_empty()
            || !reply
                .code
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err("Broker response contradicts Office verification request".into());
        }
        let outcome =
            match (
                reply.status.as_str(),
                reply.code.as_str(),
                exited_successfully,
                reply.worker_exit_code,
            ) {
                ("ok", "INTEGRITY_PASS", true, Some(0)) => OfficeIntegrity::IntegrityPass,
                ("rejected", "INTEGRITY_REJECTED", false, Some(n)) if n != 0 => {
                    OfficeIntegrity::IntegrityRejected
                }
                _ => return Err(
                    "Broker response status, exit code or integrity classification is inconsistent"
                        .into(),
                ),
            };
        self.unchanged()?;
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    const ID: &str = "11111111-1111-4111-8111-111111111111";
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    fn fixture(kind: OfficeKind) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "craft-signer-broker-protocol-{}-{}.{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed),
            kind.extension()
        ));
        fs::write(
            &path,
            b"PK\x03\x04synthetic-only-not-a-valid-signed-office-package",
        )
        .expect("create disposable unsigned fixture");
        path
    }

    fn response(code: &str, status: &str, exit_code: i32, qes: bool) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "protocolMajor":1,
            "requestId":ID,
            "status":status,
            "code":code,
            "message":"synthetic QA response",
            "documentKind":"docx",
            "workerExitCode":exit_code,
            "qualifiedEidasStatusAssessed":qes
        }))
        .expect("serialize fixture reply")
    }

    #[test]
    fn verify_request_is_read_only_and_digest_bound() {
        let file = fixture(OfficeKind::Docx);
        let request = prepare_verify(&file, OfficeKind::Docx, false, ID).expect("saved source");
        let json: Value = serde_json::from_slice(&request.json_request().expect("serialize"))
            .expect("request JSON");
        assert_eq!(json["action"], "document.verify");
        assert_eq!(json["document"]["kind"], "docx");
        assert_eq!(json["document"]["dirty"], false);
        assert!(json["document"].get("certificateThumbprint").is_none());
        assert!(json["document"].get("userApproved").is_none());
        assert_eq!(
            json["document"]["sha256AtDispatch"].as_str(),
            Some(request.sha256())
        );
        assert!(request.unchanged().is_ok());
        assert_eq!(
            request.checked_reply(&response("INTEGRITY_PASS", "ok", 0, false), true),
            Ok(OfficeIntegrity::IntegrityPass)
        );
        fs::write(&file, b"PK\x03\x04modified bytes").expect("mutate disposable fixture");
        assert!(request.unchanged().is_err());
        assert!(
            request
                .checked_reply(&response("INTEGRITY_PASS", "ok", 0, false), true)
                .is_err()
        );
        let _ = fs::remove_file(file);
    }

    #[test]
    fn xlsx_response_is_format_bound_and_same_size_edits_are_detected() {
        let file = fixture(OfficeKind::Xlsx);
        let snapshot = prepare_verify(&file, OfficeKind::Xlsx, false, ID).expect("saved XLSX");
        let request: Value =
            serde_json::from_slice(&snapshot.json_request().expect("XLSX request"))
                .expect("XLSX JSON");
        assert_eq!(request["document"]["kind"], "xlsx");
        let mut reply: Value = serde_json::from_slice(&response("INTEGRITY_PASS", "ok", 0, false))
            .expect("decode broker response");
        assert!(
            snapshot
                .checked_reply(
                    &serde_json::to_vec(&reply).expect("wrong DOCX response"),
                    true
                )
                .is_err()
        );
        reply["documentKind"] = json!("xlsx");
        assert_eq!(
            snapshot.checked_reply(
                &serde_json::to_vec(&reply).expect("correct XLSX response"),
                true
            ),
            Ok(OfficeIntegrity::IntegrityPass)
        );
        let mut bytes = fs::read(&file).expect("read disposable fixture");
        let last = bytes.last_mut().expect("nonempty fixture");
        *last ^= 1;
        fs::write(&file, &bytes).expect("same-size mutation");
        assert!(
            snapshot.unchanged().is_err(),
            "must detect same-length edits"
        );
        assert!(
            snapshot
                .checked_reply(
                    &serde_json::to_vec(&reply).expect("stale XLSX response"),
                    true
                )
                .is_err()
        );
        let _ = fs::remove_file(file);
    }
    #[test]
    fn dirty_wrong_format_and_invalid_uuid_are_refused() {
        let file = fixture(OfficeKind::Docx);
        assert!(prepare_verify(&file, OfficeKind::Docx, true, ID).is_err());
        assert!(prepare_verify(&file, OfficeKind::Xlsx, false, ID).is_err());
        assert!(prepare_verify(&file, OfficeKind::Docx, false, "not-a-uuid").is_err());
        assert!(prepare_verify(Path::new("relative.docx"), OfficeKind::Docx, false, ID).is_err());
        assert!(local_dos_path(Path::new(r"\\server\share\file.docx")).is_err());
        assert!(local_dos_path(Path::new(r"\\?\UNC\server\share\file.docx")).is_err());
        let _ = fs::remove_file(file);
    }

    #[test]
    fn reject_fake_office_qes_and_broker_mismatch() {
        let file = fixture(OfficeKind::Docx);
        let request = prepare_verify(&file, OfficeKind::Docx, false, ID).expect("saved source");
        assert!(
            request
                .checked_reply(&response("INTEGRITY_PASS", "ok", 0, true), true)
                .is_err()
        );
        assert!(
            request
                .checked_reply(&response("INTEGRITY_PASS", "ok", 0, false), false)
                .is_err()
        );
        assert!(
            request
                .checked_reply(&response("PDF_QES_PASS", "ok", 0, false), true)
                .is_err()
        );
        assert!(
            request
                .checked_reply(&response("INTEGRITY_PASS", "rejected", 1, false), false)
                .is_err()
        );
        assert_eq!(
            request.checked_reply(&response("INTEGRITY_REJECTED", "rejected", 1, false), false),
            Ok(OfficeIntegrity::IntegrityRejected)
        );
        let mut wrong: Value = serde_json::from_slice(&response("INTEGRITY_PASS", "ok", 0, false))
            .expect("decode fixture");
        wrong["requestId"] = json!("00000000-0000-4000-8000-000000000000");
        assert!(
            request
                .checked_reply(&serde_json::to_vec(&wrong).expect("encode"), true)
                .is_err()
        );
        let duplicate =
            format!("{{\"protocolMajor\":1,\"protocolMajor\":1,\"requestId\":\"{ID}\"}}");
        assert!(request.checked_reply(duplicate.as_bytes(), true).is_err());
        let _ = fs::remove_file(file);
    }

    /// No real module may be installed or approved for this opt-in IPC QA.
    /// This tests .NET BrokerLogic.Parse with Rust-produced JSON and checks
    /// that publisher approval is a *hard boundary* before execution.
    #[test]
    #[ignore = "requires the exact locally Authenticode-signed 0.2.2 QA broker; no live approval"]
    fn rust_readonly_json_reaches_signed_dotnet_broker_then_fails_closed() {
        use std::{
            io::Write,
            process::{Command, Stdio},
            thread,
            time::{Duration, Instant},
        };
        let executable = PathBuf::from(
            std::env::var_os("CRAFT_SIGNER_DOTNET_V022_BROKER_EXE")
                .expect("set signed local 0.2.2 CraftSignerBroker.exe path"),
        );
        assert!(executable.is_absolute());
        let mut binary = fs::File::open(&executable).expect("read signed fixture broker");
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 65_536];
        loop {
            let n = binary.read(&mut buffer).expect("hash signed QA broker");
            if n == 0 {
                break;
            }
            digest.update(&buffer[..n]);
        }
        let sha = format!("{:X}", digest.finalize());
        assert_eq!(
            sha, "65781B0E52E3529FBE7766C9FE103CC1724A07CA1EED8379BC1913AA1EEE9FBD",
            "do not execute unapproved or a different broker executable"
        );
        drop(binary);

        let user_local = std::env::var_os("LOCALAPPDATA").expect("Windows LOCALAPPDATA");
        let root = PathBuf::from(user_local).join("Craft").join("Extensions");
        let approval = root.join("_trust").join("org.craftopensource.signer.json");
        let live_registration = root.join("org.craftopensource.signer").join("current.json");
        assert!(
            !approval.exists(),
            "do not run if the owner approved a publisher"
        );
        assert!(
            !live_registration.exists(),
            "do not run with an installed live module"
        );

        fn invoke(executable: &Path, bytes: &[u8]) -> (bool, Value) {
            let mut child = Command::new(executable)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("run the exact local signed QA broker");
            {
                let mut input = child.stdin.take().expect("signed broker stdin");
                input.write_all(bytes).expect("write read-only broker IPC");
            }
            let start = Instant::now();
            loop {
                match child.try_wait().expect("check signed broker exit") {
                    Some(_) => break,
                    None if start.elapsed() > Duration::from_secs(15) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!("signed broker exceeded read-only QA timeout");
                    }
                    None => thread::sleep(Duration::from_millis(25)),
                }
            }
            let result = child.wait_with_output().expect("read signed broker stdout");
            assert!(
                result.stdout.len() <= MAX_RESPONSE_BYTES,
                "bounded broker reply"
            );
            (
                result.status.success(),
                serde_json::from_slice(&result.stdout).expect("broker JSON reply"),
            )
        }

        for kind in [OfficeKind::Docx, OfficeKind::Xlsx] {
            let file = fixture(kind);
            let request = prepare_verify(&file, kind, false, ID).expect("saved synthetic Office");
            let bytes = request.json_request().expect("Rust broker protocol bytes");
            let (success, response) = invoke(&executable, &bytes);
            assert!(!success, "broker must refuse unapproved user publisher");
            assert_eq!(response["protocolMajor"], 1);
            assert_eq!(
                response["requestId"], ID,
                "Rust request was parsed by C# broker"
            );
            assert_eq!(response["status"], "error");
            assert_eq!(response["code"], "PUBLISHER_NOT_APPROVED");
            request
                .unchanged()
                .expect("synthetic Office source unmodified");
            let _ = fs::remove_file(file);
        }

        let broken = format!(
            "{{\"protocolMajor\":1,\"requestId\":\"{ID}\",\"action\":\"document.verify\",\
             \"document\":null,\"unexpectedField\":true}}"
        );
        let (success, response) = invoke(&executable, broken.as_bytes());
        assert!(!success);
        assert_eq!(response["code"], "UNKNOWN_FIELD");
        assert!(!approval.exists(), "no user publisher approval created");
        assert!(!live_registration.exists(), "no installed module created");
    }
}
