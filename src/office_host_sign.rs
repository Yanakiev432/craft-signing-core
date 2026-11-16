//! Authenticated v2 Office signing host adapter, Windows-only.
//!
//! Fail closed: an explicitly confirmed native UI gesture is required, and
//! the installed broker plus three workers are authenticated before IPC.
//! This adapter never accepts a PIN, exports a key or reports an eIDAS QES.
//! Run on a dedicated worker thread; never block the GUI render thread.
use crate::{
    broker_protocol::{OfficeKind, OfficeSignChoice, prepare_sign},
    installed_broker::resolve_installed_broker,
    office_host::new_request_uuid,
};
use std::{
    ffi::c_void,
    io::{Read, Write},
    os::windows::{io::AsRawHandle, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject,
    },
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const MAX_REQUEST: usize = 16_384;
const MAX_RESPONSE: usize = 32_768;
const SIGN_TIMEOUT: Duration = Duration::from_secs(340);

/// A kill-on-close Windows Job ensures the authenticated broker and any
/// signing worker processes have one lifetime. A broker child is still
/// waiting for stdin when assigned: no document.sign request can run first.
struct SigningJob(HANDLE);

impl SigningJob {
    fn assign(child: &Child) -> Result<Self, String> {
        // SAFETY: CreateJobObjectW receives two optional null pointers. The
        // kernel returns either a valid owned HANDLE or null on failure.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err("Cannot create a bounded Windows signer process job".into());
        }
        let job = Self(handle);
        // SAFETY: The Win32 POD structure is fully zero-initialized before
        // setting the documented LimitFlags bit. Its pointer is used only
        // for the duration of SetInformationJobObject.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: The owned job HANDLE is valid; the descriptor matches the
        // JobObjectExtendedLimitInformation structure and byte size.
        let configured = unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            return Err("Cannot establish kill-on-close signer lifetime".into());
        }
        // SAFETY: child.as_raw_handle() belongs to the running Child and is
        // valid until Child is dropped. No request bytes were sent yet.
        let assigned = unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle()) };
        if assigned == 0 {
            return Err("Cannot isolate the signed broker in a Windows process job".into());
        }
        Ok(job)
    }

    fn terminate(&self) {
        // SAFETY: the job owns the broker and descendants (if assigned). The
        // input is a fixed non-success exit code, not an external command.
        let _ = unsafe { TerminateJobObject(self.0, 1) };
    }
}

impl Drop for SigningJob {
    fn drop(&mut self) {
        // SAFETY: this is the owned HANDLE returned by CreateJobObjectW. The
        // kernel closes the job and terminates any remaining assigned workers.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn invoke_authenticated_sign_broker(
    executable: &Path,
    request: &[u8],
    cancelled: &AtomicBool,
) -> Result<(Vec<u8>, bool), String> {
    if request.is_empty() || request.len() > MAX_REQUEST {
        return Err("Signed Office IPC request exceeds the size limit".into());
    }
    if cancelled.load(Ordering::SeqCst) {
        return Err("Signing cancelled before dispatch; no provider accessed".into());
    }
    let cwd = executable
        .parent()
        .ok_or("Authenticated broker folder is missing")?;
    let mut child = Command::new(executable)
        .current_dir(cwd)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Cannot launch the authenticated Craft Signer broker")?;

    let job = match SigningJob::assign(&child) {
        Ok(job) => job,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    if cancelled.load(Ordering::SeqCst) {
        job.terminate();
        let _ = child.wait();
        return Err("Signing cancelled before IPC dispatch; check output before retrying".into());
    }
    let Some(stdout) = child.stdout.take() else {
        job.terminate();
        let _ = child.wait();
        return Err("Signed broker reply channel is unavailable".into());
    };
    let read_reply = match thread::Builder::new()
        .name("craft-signer-v2-sign-reply".into())
        .spawn(move || -> Result<Vec<u8>, String> {
            let mut reply = Vec::new();
            stdout
                .take((MAX_RESPONSE + 1) as u64)
                .read_to_end(&mut reply)
                .map_err(|_| "Cannot read the signed broker reply")?;
            if reply.is_empty() || reply.len() > MAX_RESPONSE {
                return Err("Signed broker reply is empty or oversized".into());
            }
            Ok(reply)
        }) {
        Ok(thread) => thread,
        Err(_) => {
            job.terminate();
            let _ = child.wait();
            return Err("Cannot start the bounded signed broker reader".into());
        }
    };
    // Closing stdin is required: the broker reads exactly one JSON request to
    // EOF. No direct worker executable, certificate PIN or shell command.
    let write_ok = child
        .stdin
        .take()
        .is_some_and(|mut input| input.write_all(request).is_ok());
    if !write_ok {
        job.terminate();
        let _ = child.wait();
        let _ = read_reply.join();
        return Err("Cannot send bounded signing intent to the broker".into());
    }

    let started = Instant::now();
    let status = loop {
        if cancelled.load(Ordering::SeqCst) || started.elapsed() >= SIGN_TIMEOUT {
            job.terminate();
            let _ = child.wait();
            let _ = read_reply.join();
            return Err(if cancelled.load(Ordering::SeqCst) {
                "Signing cancelled; an output may have just completed and must be inspected before retrying"
            } else {
                "Signed broker exceeded its deadline; inspect output before retrying"
            }.into());
        }
        match child.try_wait() {
            Ok(Some(code)) => break code,
            Ok(None) => thread::sleep(Duration::from_millis(40)),
            Err(_) => {
                job.terminate();
                let _ = child.wait();
                let _ = read_reply.join();
                return Err("Signed broker process status is unavailable".into());
            }
        }
    };
    // Drop closes the Windows job handle. No worker is allowed to survive.
    let response = read_reply
        .join()
        .map_err(|_| "Signed broker reader panicked")??;
    if cancelled.load(Ordering::SeqCst) {
        return Err("Signing was cancelled at completion; inspect output before retrying".into());
    }
    Ok((response, status.success()))
}

/// Attempt an explicitly approved v2 DOCX/XLSX signing operation.
///
/// The trusted signed broker implements document.sign; it invokes the native
/// Windows certificate provider, whose PIN UI must remain outside Craft.
/// Never uses legacy or PATH-selected worker fallbacks. If the installed
/// module is v0.2.2, its old broker does not speak the explicit sign policy
/// and this call fails closed rather than fabricating success.
///
/// Source and destination paths are rechecked; the source is not overwritten.
/// Success means native OPC integrity only, NOT QES, certificate trust or
/// a verified identity in an external qualified trust list.
pub fn sign_office_via_installed_signer(
    source: &Path,
    destination: &Path,
    kind: OfficeKind,
    unsaved_edits: bool,
    choice: OfficeSignChoice,
    certificate_thumbprint: &str,
    cancelled: &AtomicBool,
) -> Result<PathBuf, String> {
    if cancelled.load(Ordering::SeqCst) {
        return Err("Signing cancelled before source access".into());
    }
    let id = new_request_uuid()?;
    let intent = prepare_sign(
        source,
        destination,
        kind,
        unsaved_edits,
        choice,
        certificate_thumbprint,
        &id,
    )?;
    let request = intent.json_request()?;
    if cancelled.load(Ordering::SeqCst) {
        return Err("Signing cancelled before module discovery".into());
    }
    let trusted = resolve_installed_broker()?;
    intent.unchanged()?;
    if cancelled.load(Ordering::SeqCst) {
        return Err("Signing cancelled before broker execution".into());
    }
    let (reply, process_success) =
        invoke_authenticated_sign_broker(trusted.executable(), &request, cancelled)?;
    if cancelled.load(Ordering::SeqCst) {
        return Err("Signing cancelled at reply; inspect destination before retrying".into());
    }
    let signed = intent.checked_sign_reply(&reply, process_success)?;
    if cancelled.load(Ordering::SeqCst) {
        return Err(
            "Signing cancelled after verification; inspect destination before retrying".into(),
        );
    }
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_requires_explicit_consent_before_discovering_any_module() {
        let cancelled = AtomicBool::new(false);
        let fail = sign_office_via_installed_signer(
            Path::new("not-saved.docx"),
            Path::new("new-signed.docx"),
            OfficeKind::Docx,
            false,
            OfficeSignChoice::Unconfirmed,
            "",
            &cancelled,
        );
        assert!(fail.is_err());
        assert!(fail.unwrap_err().contains("confirmation"));
    }

    #[test]
    fn unsupported_restriction_fails_closed_without_provider_prompt() {
        let cancelled = AtomicBool::new(false);
        let fail = sign_office_via_installed_signer(
            Path::new("not-saved.xlsx"),
            Path::new("new-signed.xlsx"),
            OfficeKind::Xlsx,
            false,
            OfficeSignChoice::RestrictAdditional,
            "",
            &cancelled,
        );
        assert!(fail.is_err());
        assert!(fail.unwrap_err().contains("unsupported"));
    }

    #[test]
    fn pre_cancelled_request_never_attempts_broker_discovery() {
        let cancelled = AtomicBool::new(true);
        let result = sign_office_via_installed_signer(
            Path::new("not-saved.docx"),
            Path::new("new-signed.docx"),
            OfficeKind::Docx,
            false,
            OfficeSignChoice::AllowAdditional,
            "0123456789ABCDEF0123456789ABCDEF01234567",
            &cancelled,
        );
        assert!(result.unwrap_err().contains("cancelled"));
    }

    #[test]
    fn broker_cannot_start_with_empty_or_oversized_wire_request() {
        let cancelled = AtomicBool::new(false);
        for request in [Vec::new(), vec![0_u8; MAX_REQUEST + 1]] {
            let result = invoke_authenticated_sign_broker(
                Path::new("absent-broker.exe"),
                &request,
                &cancelled,
            );
            assert!(result.unwrap_err().contains("size limit"));
        }
    }
}
