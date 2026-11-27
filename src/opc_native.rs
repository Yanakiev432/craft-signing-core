//! In-process Windows OPC signature bridge. No PowerShell, CMD or subprocess.
//! Integrity validation is not certificate trust or eIDAS QES qualification.
#![cfg(windows)]
use std::{
    ffi::OsStr,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
static NEXT_OPC_STAGE: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" {
    fn craft_opc_verify_report(source: *const u16, count: *mut i32, stage: *mut i32) -> i32;
    fn craft_opc_sign_inprocess(source: *const u16, dest: *const u16, sha1: *const u16) -> i32;
}
fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}
fn error(stage: &str, hr: i32) -> String {
    format!(
        "{stage} rejected by Windows OPC (HRESULT=0x{:08X}); trust, revocation and QES not assessed",
        hr as u32
    )
}

/// Stage at which strict OPC verification stopped; not a legal trust verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpcVerifyStage {
    PackageLoad,
    SignatureEnumeration,
    SignatureValidation,
    PartCoverage,
    NoSignature,
    StrictPass,
    Unknown,
}

/// Whole-document strict policy report. Earlier successful signatures do not
/// imply all signatures passed. HRESULT preserves the original native failure.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpcVerificationReport {
    pub stage: OpcVerifyStage,
    pub hresult: u32,
    pub verified_signatures: usize,
    pub strict_pass: bool,
    pub certificate_trust_assessed: bool,
    pub revocation_assessed: bool,
    pub qes_assessed: bool,
}

impl OpcVerificationReport {
    /// Validate the diagnostic wire contract; this is NOT a trust assessment.
    pub fn is_consistent(&self) -> bool {
        if self.certificate_trust_assessed || self.revocation_assessed || self.qes_assessed {
            return false;
        }
        if self.strict_pass {
            self.stage == OpcVerifyStage::StrictPass
                && self.hresult == 0
                && self.verified_signatures > 0
        } else {
            self.stage != OpcVerifyStage::StrictPass
                && self.hresult & 0x8000_0000 != 0
                && self.verified_signatures == 0
        }
    }
}
fn report_from_native(hr: i32, count: i32, stage: i32) -> OpcVerificationReport {
    let stage = match stage {
        0 => OpcVerifyStage::PackageLoad,
        1 => OpcVerifyStage::SignatureEnumeration,
        2 => OpcVerifyStage::SignatureValidation,
        3 => OpcVerifyStage::PartCoverage,
        4 => OpcVerifyStage::NoSignature,
        5 => OpcVerifyStage::StrictPass,
        _ => OpcVerifyStage::Unknown,
    };
    let strict_pass = hr == 0 && count > 0 && stage == OpcVerifyStage::StrictPass;
    OpcVerificationReport {
        stage,
        hresult: hr as u32,
        verified_signatures: if strict_pass { count as usize } else { 0 },
        strict_pass,
        certificate_trust_assessed: false,
        revocation_assessed: false,
        qes_assessed: false,
    }
}

/// Detailed read-only report. No trust or QES is inferred from native OPC.
pub fn inspect_opc_inprocess(path: &Path) -> Result<OpcVerificationReport, String> {
    let absolute = path
        .canonicalize()
        .map_err(|_| "source file does not exist".to_string())?;
    if !absolute.is_file() {
        return Err("source is not a regular file".into());
    }
    let source = wide(absolute.as_os_str());
    let mut count = 0i32;
    let mut stage = -1i32;
    let hr = unsafe { craft_opc_verify_report(source.as_ptr(), &mut count, &mut stage) };
    Ok(report_from_native(hr, count, stage))
}

/// Strict compatibility wrapper: only complete native verification is accepted.
pub fn verify_opc_inprocess(path: &Path) -> Result<usize, String> {
    let report = inspect_opc_inprocess(path)?;
    if !report.strict_pass {
        return Err(format!(
            "{}; stage={:?}",
            error("native OPC verification", report.hresult as i32),
            report.stage
        ));
    }
    Ok(report.verified_signatures)
}

/// Signs a new DOCX/XLSX with explicit CurrentUser/My SHA1 certificate thumbprint.
/// Hardware private key remains with its Windows provider and official PIN UI.
/// No existing output is replaced. Verification is performed before final rename.
pub fn sign_opc_inprocess(
    source: &Path,
    output: &Path,
    sha1_thumbprint: &str,
) -> Result<(), String> {
    if sha1_thumbprint.len() != 40 || !sha1_thumbprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("explicit 40-hex certificate SHA1 thumbprint required".into());
    }
    if output.exists() || source == output {
        return Err("output must be nonexistent and distinct".into());
    }
    if source.extension().and_then(|x| x.to_str()).is_none_or(|x| {
        !["docx", "xlsx"]
            .iter()
            .any(|ext| x.eq_ignore_ascii_case(ext))
    }) {
        return Err("source must be a DOCX or XLSX document".into());
    }
    let absolute = source
        .canonicalize()
        .map_err(|_| "source document missing".to_string())?;
    if !absolute.is_file() {
        return Err("source must be a regular file".into());
    }
    let abs_output = if output.is_absolute() {
        output.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(output)
    };
    // Never expose a half-normalized output as the user's signed file.
    // Native OPC signs into a unique sibling; ZIP is rewritten in-process,
    // both original and normalized signed archives are checked independently.
    let sequence = NEXT_OPC_STAGE.fetch_add(1, Ordering::Relaxed);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let stem = format!(".craft-opc-{}-{stamp}-{sequence}", std::process::id());
    let mut raw_name = abs_output.as_os_str().to_os_string();
    raw_name.push(format!("{stem}.raw"));
    let raw = PathBuf::from(raw_name);
    let mut stage_name = abs_output.as_os_str().to_os_string();
    stage_name.push(format!("{stem}.normalized"));
    let normalized = PathBuf::from(stage_name);
    if raw.exists() || normalized.exists() {
        return Err("temporary OPC output name collision".into());
    }
    let result = (|| {
        let src = wide(absolute.as_os_str());
        let dst = wide(raw.as_os_str());
        let identity = wide(OsStr::new(sha1_thumbprint));
        let hr = unsafe { craft_opc_sign_inprocess(src.as_ptr(), dst.as_ptr(), identity.as_ptr()) };
        if hr < 0 {
            return Err(error("native OPC signing", hr));
        }
        let before = verify_opc_inprocess(&raw)?;
        crate::opc_zip::normalize_container(&raw, &normalized)?;
        let after = verify_opc_inprocess(&normalized)?;
        if before != after {
            return Err("ZIP normalization changed the verified signature count".into());
        }
        // The final path must be created atomically without replacement.
        // A separate process might create it after our earlier exists() check.
        // Staging and destination are siblings on the same filesystem, so
        // hard_link refuses an existing name without changing validated bytes.
        std::fs::hard_link(&normalized, &abs_output)
            .map_err(|e| format!("atomic no-overwrite OPC publication failed: {e}"))?;
        Ok(())
    })();
    let _ = std::fs::remove_file(&raw);
    let _ = std::fs::remove_file(&normalized);
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stage_report_never_grants_partial_or_unknown_success() {
        for (hr, count, stage) in [(0, 1, 3), (0, 1, 99), (-1, 1, 5), (0, 0, 5), (1, 1, 5)] {
            let r = report_from_native(hr, count, stage);
            assert!(!r.strict_pass);
            assert_eq!(r.verified_signatures, 0);
            assert!(!r.certificate_trust_assessed && !r.revocation_assessed && !r.qes_assessed);
        }
        let r = report_from_native(0, 2, 5);
        assert!(r.strict_pass);
        assert_eq!(r.verified_signatures, 2);
    }
    #[test]
    fn no_implicit_identity_non_office_or_missing_file() {
        assert!(sign_opc_inprocess(Path::new("missing.docx"), Path::new("out.docx"), "").is_err());
        assert!(
            sign_opc_inprocess(Path::new("test.pdf"), Path::new("out.pdf"), &"a".repeat(40))
                .is_err()
        );
        assert!(verify_opc_inprocess(Path::new("missing.docx")).is_err());
    }
}
