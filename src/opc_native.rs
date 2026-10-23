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
    fn craft_opc_verify_inprocess(source: *const u16, count: *mut i32) -> i32;
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

/// Validates signed XML and covered OPC references without starting a shell.
/// Package-wide OPC part coverage is enforced by the native implementation.
/// A successful result does not establish certificate trust or eIDAS QES.
pub fn verify_opc_inprocess(path: &Path) -> Result<usize, String> {
    let absolute = path
        .canonicalize()
        .map_err(|_| "source file does not exist".to_string())?;
    if !absolute.is_file() {
        return Err("source is not a regular file".into());
    }
    let source = wide(absolute.as_os_str());
    let mut count = 0i32;
    let hr = unsafe { craft_opc_verify_inprocess(source.as_ptr(), &mut count) };
    if hr < 0 || count <= 0 {
        return Err(error("native OPC verification", hr));
    }
    Ok(count as usize)
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
        if abs_output.exists() {
            return Err("signed destination appeared while signing".into());
        }
        std::fs::rename(&normalized, &abs_output).map_err(|e| e.to_string())?;
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
    fn no_implicit_identity_non_office_or_missing_file() {
        assert!(sign_opc_inprocess(Path::new("missing.docx"), Path::new("out.docx"), "").is_err());
        assert!(
            sign_opc_inprocess(Path::new("test.pdf"), Path::new("out.pdf"), &"a".repeat(40))
                .is_err()
        );
        assert!(verify_opc_inprocess(Path::new("missing.docx")).is_err());
    }
}
