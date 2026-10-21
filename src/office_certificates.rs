//! Read-only Windows certificate inventory for PdfCraft-style Office signing selection.
//! The selected SHA-1 thumbprint is subsequently passed to the existing OPC/XMLDSig
//! signer; the original private key always remains with Windows CSP/CNG.
use serde::Deserialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const SOURCE: &str = include_str!("../tools/opc_certificate_windows.ps1");

#[derive(Clone, Debug, Deserialize)]
pub struct OfficeCertificate {
    pub thumbprint: String,
    pub subject: String,
    pub issuer: String,
    pub expires: String,
    pub has_private_key: bool,
    pub valid_now: bool,
}

struct Staged {
    dir: PathBuf,
    script: PathBuf,
}
impl Drop for Staged {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.script);
        let _ = fs::remove_dir(&self.dir);
    }
}
impl Staged {
    fn create() -> Result<Self, String> {
        for attempt in 0..16 {
            let tick = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "craft-certs-{}-{tick}-{attempt}",
                std::process::id()
            ));
            if fs::create_dir(&dir).is_err() {
                continue;
            }
            let script = dir.join("opc_certificate_windows.ps1");
            let created = (|| -> std::io::Result<()> {
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&script)?;
                file.write_all(SOURCE.as_bytes())?;
                file.sync_all()
            })();
            if let Err(e) = created {
                let _ = fs::remove_dir_all(&dir);
                return Err(format!("Cannot stage read-only certificate inventory: {e}"));
            }
            return Ok(Self { dir, script });
        }
        Err("No private directory available for certificate inventory".into())
    }
}

/// Enumerates CurrentUser/My metadata only. Never opens/acquires private keys.
/// The user must explicitly select an individual usable certificate in the app.
pub fn list_office_certificates() -> Result<Vec<OfficeCertificate>, String> {
    let stage = Staged::create()?;
    let system_root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let exe = PathBuf::from(system_root)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    let mut cmd = Command::new(exe);
    cmd.arg("-NoLogo")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-File")
        .arg(&stage.script);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // no console, no key acquisition
    }
    let result = cmd
        .output()
        .map_err(|e| format!("Certificate inventory could not start: {e}"))?;
    if !result.status.success() {
        return Err(format!(
            "Certificate inventory failed: {}",
            String::from_utf8_lossy(&result.stderr)
                .chars()
                .take(500)
                .collect::<String>()
        ));
    }
    let text = std::str::from_utf8(&result.stdout)
        .map_err(|_| "Certificate inventory is not UTF-8".to_string())?;
    let mut ids: Vec<OfficeCertificate> = serde_json::from_str(text.trim())
        .map_err(|e| format!("Invalid certificate listing: {e}"))?;
    ids.sort_by(|a, b| {
        a.subject
            .cmp(&b.subject)
            .then(a.thumbprint.cmp(&b.thumbprint))
    });
    let mut last = std::collections::HashSet::new();
    for cert in &ids {
        if cert.thumbprint.len() != 40
            || !cert.thumbprint.bytes().all(|c| c.is_ascii_hexdigit())
            || !last.insert(cert.thumbprint.to_ascii_lowercase())
        {
            return Err("Invalid or duplicated Windows certificate identity".into());
        }
    }
    Ok(ids)
}
