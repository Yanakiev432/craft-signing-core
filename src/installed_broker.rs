//! Fail-closed Craft Signer v2 owner-approved, versioned module discovery.
//!
//! No runtime path override: production obtains Windows Known Folder LocalAppData,
//! not an untrusted environment variable. The test-only resolver accepts an
//! explicit disposable root and never creates a live user publisher policy.
//! Verified worker handles stay locked against writes/deletes while the host
//! decides whether to spawn the exact authenticated broker.
use crate::signed_module::{VerifiedCatalog, verify_catalog};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MODULE_ID: &str = "org.craftopensource.signer";
const POLICY_SCHEMA: &str = "craft.signer/local-developer-approval/1";
const FILE_SHARE_READ: u32 = 0x0000_0001;
const REPARSE_POINT: u32 = 0x0000_0400;
const MAX_WORKER: u64 = 200 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnerApproval {
    schema: String,
    module_id: String,
    key_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CurrentRegistration {
    module_id: String,
    module_version: String,
    release_directory: String,
    publisher_public_key_sha256: String,
    protocol_major: u32,
}

/// Holds the verified worker handles open without allowing replacement.
/// Keep this value alive until after the authenticated broker starts.
pub struct VerifiedInstalledBroker {
    executable: PathBuf,
    catalog: VerifiedCatalog,
    _worker_locks: Vec<File>,
}

impl VerifiedInstalledBroker {
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn verified_catalog(&self) -> &VerifiedCatalog {
        &self.catalog
    }
}

/// Installed-module lookup uses the OS-supplied user LocalAppData known folder.
/// No user override, PATH, signed manifest path field, or developer test env.
pub fn resolve_installed_broker() -> Result<VerifiedInstalledBroker, String> {
    let folders = directories::BaseDirs::new().ok_or("Windows user data folder unavailable")?;
    let local = folders.data_local_dir();
    if local.to_string_lossy().starts_with(r"\\") {
        return Err("Network/device module installation root is not supported".into());
    }
    resolve_under(&local.join("Craft").join("Extensions"))
}

fn reject_reparse(path: &Path) -> Result<(), String> {
    for entry in path.ancestors() {
        if entry.as_os_str().is_empty() {
            break;
        }
        let attributes =
            fs::symlink_metadata(entry).map_err(|_| "Cannot inspect signer module path")?;
        if attributes.file_attributes() & REPARSE_POINT != 0 {
            return Err("Signer module uses a redirected or linked path".into());
        }
    }
    Ok(())
}

fn only_entries(dir: &Path, allowed: &[&str]) -> Result<(), String> {
    reject_reparse(dir)?;
    for entry in fs::read_dir(dir).map_err(|_| "Cannot inspect signer release directory")? {
        let found = entry.map_err(|_| "Cannot inspect signer release entry")?;
        let name = found.file_name();
        let Some(name) = name.to_str() else {
            return Err("Signer release has a non-Unicode entry".into());
        };
        if !allowed.contains(&name) {
            return Err("Unrecognized entry inside signer module release".into());
        }
        reject_reparse(&found.path())?;
    }
    Ok(())
}

fn locked_digest(path: &Path, limit: u64) -> Result<(File, String), String> {
    reject_reparse(path)?;
    let mut locked = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|_| "Cannot read-lock signed module payload")?;
    let size = locked
        .metadata()
        .map_err(|_| "Cannot inspect signed module file size")?
        .len();
    if !(1..=limit).contains(&size)
        || !locked
            .metadata()
            .map_err(|_| "Cannot inspect module file")?
            .is_file()
    {
        return Err("Signed module payload is not a bounded regular file".into());
    }
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65_536];
    let mut total = 0u64;
    loop {
        let n = locked
            .read(&mut buf)
            .map_err(|_| "Cannot hash signed module payload")?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or("Signer payload size overflow")?;
        if total > limit {
            return Err("Signed module payload grew beyond the accepted limit".into());
        }
        hash.update(&buf[..n]);
    }
    if total != size {
        return Err("Signed module payload changed during verification".into());
    }
    Ok((locked, format!("{:X}", hash.finalize())))
}

fn bounded_public_file(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let (mut locked, _) = locked_digest(path, limit)?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(
            locked
                .metadata()
                .map_err(|_| "Cannot stat module catalog")?
                .len(),
        )
        .map_err(|_| "Signed module catalog too large")?,
    );
    locked
        .seek(SeekFrom::Start(0))
        .map_err(|_| "Cannot reset signed catalog reader")?;
    locked
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read signed module catalog")?;
    Ok(bytes)
}

fn parse_json<T: for<'a> Deserialize<'a>>(path: &Path, max: u64) -> Result<T, String> {
    serde_json::from_slice(&bounded_public_file(path, max)?)
        .map_err(|_| "Malformed signer policy or current module registration".into())
}

/// Host-side floor independent of the installer's downgrade guard.
///
/// v0.2.1-qa has a known incorrect EU DSS unsigned-PDF classification and is
/// not a supported module for native Office/PDF host verification.
/// This is a *minimum compatible version*, not an anti-rollback mechanism for
/// every future release; publisher policy and ModuleStore remain separate gates.
fn supported_host_module_version(version: &str) -> bool {
    let digits = version.split_once('-').map_or(version, |(head, _)| head);
    let mut parts = digits.split('.');
    let (Some(major), Some(minor), Some(patch), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let part = |s: &str| -> Option<u32> {
        if s.is_empty()
            || (s.len() > 1 && s.starts_with('0'))
            || !s.bytes().all(|c| c.is_ascii_digit())
        {
            return None;
        }
        s.parse().ok()
    };
    match (part(major), part(minor), part(patch)) {
        (Some(major), Some(minor), Some(patch)) => (major, minor, patch) >= (0, 2, 2),
        _ => false,
    }
}
fn verified_release_leaf(name: &str, catalog: &VerifiedCatalog) -> bool {
    let expected = format!(
        "{}-{}",
        catalog.module_version,
        &catalog.manifest_sha256[..16],
    );
    name == expected && name.len() <= 70
}

/// The same path used by production, with an explicit root solely so isolated
/// tests can prove unsigned files, changed registrations and tampered workers
/// never result in an executable being returned.
fn resolve_under(root: &Path) -> Result<VerifiedInstalledBroker, String> {
    reject_reparse(root)?;
    let policy_path = root.join("_trust").join("org.craftopensource.signer.json");
    let owner: OwnerApproval = parse_json(&policy_path, 8192)
        .map_err(|_| "Owner-approved Craft Signer publisher policy is missing or invalid")?;
    if owner.schema != POLICY_SCHEMA
        || owner.module_id != MODULE_ID
        || owner.key_sha256.len() != 64
        || !owner.key_sha256.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("Craft Signer publisher approval does not match the module".into());
    }

    let module_root = root.join(MODULE_ID);
    only_entries(&module_root, &["current.json", "releases"])?;
    let active: CurrentRegistration = parse_json(&module_root.join("current.json"), 8192)?;
    if active.module_id != MODULE_ID
        || active.protocol_major != 1
        || !active
            .publisher_public_key_sha256
            .eq_ignore_ascii_case(&owner.key_sha256)
    {
        return Err("Active Craft Signer registration is not owner-approved".into());
    }
    let leaf = &active.release_directory;
    if leaf.is_empty()
        || leaf.len() > 70
        || !leaf
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        || leaf.starts_with('.')
    {
        return Err("Untrusted Craft Signer release directory".into());
    }

    let release = module_root.join("releases").join(leaf);
    only_entries(
        &release,
        &[
            "manifest.json",
            "manifest.p7s",
            "publisher.cer",
            "craft-signer-broker.exe",
            "wordcraft-cli.exe",
            "gridcraft-cli.exe",
        ],
    )?;
    let manifest = bounded_public_file(&release.join("manifest.json"), 16_384)?;
    let cms = bounded_public_file(&release.join("manifest.p7s"), 65_536)?;
    let public_cert = bounded_public_file(&release.join("publisher.cer"), 16_384)?;
    let catalog = verify_catalog(&manifest, &cms, &public_cert, &owner.key_sha256)?;
    if !supported_host_module_version(&catalog.module_version) {
        return Err("Craft Signer module version is below this host's supported minimum".into());
    }
    if catalog.module_version != active.module_version || !verified_release_leaf(leaf, &catalog) {
        return Err("Signed catalog, active module version and release path disagree".into());
    }

    let expected = [
        ("craft-signer-broker.exe", &catalog.broker_sha256),
        ("wordcraft-cli.exe", &catalog.word_worker_sha256),
        ("gridcraft-cli.exe", &catalog.grid_worker_sha256),
    ];
    let mut locks = Vec::with_capacity(expected.len());
    for (name, digest) in expected {
        let (lock, actual) = locked_digest(&release.join(name), MAX_WORKER)?;
        if !actual.eq_ignore_ascii_case(digest) {
            return Err("Signed module executable has been tampered with".into());
        }
        locks.push(lock);
    }
    Ok(VerifiedInstalledBroker {
        executable: release.join("craft-signer-broker.exe"),
        catalog,
        _worker_locks: locks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn host_rejects_v021_unsigned_pdf_parser_and_malformed_version() {
        for version in [
            "0.2.1-qa",
            "0.2.0",
            "0.1.999",
            "0.02.2",
            "0.2",
            "not-semver",
            "0.2.2.0",
            "0.2.-1",
        ] {
            assert!(
                !supported_host_module_version(version),
                "{version} must fail"
            );
        }
        for version in ["0.2.2-qa", "0.2.2", "0.2.3-qa", "0.3.0", "1.0.0"] {
            assert!(
                supported_host_module_version(version),
                "{version} must pass"
            );
        }
    }
    #[test]
    fn invalid_release_leaf_is_rejected() {
        let cat = VerifiedCatalog {
            module_version: "0.2.2-qa".into(),
            manifest_sha256: "A".repeat(64),
            publisher_key_sha256: "B".repeat(64),
            broker_sha256: "C".repeat(64),
            word_worker_sha256: "D".repeat(64),
            grid_worker_sha256: "E".repeat(64),
        };
        assert!(verified_release_leaf("0.2.2-qa-AAAAAAAAAAAAAAAA", &cat));
        for bad in [
            "../escape",
            "0.2.1-qa-AAAAAAAAAAAAAAAA",
            "0.2.2-qa-0000000000000000",
        ] {
            assert!(!verified_release_leaf(bad, &cat));
        }
    }

    /// Real signed .NET fixture copied into a private temporary module root.
    /// Tests use a synthetic policy ONLY inside that temporary directory.
    #[test]
    #[ignore = "requires local signed 0.2.2 artifacts and independent public key pin"]
    fn installed_v022_discovery_checks_all_three_real_signed_worker_hashes() {
        let source = PathBuf::from(
            std::env::var_os("CRAFT_SIGNER_DOTNET_V022_ROOT")
                .expect("signed v0.2.2 source repository path"),
        );
        let pin = std::env::var("CRAFT_SIGNER_PUBLISHER_SPKI_SHA256")
            .expect("independently verified publisher SPKI SHA-256");
        let temp = tempfile::tempdir().expect("disposable signer release root");
        let extensions = temp.path().join("Craft").join("Extensions");
        let module = extensions.join(MODULE_ID);
        let policies = extensions.join("_trust");
        fs::create_dir_all(&policies).expect("temporary approval folder");
        let manifest = fs::read(
            source
                .join("ModuleV2")
                .join("Package")
                .join("manifest.json"),
        )
        .expect("actual signed .NET manifest");
        let hash = format!("{:X}", Sha256::digest(&manifest));
        let leaf = format!("0.2.2-qa-{}", &hash[..16]);
        let release = module.join("releases").join(&leaf);
        fs::create_dir_all(&release).expect("temporary signed release folder");
        let components = [
            (
                "manifest.json",
                source
                    .join("ModuleV2")
                    .join("Package")
                    .join("manifest.json"),
            ),
            (
                "manifest.p7s",
                source.join("ModuleV2").join("Package").join("manifest.p7s"),
            ),
            (
                "publisher.cer",
                source
                    .join("ModuleV2")
                    .join("Package")
                    .join("publisher.cer"),
            ),
            (
                "craft-signer-broker.exe",
                source
                    .join("ModuleV2")
                    .join("Broker")
                    .join("dist-local")
                    .join("CraftSignerBroker.exe"),
            ),
            (
                "wordcraft-cli.exe",
                source.join("Bundles").join("wordcraft-cli.exe"),
            ),
            (
                "gridcraft-cli.exe",
                source.join("Bundles").join("gridcraft-cli.exe"),
            ),
        ];
        for (name, path) in components {
            fs::copy(path, release.join(name)).expect("copy signed QA input into private root");
        }
        let approval = policies.join("org.craftopensource.signer.json");
        fs::write(
            &approval,
            serde_json::to_vec(&json!({
                "schema":POLICY_SCHEMA, "moduleId":MODULE_ID, "keySha256":pin
            }))
            .expect("synthetic policy JSON"),
        )
        .expect("write temporary test-only policy");
        let current = module.join("current.json");
        let record = json!({
            "moduleId":MODULE_ID, "moduleVersion":"0.2.2-qa",
            "releaseDirectory":leaf, "publisherPublicKeySha256":pin, "protocolMajor":1
        });
        fs::write(
            &current,
            serde_json::to_vec(&record).expect("registration JSON"),
        )
        .expect("write temporary test-only registration");

        let accepted = resolve_under(&extensions).expect("fully authentic signed 0.2.2 release");
        assert_eq!(accepted.verified_catalog().module_version, "0.2.2-qa");
        assert_eq!(
            accepted.executable(),
            release.join("craft-signer-broker.exe")
        );
        drop(accepted);

        let mut altered_registration = record.clone();
        altered_registration["releaseDirectory"] = json!("0.2.2-qa-0000000000000000");
        fs::write(
            &current,
            serde_json::to_vec(&altered_registration).expect("serialize"),
        )
        .expect("modify private registration");
        assert!(
            resolve_under(&extensions).is_err(),
            "wrong release name must fail"
        );
        fs::write(&current, serde_json::to_vec(&record).expect("serialize"))
            .expect("restore registration");

        fs::write(
            &approval,
            serde_json::to_vec(&json!({
                "schema":POLICY_SCHEMA, "moduleId":MODULE_ID, "keySha256":"0".repeat(64)
            }))
            .expect("serialize"),
        )
        .expect("modify private approval");
        assert!(
            resolve_under(&extensions).is_err(),
            "unapproved publisher must fail"
        );
        fs::write(
            &approval,
            serde_json::to_vec(&json!({
                "schema":POLICY_SCHEMA, "moduleId":MODULE_ID, "keySha256":pin
            }))
            .expect("serialize"),
        )
        .expect("restore private approval");

        let foreign = release.join("unexpected.dll");
        fs::write(&foreign, b"malicious DLL placeholder").expect("create synthetic DLL");
        assert!(
            resolve_under(&extensions).is_err(),
            "unexpected release file must fail"
        );
        fs::remove_file(foreign).expect("remove synthetic DLL");

        let worker = release.join("gridcraft-cli.exe");
        let mut data = fs::read(&worker).expect("read temporary worker copy");
        data[1_024] ^= 1;
        fs::write(&worker, &data).expect("tamper temporary GridCraft worker");
        assert!(
            resolve_under(&extensions).is_err(),
            "worker byte tamper must fail"
        );

        let user = directories::BaseDirs::new().expect("Windows known folders");
        let real = user.data_local_dir().join("Craft").join("Extensions");
        assert!(!extensions.starts_with(&real), "test root must not be live");
        // tempfile removes the entire synthetic approval and release tree.
    }

    /// Two independently signed .NET catalogs in one disposable release store.
    /// Does not create or change any owner publisher policy or live installation.
    #[test]
    #[ignore = "requires local signed 0.2.1 + 0.2.2 packages and independently pinned publisher"]
    fn real_signed_v021_to_v022_host_switch_refuses_old_release_and_locked_mutation() {
        let old = PathBuf::from(
            std::env::var_os("CRAFT_SIGNER_DOTNET_V021_ROOT")
                .expect("set v0.2.1 signed QA repository root"),
        );
        let new = PathBuf::from(
            std::env::var_os("CRAFT_SIGNER_DOTNET_V022_ROOT")
                .expect("set v0.2.2 signed QA repository root"),
        );
        let pin = std::env::var("CRAFT_SIGNER_PUBLISHER_SPKI_SHA256")
            .expect("independent developer public SPKI SHA-256 is required");
        let temp = tempfile::tempdir().expect("private disposable module root");
        let extensions = temp.path().join("Craft").join("Extensions");
        let module = extensions.join(MODULE_ID);
        let policy_dir = extensions.join("_trust");
        fs::create_dir_all(&policy_dir).unwrap();
        fs::write(
            policy_dir.join("org.craftopensource.signer.json"),
            serde_json::to_vec(&json!({
                "schema":POLICY_SCHEMA,"moduleId":MODULE_ID,"keySha256":pin
            }))
            .unwrap(),
        )
        .unwrap();

        // Real immutable manifests, detached signatures and all three
        // executable bytes; never invoke a signing or installation entrypoint.
        let copy_release = |source: &Path, expected_version: &str| -> String {
            let pkg = source.join("ModuleV2").join("Package");
            let manifest = fs::read(pkg.join("manifest.json")).unwrap();
            let cms = fs::read(pkg.join("manifest.p7s")).unwrap();
            let public_cert = fs::read(pkg.join("publisher.cer")).unwrap();
            let catalog = verify_catalog(&manifest, &cms, &public_cert, &pin)
                .expect("real source catalog must be cryptographically authenticated");
            assert_eq!(catalog.module_version, expected_version);
            let leaf = format!(
                "{}-{}",
                expected_version,
                &format!("{:X}", Sha256::digest(&manifest))[..16]
            );
            let release = module.join("releases").join(&leaf);
            fs::create_dir_all(&release).unwrap();
            for (name, path) in [
                ("manifest.json", pkg.join("manifest.json")),
                ("manifest.p7s", pkg.join("manifest.p7s")),
                ("publisher.cer", pkg.join("publisher.cer")),
                (
                    "craft-signer-broker.exe",
                    source
                        .join("ModuleV2")
                        .join("Broker")
                        .join("dist-local")
                        .join("CraftSignerBroker.exe"),
                ),
                (
                    "wordcraft-cli.exe",
                    source.join("Bundles").join("wordcraft-cli.exe"),
                ),
                (
                    "gridcraft-cli.exe",
                    source.join("Bundles").join("gridcraft-cli.exe"),
                ),
            ] {
                fs::copy(path, release.join(name)).expect("copy signed QA evidence");
            }
            leaf
        };
        let earlier = copy_release(&old, "0.2.1-qa");
        let later = copy_release(&new, "0.2.2-qa");
        assert_ne!(
            earlier, later,
            "separately signed releases have distinct hashes"
        );

        let current = module.join("current.json");
        let write_registration = |leaf: &str, version: &str| {
            let value = json!({
                "moduleId":MODULE_ID,"moduleVersion":version,
                "releaseDirectory":leaf,"publisherPublicKeySha256":pin,
                "protocolMajor":1
            });
            fs::write(&current, serde_json::to_vec(&value).unwrap()).unwrap();
        };
        write_registration(&earlier, "0.2.1-qa");
        assert!(
            resolve_under(&extensions).is_err(),
            "the host refuses known vulnerable signed v0.2.1 despite matching publisher"
        );

        write_registration(&later, "0.2.2-qa");
        let locked =
            resolve_under(&extensions).expect("newer signed v0.2.2 must be independently accepted");
        assert_eq!(locked.verified_catalog().module_version, "0.2.2-qa");
        let broker = locked.executable().to_owned();

        // A locked handle must prevent replacing the authenticated broker
        // between its SHA-256 check and the caller's eventual process start.
        assert!(
            fs::write(&broker, b"corrupt broker swap").is_err(),
            "Windows share-mode file lock must block mutation of signed broker"
        );

        // An outside writer could change current.json after the handle is
        // acquired. The existing handle remains pinned to the trusted v0.2.2
        // path; a new resolver call must fail closed on the old version.
        write_registration(&earlier, "0.2.1-qa");
        assert_eq!(locked.executable(), broker.as_path());
        assert!(
            resolve_under(&extensions).is_err(),
            "registration rollback must not activate old signed module"
        );
        drop(locked);

        write_registration(&later, "0.2.2-qa");
        assert!(
            resolve_under(&extensions).is_ok(),
            "restoring the new release works"
        );
        fs::write(&current, b"{incomplete registration").unwrap();
        assert!(
            resolve_under(&extensions).is_err(),
            "partial registration fails closed"
        );

        let real_user = directories::BaseDirs::new()
            .unwrap()
            .data_local_dir()
            .join("Craft")
            .join("Extensions");
        assert!(
            !extensions.starts_with(&real_user),
            "the synthetic approval never targets the real user's module root"
        );
    }
}
