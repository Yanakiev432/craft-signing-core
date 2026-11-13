//! Native, no-unsafe independent verification of a Craft Signer detached
//! .NET CMS module catalog. A signed catalog is NOT a user approval decision.
//! The separately pinned, user-owned public-key fingerprint is mandatory.
//!
//! This first verifier supports the RSA/SHA-256 detached id-data profile
//! actually emitted by signed Craft Signer 0.2.2-qa. Unsupported algorithms
//! or signed attributes fail closed; they are not silently downgraded.
use cms::{
    cert::CertificateChoices,
    content_info::ContentInfo,
    signed_data::{SignedData, SignerIdentifier},
};
use der::{Decode, Encode};
use rsa::{
    PublicKey,
    pkcs1v15::{Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
    signature::Verifier,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const MODULE_ID: &str = "org.craftopensource.signer";
const SCHEMA: &str = "craft.signer/module-preview-v2";
const CMS_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const CMS_DATA: &str = "1.2.840.113549.1.7.1";
const SHA256_OID: &str = "2.16.840.1.101.3.4.2.1";
const RSA_PUBLIC_KEY_OID: &str = "1.2.840.113549.1.1.1";
const RSA_SHA256_SIGN_OID: &str = "1.2.840.113549.1.1.11";

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Worker {
    host: String,
    file: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    schema: String,
    module_id: String,
    module_version: String,
    protocol_major: u32,
    workers: Vec<Worker>,
    actions: Vec<String>,
    supported_host_adapters: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCatalog {
    pub module_version: String,
    pub manifest_sha256: String,
    pub publisher_key_sha256: String,
    pub broker_sha256: String,
    pub word_worker_sha256: String,
    pub grid_worker_sha256: String,
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:X}", Sha256::digest(bytes))
}

fn hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn strict_manifest(manifest: &[u8]) -> Result<Manifest, String> {
    if manifest.is_empty() || manifest.len() > 16_384 {
        return Err("Signed module catalog size is out of bounds".into());
    }
    let value: Manifest =
        serde_json::from_slice(manifest).map_err(|_| "Invalid signed module JSON")?;
    if value.schema != SCHEMA
        || value.module_id != MODULE_ID
        || value.protocol_major != 1
        || value.module_version.is_empty()
        || value.module_version.len() > 40
        || !value
            .module_version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        || value.workers.len() != 3
        || value.actions != ["document.sign", "document.verify"]
        || value.supported_host_adapters.len() > 16
        || value
            .supported_host_adapters
            .iter()
            .any(|label| label.len() > 120)
    {
        return Err("Unsupported signer module identity, actions or version".into());
    }
    let expected = [
        ("broker", "craft-signer-broker.exe"),
        ("wordcraft", "wordcraft-cli.exe"),
        ("gridcraft", "gridcraft-cli.exe"),
    ];
    for (host, executable) in expected {
        if value
            .workers
            .iter()
            .filter(|w| w.host == host && w.file == executable && hex64(&w.sha256))
            .count()
            != 1
        {
            return Err("Signed module worker descriptor is invalid".into());
        }
    }
    if value.workers.iter().any(|w| {
        !expected
            .iter()
            .any(|(host, executable)| &w.host == host && &w.file == executable)
    }) {
        return Err("Unexpected signed module executable".into());
    }
    Ok(value)
}

/// Authenticate actual detached .NET SignedCms bytes and parse only the
/// authenticated manifest. Does not accept a certificate alone as approval.
pub fn verify_catalog(
    manifest: &[u8],
    detached_cms: &[u8],
    publisher_der: &[u8],
    approved_public_key_sha256: &str,
) -> Result<VerifiedCatalog, String> {
    if !hex64(approved_public_key_sha256)
        || detached_cms.is_empty()
        || detached_cms.len() > 65_536
        || publisher_der.is_empty()
        || publisher_der.len() > 16_384
    {
        return Err("Missing or oversized signed module trust evidence".into());
    }
    let publisher = cms::cert::x509::Certificate::from_der(publisher_der)
        .map_err(|_| "Publisher X.509 certificate is invalid")?;
    let spki = publisher
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| "Publisher public key cannot be serialized")?;
    let actual_key = hex_digest(&spki);
    if !actual_key.eq_ignore_ascii_case(approved_public_key_sha256) {
        return Err("Signer does not match the independently approved public key".into());
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "System clock is earlier than Unix epoch")?
        .as_secs();
    if now
        < publisher
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs()
        || now
            > publisher
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs()
    {
        return Err("Approved publisher certificate is not currently valid".into());
    }
    if publisher
        .tbs_certificate
        .subject_public_key_info
        .algorithm
        .oid
        .to_string()
        != RSA_PUBLIC_KEY_OID
    {
        return Err("Unsupported module publisher public-key algorithm".into());
    }

    let info =
        ContentInfo::from_der(detached_cms).map_err(|_| "Invalid detached CMS ContentInfo")?;
    if info.content_type.to_string() != CMS_SIGNED_DATA {
        return Err("Catalog is not CMS SignedData".into());
    }
    let signed: SignedData = info
        .content
        .decode_as()
        .map_err(|_| "Invalid CMS SignedData structure")?;
    if signed.encap_content_info.econtent_type.to_string() != CMS_DATA
        || signed.encap_content_info.econtent.is_some()
        || signed.digest_algorithms.len() != 1
        || signed
            .digest_algorithms
            .iter()
            .any(|alg| alg.oid.to_string() != SHA256_OID)
        || signed.signer_infos.0.len() != 1
    {
        return Err("Catalog must have exactly one detached SHA-256 signer".into());
    }
    let embedded = signed
        .certificates
        .as_ref()
        .ok_or("CMS publisher cert is missing")?;
    if embedded.0.len() != 1 {
        return Err("CMS must include exactly one publisher certificate".into());
    }
    match embedded.0.iter().next() {
        Some(CertificateChoices::Certificate(cert)) if cert == &publisher => {}
        _ => return Err("Embedded CMS publisher certificate differs".into()),
    }
    let signer = signed
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or("CMS signerInfos is empty")?;
    match &signer.sid {
        SignerIdentifier::IssuerAndSerialNumber(id)
            if id.issuer == publisher.tbs_certificate.issuer
                && id.serial_number == publisher.tbs_certificate.serial_number => {}
        _ => return Err("CMS signer identifier does not match approved certificate".into()),
    }
    if signer.digest_alg.oid.to_string() != SHA256_OID
        || !matches!(
            signer.signature_algorithm.oid.to_string().as_str(),
            RSA_PUBLIC_KEY_OID | RSA_SHA256_SIGN_OID
        )
        || signer.signed_attrs.is_some()
    {
        return Err("Unsupported CMS signature mode or algorithm (fail closed)".into());
    }
    let public_key = PublicKey::from_public_key_der(&spki)
        .map_err(|_| "Cannot decode approved RSA public key")?;
    let signature = Signature::try_from(signer.signature.as_bytes())
        .map_err(|_| "Cannot decode CMS RSA signature")?;
    VerifyingKey::<rsa::sha2::Sha256>::new(public_key)
        .verify(manifest, &signature)
        .map_err(|_| "CMS signature does not authenticate the manifest")?;

    let decoded = strict_manifest(manifest)?;
    let hash_for = |name: &str| {
        decoded
            .workers
            .iter()
            .find(|worker| worker.file == name)
            .map(|worker| worker.sha256.to_ascii_uppercase())
            .ok_or_else(|| "Missing signed module worker".to_owned())
    };
    Ok(VerifiedCatalog {
        module_version: decoded.module_version,
        manifest_sha256: hex_digest(manifest),
        publisher_key_sha256: actual_key,
        broker_sha256: hash_for("craft-signer-broker.exe")?,
        word_worker_sha256: hash_for("wordcraft-cli.exe")?,
        grid_worker_sha256: hash_for("gridcraft-cli.exe")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, fs, path::PathBuf};

    #[test]
    fn no_approval_or_untrusted_inputs_are_accepted() {
        assert!(verify_catalog(b"", b"", b"", "").is_err());
        assert!(verify_catalog(b"{}", b"abc", b"abc", &"0".repeat(64)).is_err());
        assert!(!hex64("invalid"));
        assert!(strict_manifest(br#"{"schema":"forged"}"#).is_err());
    }

    /// Real detached .NET catalog. Only public manifest, CMS and certificate
    /// are used. No token, signing operation, installed module or trust store.
    #[test]
    #[ignore = "requires locally signed Craft Signer 0.2.2 catalog and independent public SPKI SHA-256"]
    fn actual_dotnet_v022_rsa_cms_catalog_verifies_and_tamper_fails() {
        let source = PathBuf::from(
            env::var_os("CRAFT_SIGNER_DOTNET_CMS_QA_DIR")
                .expect("set CRAFT_SIGNER_DOTNET_CMS_QA_DIR to local ModuleV2/Package"),
        );
        let pin = env::var("CRAFT_SIGNER_PUBLISHER_SPKI_SHA256")
            .expect("independently computed SPKI SHA-256 required");
        let manifest = fs::read(source.join("manifest.json")).expect("manifest file");
        let cms = fs::read(source.join("manifest.p7s")).expect("signed CMS file");
        let cert = fs::read(source.join("publisher.cer")).expect("publisher public DER");
        let accepted = verify_catalog(&manifest, &cms, &cert, &pin)
            .expect("actual 0.2.2 signed catalog verified by independent RustCrypto");
        assert_eq!(accepted.module_version, "0.2.2-qa");
        assert_eq!(accepted.manifest_sha256, hex_digest(&manifest));
        assert_eq!(accepted.broker_sha256.len(), 64);

        let mut tampered_manifest = manifest.clone();
        tampered_manifest[0] ^= 1;
        assert!(verify_catalog(&tampered_manifest, &cms, &cert, &pin).is_err());

        let mut tampered_signature = cms.clone();
        let end = tampered_signature.len() - 1;
        tampered_signature[end] ^= 1;
        assert!(verify_catalog(&manifest, &tampered_signature, &cert, &pin).is_err());

        let mut tampered_cert = cert.clone();
        let end = tampered_cert.len() - 1;
        tampered_cert[end] ^= 1;
        assert!(verify_catalog(&manifest, &cms, &tampered_cert, &pin).is_err());
        assert!(verify_catalog(&manifest, &cms, &cert, &"0".repeat(64)).is_err());
    }
}
