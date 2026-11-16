//! Opt-in, disposable v0.2.3 release discovery test. No real approval or signing.
use super::*;
use serde_json::json;

#[test]
#[ignore = "requires locally signed 0.2.3 QA artifacts; synthetic temporary owner policy only"]
fn signed_v023_resolver_authenticates_and_rejects_modified_release() {
    let root = PathBuf::from(
        std::env::var_os("CRAFT_SIGNER_V023_QA_ROOT").expect("provide the local 0.2.3 QA worktree"),
    );
    const PIN: &str = "E70FFDFAD52A79E3EDB3C0E1CC74694303109E0CA8C8849A51E5DCF5ED13E0AB";
    let temp = tempfile::tempdir().expect("disposable release store");
    let extensions = temp.path().join("Craft").join("Extensions");
    let real = directories::BaseDirs::new()
        .expect("Windows folders")
        .data_local_dir()
        .join("Craft")
        .join("Extensions");
    assert!(
        !extensions.starts_with(&real),
        "cannot test against live owner policy"
    );
    let module = extensions.join(MODULE_ID);
    let policies = extensions.join("_trust");
    fs::create_dir_all(&policies).expect("synthetic policy location");

    let pkg = root.join("ModuleV2").join("Package");
    let manifest = fs::read(pkg.join("manifest.json")).expect("signed manifest");
    let hash = format!("{:X}", Sha256::digest(&manifest));
    let leaf = format!("0.2.3-qa-{}", &hash[..16]);
    let release = module.join("releases").join(&leaf);
    fs::create_dir_all(&release).expect("synthetic release location");
    for (name, source) in [
        ("manifest.json", pkg.join("manifest.json")),
        ("manifest.p7s", pkg.join("manifest.p7s")),
        ("publisher.cer", pkg.join("publisher.cer")),
        (
            "craft-signer-broker.exe",
            root.join("ModuleV2/Broker/dist-local/CraftSignerBroker.exe"),
        ),
        ("wordcraft-cli.exe", root.join("Bundles/wordcraft-cli.exe")),
        ("gridcraft-cli.exe", root.join("Bundles/gridcraft-cli.exe")),
    ] {
        let copied = fs::copy(source, release.join(name)).expect("copy signed QA source bytes");
        assert!(copied > 0);
    }
    let approval = policies.join("org.craftopensource.signer.json");
    let approved = json!({
        "schema": POLICY_SCHEMA, "moduleId": MODULE_ID, "keySha256": PIN,
    });
    fs::write(&approval, serde_json::to_vec(&approved).unwrap()).expect("synthetic policy only");
    let current = module.join("current.json");
    let registration = json!({
        "moduleId": MODULE_ID,
        "moduleVersion": "0.2.3-qa",
        "releaseDirectory": leaf,
        "publisherPublicKeySha256": PIN,
        "protocolMajor": 1,
    });
    fs::write(&current, serde_json::to_vec(&registration).unwrap())
        .expect("synthetic registration only");

    let accepted = resolve_under(&extensions).expect("real signed 0.2.3 authenticated");
    assert_eq!(accepted.verified_catalog().module_version, "0.2.3-qa");
    assert_eq!(
        accepted.verified_catalog().broker_sha256,
        "300A25093A40C997CD45A5DC6AF4F40A63581EFF80BEEAC36EA6257651A9B4D5"
    );
    assert_eq!(
        accepted.executable(),
        release.join("craft-signer-broker.exe")
    );
    drop(accepted);

    let mut swapped = registration.clone();
    swapped["releaseDirectory"] = json!("0.2.3-qa-0000000000000000");
    fs::write(&current, serde_json::to_vec(&swapped).unwrap()).unwrap();
    assert!(
        resolve_under(&extensions).is_err(),
        "bad release leaf must fail"
    );
    fs::write(&current, serde_json::to_vec(&registration).unwrap()).unwrap();

    let mut wrong_key = approved.clone();
    wrong_key["keySha256"] = json!("0".repeat(64));
    fs::write(&approval, serde_json::to_vec(&wrong_key).unwrap()).unwrap();
    assert!(
        resolve_under(&extensions).is_err(),
        "publisher substitution must fail"
    );
    fs::write(&approval, serde_json::to_vec(&approved).unwrap()).unwrap();

    let foreign = release.join("unapproved-worker.dll");
    fs::write(&foreign, b"synthetic non-executable marker").unwrap();
    assert!(
        resolve_under(&extensions).is_err(),
        "extra release entry must fail"
    );
    fs::remove_file(&foreign).unwrap();

    let worker = release.join("gridcraft-cli.exe");
    let mut modified = fs::read(&worker).unwrap();
    modified[1_024] ^= 1;
    fs::write(&worker, modified).unwrap();
    assert!(
        resolve_under(&extensions).is_err(),
        "worker byte tampering must fail"
    );
    // tempfile Drop destroys all synthetic policy, registration and worker copies.
}
