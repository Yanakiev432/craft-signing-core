//! Local Windows OPC DOCX/XLSX signing smoke harness. Integrity only, not QES.
//! An explicit certificate thumbprint is required; no implicit credential selection.
#![cfg(windows)]

use craft_signing_core::opc_native::{sign_opc_inprocess, verify_opc_inprocess};
use std::{env, path::PathBuf, process::ExitCode};

fn run() -> Result<(), String> {
    let mut args = env::args_os().skip(1);
    let source = PathBuf::from(
        args.next()
            .ok_or("usage: opc_sign_smoke SOURCE OUTPUT THUMBPRINT")?,
    );
    let output = PathBuf::from(args.next().ok_or("missing output path")?);
    let thumbprint = args
        .next()
        .ok_or("missing explicit certificate thumbprint")?
        .into_string()
        .map_err(|_| "thumbprint contains invalid unicode")?;
    if args.next().is_some() {
        return Err("unexpected additional argument".into());
    }
    sign_opc_inprocess(&source, &output, &thumbprint)?;
    println!("NATIVE_OPC_SIGN_PASS");
    let count = verify_opc_inprocess(&output)?;
    println!("NATIVE_OPC_VERIFY_PASS signatures={count}");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("NATIVE_OPC_SMOKE_FAIL: {e}");
            ExitCode::FAILURE
        }
    }
}
