//! Offline OPC signature-integrity verification smoke test; not certificate trust.
#![cfg(windows)]
use craft_signing_core::opc_native::verify_opc_inprocess;
use std::{env, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: opc_verify_smoke DOCUMENT.docx|DOCUMENT.xlsx");
        return ExitCode::FAILURE;
    };
    if args.next().is_some() {
        eprintln!("unexpected extra argument");
        return ExitCode::FAILURE;
    }
    match verify_opc_inprocess(&PathBuf::from(path)) {
        Ok(n) => {
            println!("OPC_VERIFY_PASS signatures={n}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("OPC_VERIFY_FAIL: {e}");
            ExitCode::FAILURE
        }
    }
}
