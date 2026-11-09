//! Synthetic-only in-process visual OPC smoke harness. Not a production UI command.
#![cfg(windows)]
use craft_signing_core::{
    office_visible_opc::{add_unsigned_visual_appearance, OfficeImagePlacement},
    opc_native::{sign_opc_inprocess, verify_opc_inprocess},
};
use std::{env, fs, path::PathBuf, process::ExitCode};

fn run() -> Result<(), String> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() != 5 {
        return Err("usage: office_visible_smoke SOURCE OUTPUT PNG THUMBPRINT SIGNER".into());
    }
    let source = PathBuf::from(&args[0]);
    let output = PathBuf::from(&args[1]);
    let png = PathBuf::from(&args[2]);
    let thumbprint = args[3].to_string_lossy().to_string();
    let signer = args[4].to_string_lossy().to_string();
    let source_resolved = source.canonicalize().map_err(|e| e.to_string())?;
    let png_resolved = png.canonicalize().map_err(|e| e.to_string())?;
    // Do not accidentally run a development appearance test on personal documents.
    let target = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target").canonicalize().map_err(|e| e.to_string())?;
    if !source_resolved.starts_with(&target) || !png_resolved.starts_with(&target) {
        return Err("Synthetic source and PNG must both be within core/target".into());
    }
    let placement = match source.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "docx" => OfficeImagePlacement::WordDocumentEnd,
        "xlsx" => OfficeImagePlacement::ExcelCell { column: 4, row: 1 },
        _ => return Err("Only DOCX/XLSX synthetic sources supported".into()),
    };
    let stage_name = format!(
        "visible-unsigned-{}.{}",
        std::process::id(),
        source.extension().and_then(|e| e.to_str()).unwrap()
    );
    let stage = output.with_file_name(stage_name);
    if stage.exists() || output.exists() {
        return Err("Unsigned stage or signed destination already exists".into());
    }
    let img = fs::read(png_resolved).map_err(|e| e.to_string())?;
    add_unsigned_visual_appearance(&source, &stage, &img, &signer, placement)?;
    let result = (|| {
        sign_opc_inprocess(&stage, &output, &thumbprint)?;
        let count = verify_opc_inprocess(&output)?;
        if count != 1 {
            return Err("Expected exactly one new valid OPC signature".into());
        }
        Ok::<_, String>(())
    })();
    let _ = fs::remove_file(&stage);
    result?;
    println!("NATIVE_VISUAL_OPC_SIGN_PASS");
    println!("NATIVE_VISUAL_OPC_VERIFY_PASS signatures=1");
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("NATIVE_VISUAL_OPC_SMOKE_FAIL: {e}");
            ExitCode::FAILURE
        }
    }
}
