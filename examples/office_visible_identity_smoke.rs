//! Synthetic-only certificate-bound in-process rendered/embedded/signed OPC acceptance.
#![cfg(windows)]
use craft_signing_core::{
    office_appearance::OfficeSignatureAppearance,
    office_visible_opc::{OfficeImagePlacement, parse_excel_cell_anchor},
    office_visible_sign::sign_with_visible_appearance,
    opc_native::verify_opc_inprocess,
};
use std::{env, path::PathBuf, process::ExitCode};

fn run() -> Result<(), String> {
    let mut args=env::args_os().skip(1);
    let source=PathBuf::from(args.next().ok_or("usage: office_visible_identity_smoke SOURCE OUTPUT THUMBPRINT")?);
    let output=PathBuf::from(args.next().ok_or("Missing output")?);
    let thumbprint=args.next().ok_or("Missing thumbprint")?.to_string_lossy().to_string();
    let excel_anchor = args.next().map(|s| s.to_string_lossy().to_string());
    if args.next().is_some() {return Err("Unexpected arguments".into());}
    let root=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target").canonicalize().map_err(|e|e.to_string())?;
    let absolute=source.canonicalize().map_err(|e|e.to_string())?;
    if !absolute.starts_with(&root) {return Err("Synthetic core/target fixture required".into());}
    let placement=match source.extension().and_then(|x|x.to_str()).unwrap_or("") {
        "docx" => {
            if excel_anchor.is_some() {
                return Err("Excel cell argument is not allowed for DOCX".into());
            }
            OfficeImagePlacement::WordDocumentEnd
        },
        "xlsx" => parse_excel_cell_anchor(excel_anchor.as_deref().unwrap_or("E2"))?,
        _=>return Err("Not DOCX/XLSX".into())
    };
    let appearance=OfficeSignatureAppearance::default();
    sign_with_visible_appearance(&source,&output,&thumbprint,&appearance,placement)?;
    let n=verify_opc_inprocess(&output)?;
    if n!=1 {return Err("Wrong signature count".into());}
    println!("NATIVE_CERT_BOUND_VISIBLE_{}_PASS", source.extension().unwrap().to_string_lossy().to_uppercase());
    Ok(())
}
fn main()->ExitCode {
    match run(){
        Ok(())=>ExitCode::SUCCESS,
        Err(e)=>{eprintln!("VISIBLE_IDENTITY_SMOKE_FAIL: {e}");ExitCode::FAILURE}
    }
}
