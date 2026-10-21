#[cfg(windows)]
fn main() {
    let p = std::env::args_os()
        .nth(1)
        .expect("expected DOCX or XLSX path");
    match craft_signing_core::opc_native::verify_opc_inprocess(std::path::Path::new(&p)) {
        Ok(n) => println!(
            "WINDOWS_OPC_NATIVE_CRYPTOVERIFY_OK signatures={n} complete_package_coverage=NOT_CHECKED trust=NOT_CHECKED"
        ),
        Err(e) => {
            eprintln!("WINDOWS_OPC_NATIVE_REJECTED: {e}");
            std::process::exit(1)
        }
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows-only native OPC");
    std::process::exit(1)
}
