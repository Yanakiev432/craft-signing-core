#[cfg(windows)]
fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if args.len() != 4 {
        eprintln!("Usage: opc_native_sign input.docx output.docx 40hexSHA1certThumbprint");
        std::process::exit(2);
    }
    let fingerprint = args[3].to_string_lossy();
    match craft_signing_core::opc_native::sign_opc_inprocess(
        std::path::Path::new(&args[1]),
        std::path::Path::new(&args[2]),
        &fingerprint,
    ) {
        Ok(()) => println!("WINDOWS_OPC_INPROCESS_SIGN_AND_REVERIFY=PASS; QES=NOT_CHECKED"),
        Err(error) => {
            eprintln!("WINDOWS_OPC_NATIVE_SIGN_REJECTED: {error}");
            std::process::exit(1)
        }
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows-only");
    std::process::exit(1);
}
