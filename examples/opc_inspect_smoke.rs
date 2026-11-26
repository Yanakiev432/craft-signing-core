//! Read-only strict OPC stage report. Exit 0 only for strict PASS.
#[cfg(windows)]
fn main() -> std::process::ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 1 {
        return std::process::ExitCode::FAILURE;
    }
    match craft_signing_core::opc_native::inspect_opc_inprocess(std::path::Path::new(&args[0])) {
        Ok(r) => {
            println!("{}", serde_json::to_string(&r).expect("serialize report"));
            if r.strict_pass {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}
#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
