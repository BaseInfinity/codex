//! Helper binary for exercising the production reqwest client construction path in tests.
//!
//! Unlike `custom_ca_probe`, this binary intentionally uses
//! `build_reqwest_client_with_custom_ca(reqwest::Client::builder())` without disabling proxy
//! autodetection. The macOS seatbelt regression test launches it under `sandbox-exec` with
//! `com.apple.SystemConfiguration.configd` denied to prove that client construction no longer
//! panics when system proxy discovery cannot create an `SCDynamicStore`.

use std::process;

fn main() {
    match codex_client::build_reqwest_client_with_custom_ca(reqwest::Client::builder()) {
        Ok(_) => {
            println!("ok");
        }
        Err(error) => {
            eprintln!("{error}");
            process::exit(1);
        }
    }
}
