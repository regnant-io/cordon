//! Build script: Tauri's code generation, plus a check that the bundled
//! llama.cpp runtime is in place.

use std::path::Path;

fn main() {
    // The bundle's `resources` entry names this directory. It is filled by
    // `scripts/fetch-llama` and is not committed, so a fresh checkout would
    // otherwise fail here with a missing-path error that says nothing about
    // llama.cpp. An empty directory lets a development build proceed (the app
    // then falls back to a `llama-server` on PATH); the packaging scripts refuse
    // to produce an installer without the runtime.
    let llama = Path::new("llama");
    if !llama.exists() {
        let _ = std::fs::create_dir_all(llama);
    }
    let exe = if std::env::var("CARGO_CFG_WINDOWS").is_ok() {
        "llama-server.exe"
    } else {
        "llama-server"
    };
    if !llama.join(exe).is_file() {
        println!(
            "cargo:warning=desktop/src-tauri/llama/{} is missing; run scripts/fetch-llama \
             to bundle llama.cpp. This build will look for llama-server on PATH.",
            exe
        );
    }
    println!("cargo:rerun-if-changed=llama");

    // The `cordon` command line is staged into `bin` by scripts/stage-cli.mjs
    // before an installer is built. The resource entry needs the folder to
    // exist for any other build.
    let bin = Path::new("bin");
    if !bin.exists() {
        let _ = std::fs::create_dir_all(bin);
    }
    println!("cargo:rerun-if-changed=bin");

    tauri_build::build()
}
