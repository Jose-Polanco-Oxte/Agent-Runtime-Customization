use std::{env, fs, path::Path};

mod command_manifest {
    include!("src/command_manifest.rs");
}

fn emit_frontend_dependencies(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());
    if !path.is_dir() {
        return;
    }

    let entries = fs::read_dir(path).unwrap_or_else(|error| {
        panic!("failed reading embedded frontend directory {path:?}: {error}")
    });
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| {
            panic!("failed reading embedded frontend entry in {path:?}: {error}")
        });
        let entry_path = entry.path();
        if entry_path.is_dir() {
            emit_frontend_dependencies(&entry_path);
        } else {
            println!("cargo:rerun-if-changed={}", entry_path.display());
        }
    }
}

fn main() {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
        .map(std::path::PathBuf::from)
        .expect("CARGO_MANIFEST_DIR must be set for the Tauri build script");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/command_manifest.rs");
    let frontend_dist = manifest_dir.join("..").join("dist");
    emit_frontend_dependencies(&frontend_dist);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(command_manifest::DECISION_COMMANDS),
    ))
    .expect("failed to build the Tauri application manifest");
}
