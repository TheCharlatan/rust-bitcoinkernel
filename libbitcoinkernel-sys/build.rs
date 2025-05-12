use bindgen::RustEdition;
use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let bitcoin_dir = Path::new("bitcoin");
    let out_dir = env::var("OUT_DIR").unwrap();
    let build_dir = Path::new(&out_dir).join("bitcoin");
    let install_dir = Path::new(&out_dir).join("install");

    println!("{} {}", bitcoin_dir.display(), build_dir.display());

    // Iterate through all files in the Bitcoin Core submodule directory
    println!("cargo:rerun-if-changed={}", bitcoin_dir.display());

    Command::new("cmake")
        .arg("-B")
        .arg(&build_dir)
        .arg("-S")
        .arg(&bitcoin_dir)
        .arg("-DBUILD_KERNEL_LIB=ON")
        .arg("-DBUILD_TESTS=OFF")
        .arg("-DBUILD_TX=OFF")
        .arg("-DBUILD_WALLET_TOOL=OFF")
        .arg("-DENABLE_WALLET=OFF")
        .arg("-DBUILD_UTIL=OFF")
        .arg("-DBUILD_DAEMON=OFF")
        .arg("-DBUILD_UTIL_CHAINSTATE=OFF")
        .arg("-DBUILD_CLI=OFF")
        .arg("-DBUILD_SHARED_LIBS=OFF")
        .arg("-DCMAKE_INSTALL_LIBDIR=lib")
        .arg(format!("-DCMAKE_INSTALL_PREFIX={}", install_dir.display()))
        .status()
        .unwrap();

    let num_jobs = env::var("NUM_JOBS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(1); // Default to 1 if not set

    Command::new("cmake")
        .arg("--build")
        .arg(&build_dir)
        .arg(format!("--parallel={}", num_jobs))
        .status()
        .unwrap();

    Command::new("cmake")
        .arg("--install")
        .arg(&build_dir)
        .status()
        .unwrap();

    let lib_dir = install_dir.join("lib");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    // Link all static libraries found in the install directory
    for entry in std::fs::read_dir(&lib_dir).expect("Library directory has to be readable") {
        let path = entry.unwrap().path();
        if path.extension().map_or(false, |extension| extension == "a") {
            if let Some(name) = path.file_stem().and_then(|n| n.to_str()) {
                // Remove the 'lib' prefix from the filename
                let lib_name = name.strip_prefix("lib").unwrap_or(name);
                println!("cargo:rustc-link-lib=static={}", lib_name);
            }
        }
    }

    // Header path for bindgen
    let include_path = install_dir.join("include");
    let header = include_path.join("bitcoinkernel.h");

    #[allow(deprecated)]
    let bindings = bindgen::Builder::default()
        .header(header.to_str().unwrap())
        .rust_target(bindgen::RustTarget::Stable_1_71)
        .rust_edition(RustEdition::Edition2021)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(
        env::var("OUT_DIR").expect("OUT_DIR was not defined by the cargo environment!"),
    );
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    let compiler = cc::Build::new().get_compiler();
    if compiler.is_like_clang() {
        let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
        if target_os == "macos" {
            println!("cargo:rustc-link-lib=dylib=c++");
        } else {
            println!("cargo:rustc-link-lib=dylib=stdc++");
        }
    } else if compiler.is_like_gnu() {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    } else {
        panic!("Cannot figure out the c++ standard library to link with this compiler.");
    }
}
