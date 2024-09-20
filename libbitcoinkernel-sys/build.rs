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

    let pkg_config_path = install_dir.join("lib/pkgconfig");
    env::set_var("PKG_CONFIG_PATH", pkg_config_path);

    let library = pkg_config::Config::new()
        .statik(true)
        .probe("libbitcoinkernel")
        .expect("Failed to find the 'bitcoinkernel' library with pkg-config");

    let header = format!("{}/bitcoinkernel.h", library.include_paths[0].display());

    let bindings = bindgen::Builder::default()
        .header(header)
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
        println!("cargo:rustc-link-lib=dylib=c++");
    } else if compiler.is_like_gnu() {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    } else {
        panic!("Cannot figure out the c++ standard library to link with this compiler.");
    }
}
