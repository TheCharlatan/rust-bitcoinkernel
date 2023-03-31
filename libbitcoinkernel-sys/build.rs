use std::env;
use std::path::PathBuf;

fn main() {
    let pkg_config_path = "/home/drgrid/bitcoin/test_install/lib/pkgconfig";
    if env::var("PKG_CONFIG_PATH").is_err() {
        env::set_var("PKG_CONFIG_PATH", pkg_config_path);
    }

    let library = pkg_config::Config::new()
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
}
