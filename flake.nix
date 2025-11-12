{
	description = "rust-bitcoinkernel";

	inputs = {
		nixpkgs.url = "nixpkgs/nixos-25.05";
		flake-utils.url = "github:numtide/flake-utils";
		fenix = {
			url = "github:nix-community/fenix";
			inputs.nixpkgs.follows = "nixpkgs";
		};
	};

	outputs = { self, nixpkgs, flake-utils, fenix }:
		flake-utils.lib.eachDefaultSystem (system:
			let
				pkgs = import nixpkgs {
					inherit system;
				};

				rustVersion = "1.71.0";
				rustToolchain = fenix.packages.${system}.fromToolchainName {
					name = rustVersion;
					sha256 = "sha256-ks0nMEGGXKrHnfv4Fku+vhQ7gx76ruv6Ij4fKZR3l78=";
				};
				rustBuildToolchain = fenix.packages.${system}.combine [
					rustToolchain.rustc
					rustToolchain.cargo
					rustToolchain.rust-src
					rustToolchain.rust-std
				];

				rustBuildToolchainNightly = fenix.packages.${system}.latest.toolchain;

				rustPlatformNightly = pkgs.makeRustPlatform {
					cargo = rustBuildToolchainNightly;
					rustc = rustBuildToolchainNightly;
				};
				rustfilt = rustPlatformNightly.buildRustPackage rec {
					pname = "rustfilt";
					version = "0.2.1";
					src = pkgs.fetchFromGitHub {
						owner = "luser";
						repo = "rustfilt";
						rev = version;
						hash = "sha256-zb1tkeWmeMq7aM8hWssS/UpvGzGbfsaVYCOKBnAKwiQ=";
					};
					cargoLock.lockFile = "${src}/Cargo.lock";
				};
			in {
				devShells.default = pkgs.mkShell {
					packages = [
						rustBuildToolchain

						pkgs.cmake
						pkgs.boost.dev
						pkgs.cargo-fuzz
					];

					LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";
				};

				devShells.nightly = pkgs.mkShell {
					packages = [
						rustBuildToolchainNightly

						pkgs.cmake
						pkgs.boost.dev
						pkgs.cargo-fuzz

						pkgs.libllvm
						pkgs.cargo-llvm-cov
						rustfilt
					];

					LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";
					LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
						pkgs.gcc.cc.lib
					];
				};
			}
		);
}
