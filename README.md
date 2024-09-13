# rust-bitcoinkernel

:warning::construction: This library is still under contruction. :warning::construction:

`rust-bitcoinkernel` is a wrapper around
[libbitcoinkernel](https://github.com/bitcoin/bitcoin/issues/24303), a C++
library exposing Bitcoin Core's validation engine.

## Building

To build this library, first build the kernel library on my kernelApi branch. It
produces a C-compatible header that is used by this project to create the FFI.

```bash
git clone https://github.com/TheCharlatan/bitcoin
git checkout kernelApi
cmake -B build -DBUILD_KERNEL_LIB=ON -DCMAKE_INSTALL_PREFIX=~/bitcoin/install_dir
cmake --build build --target bitcoinkernel
cmake --install build --component Kernel
```

This will install the library in `$HOME/bitcoin/install_dir`. Change the value
after `--prefix` to control where the library will be installed or leave it
unchanged to install it system-wide.

Then, to compile `rust-bitcoinkernel` (add the `PKG_CONFIG_PATH` if
libbitcoinkernel is not installed in `/usr/local`):

```bash
PKG_CONFIG_PATH=/path/to/bitcoin/install_dir/lib/pkgconfig cargo b
```

And similarly for running it (env variables only required if not installed in
`/usr/local`, use `DYLD_LIBRARY_PATH` on macos instead of `LD_LIBRARY_PATH`):

```bash
PKG_CONFIG_PATH=/path/to/bitcoin/install_dir/lib/pkgconfig LD_LIBRARY_PATH=/path/to/bitcoin/install_dir/lib cargo run
```

## Fuzzing

Fuzzing is done with [cargo fuzz](https://github.com/rust-fuzz/cargo-fuzz).

There are currently three supported fuzzing targets: `fuzz_target_block`,
`fuzz_target_chainman` and `fuzz_target_verify`. The `chainman` target touches
the filesystem in `/tmp`. If `/tmp` is not already a tmpfs, the user should
create a tmpfs in `/tmp/rust_kernel_fuzz`.

To get fuzzing run (in this case the `verify` target):

```bash
LD_LIBRARY_PATH=/usr/local/lib cargo fuzz run fuzz_target_verify
```

Sanitizers can be turned on with e.g.
```bash
LD_LIBRARY_PATH=/usr/local/lib RUSTFLAGS="-Zsanitizer=address" cargo fuzz run fuzz_target_block
```

### Coverage

Once fuzzed, a coverage report can be generated with (picking the `verify`
target as an example):
```
LD_LIBRARY_PATH=/usr/local/lib RUSTFLAGS="-C instrument-coverage" cargo fuzz coverage fuzz_target_verify
llvm-cov show \
  -format=html \
  -instr-profile=fuzz/coverage/fuzz_target_verify/coverage.profdata \
  target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/fuzz_target_verify \
  -show-line-counts-or-regions \
  -Xdemangler=rustfilt \
  -output-dir=coverage_report \
  -ignore-filename-regex="/rustc"
```

You may have to install the following tooling:
```
rustup component add llvm-tools-preview
cargo install rustfilt
```

