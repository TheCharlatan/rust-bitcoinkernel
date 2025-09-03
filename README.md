# rust-bitcoinkernel

:warning::construction: This library is still under contruction. :warning::construction:

`rust-bitcoinkernel` is a wrapper around
[libbitcoinkernel](https://github.com/bitcoin/bitcoin/issues/24303), a C++
library exposing Bitcoin Core's validation engine. It supports both validation
of blocks and transaction outputs as well as reading block data.

## Building

The library statically compiles the Bitcoin Core libbitcoinkernel library as
part of its build system. Currently it targets the kernelApi branch on the
following fork: https://github.com/TheCharlatan/bitcoin/tree/kernelApi.

Bitcoin Core is vendored as a `git subtree` in this project. The subtree can
be updated, or made to point at a different commit or branch in Bitcoin Core's
history with:

```
 git subtree pull --prefix libbitcoinkernel-sys/bitcoin https://github.com/TheCharlatan/bitcoin kernelApiNode --squash
```

To build this library, the usual Bitcoin Core build requirements, such as
`cmake` and a working C and C++ compiler are required. An installation of boost
is required as well. Consult the Bitcoin Core documentation for the required
dependencies. Once setup, run:

```bash
cargo b
```

## Examples

Examples for the usage of the library can be found in the `examples/` directory
and the `tests`. For now, the example binary implements a bare-bones silent
payments scanner.

## Testing

Due to the underlying Bitcoin Core logging system using global state, tests must be run sequentially:

```bash
cargo test -- --test-threads=1
```

## Fuzzing

Fuzzing is done with [cargo fuzz](https://github.com/rust-fuzz/cargo-fuzz).

There are currently three supported fuzzing targets: `fuzz_target_block`,
`fuzz_target_chainman` and `fuzz_target_verify`. The `chainman` target touches
the filesystem in `/tmp`. If `/tmp` is not already a tmpfs, the user should
create a tmpfs in `/tmp/rust_kernel_fuzz`.

To get fuzzing run (in this case the `verify` target):

```bash
cargo fuzz run fuzz_target_verify
```

Sanitizers can be turned on with e.g.
```bash
RUSTFLAGS="-Zsanitizer=address" cargo fuzz run fuzz_target_block
```

To get the sanitizer flags working in the libbitcoinkernel Bitcoin Core
library, the easiest way for now is to edit the `libbitcoinkernel-sys/build.rs`
flags.

### Coverage

Once fuzzed, a coverage report can be generated with (picking the `verify`
target as an example):
```
RUSTFLAGS="-C instrument-coverage" cargo fuzz coverage fuzz_target_verify
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

## Copyright

This project is copyright "The Bitcoin Kernel developers" which includes:
- TheCharlatan (2023-present) - Original author and maintainer  
- All contributors to this repository

For a complete list of contributors, see: `git log --format='%an' | sort -u`
