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
./autogen.sh
./configure --with-experimental-kernel-lib --enable-shared --prefix ~/bitcoin/install_dir
make install -j 24
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
`/usr/local`):

```bash
PKG_CONFIG_PATH=/path/to/bitcoin/install_dir/lib/pkgconfig LD_LIBRARY_PATH=/path/to/bitcoin/install_dir/lib cargo run
```

## Fuzzing

Fuzzing is done with [cargo fuzz](https://github.com/rust-fuzz/cargo-fuzz).

There are currently two supported fuzzing targets: `fuzz_target_chainman` and
`fuzz_target_verify`. The `chainman` target requires the user to first mount a
temporary ramdisk:

```bash
sudo mkdir -p /mnt/tmp/kernel
sudo mount -t tmpfs -o size=4g tmpfs /mnt/tmp/kernel
```

Once done the user can unmount the ramdisk again with:

```bash
sudo umount /mnt/tmp/kernel
```

To get fuzzing run (in this case the `verify` target):

```bash
LD_LIBRARY_PATH=/usr/local/lib cargo fuzz run fuzz_target_verify
```

