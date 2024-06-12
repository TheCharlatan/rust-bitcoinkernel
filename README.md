# rust-bitcoinkernel

:warning::construction: This library is still under contruction. :warning::construction:

`rust-bitcoinkernel` is a wrapper around
[libbitcoinkernel](https://github.com/bitcoin/bitcoin/issues/24303), a C++
library exposing Bitcoin Core's validation engine.

## Building

To build this library, first build the kernel library on my kernelApi branch. It
produces a C-compatible header that is used by this project to create the FFI.

```
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

```
PKG_CONFIG_PATH=/path/to/bitcoin/install_dir/lib/pkgconfig cargo b
```

And similarly for running it (env variables only required if not installed in
`/usr/local`):

```
PKG_CONFIG_PATH=/path/to/bitcoin/install_dir/lib/pkgconfig LD_LIBRARY_PATH=/path/to/bitcoin/install_dir/lib cargo run
```

