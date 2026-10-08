#!/bin/sh
# Build the browser wallet core (crates/gnb-wallet-wasm) for wasm32-wasip1 and
# copy it to site/wallet/gnb_wallet.wasm.
#
# Needs: the rustup target wasm32-wasip1 and a wasi-sdk (clang with the wasm32
# backend and the WASI sysroot), e.g. https://github.com/WebAssembly/wasi-sdk
#   WASI_SDK=~/.local/wasi-sdk scripts/build-wallet-wasm.sh
set -eu
W=${WASI_SDK:-$HOME/.local/wasi-sdk}
export WASI_SDK_DIR="$W/share/wasi-sysroot"
export CC_wasm32_wasip1="$W/bin/clang" AR_wasm32_wasip1="$W/bin/llvm-ar"
export CFLAGS_wasm32_wasip1="--target=wasm32-wasip1 --sysroot=$W/share/wasi-sysroot"
cd "$(dirname "$0")/.."
cargo build --release -p gnb-wallet-wasm --target wasm32-wasip1
cp target/wasm32-wasip1/release/gnb_wallet_wasm.wasm site/wallet/gnb_wallet.wasm
shasum -a 256 site/wallet/gnb_wallet.wasm
