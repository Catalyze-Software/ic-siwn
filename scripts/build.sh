cargo test candid -p ic_siwn_provider
cargo build -p ic_siwn_provider --release --target wasm32-unknown-unknown
gzip -c target/wasm32-unknown-unknown/release/ic_siwn_provider.wasm > target/wasm32-unknown-unknown/release/ic_siwn_provider.wasm.gz

mkdir -p wasm

# Copy wasm
cp target/wasm32-unknown-unknown/release/ic_siwn_provider.wasm.gz wasm/ic_siwn_provider.wasm.gz
