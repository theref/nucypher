#!/bin/bash
set -e
cd "$(dirname "$0")"
cargo build --target wasm32-unknown-unknown --release
mkdir -p out

# All fixture binaries
BINS=(
    always_true
    always_false
    check_context
    read_chain_balance
    check_block_timestamp
    fetch_https
    verify_ecdsa_sig
    verify_jwt_token
    userop_batch_validator
    erc20_token_gate
    nft_ownership
    time_locked_access
)

for bin in "${BINS[@]}"; do
    cp target/wasm32-unknown-unknown/release/$bin.wasm out/
done

echo "Built $(ls out/*.wasm | wc -l) fixtures to out/"
