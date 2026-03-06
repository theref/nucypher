//! # ERC-20 Token Gate Fixture
//!
//! A practical demonstration: gate access based on ERC-20 token balance.
//! This is the most common DeFi access pattern.
//!
//! Flow:
//! 1. Encode `balanceOf(address)` calldata using ABI encoding
//! 2. Call `read_chain` with the token contract address
//! 3. Decode the uint256 result
//! 4. Compare against a minimum balance threshold
//! 5. Return true if balance >= threshold
//!
//! Context variables:
//! - `:tokenContract` — ERC-20 contract address
//! - `:userAddress` — address to check balance for
//! - `:minBalance` — minimum required balance (as decimal string)
//! - `:chainId` — chain ID (defaults to 1)

use extism_pdk::*;
use serde::Deserialize;

#[link(wasm_import_module = "taco")]
extern "C" {
    fn read_chain(chain_id: i32, contract_ptr: u64, calldata_ptr: u64) -> u64;
    fn get_context(key_ptr: u64) -> u64;
}

/// Helper: allocate a string in Extism memory and return the offset.
fn alloc_string(s: &str) -> u64 {
    let mem = Memory::from_bytes(s.as_bytes()).expect("failed to allocate");
    mem.offset()
}

/// Helper: allocate bytes in Extism memory and return the offset.
fn alloc_bytes(data: &[u8]) -> u64 {
    let mem = Memory::from_bytes(data).expect("failed to allocate");
    mem.offset()
}

/// Helper: read bytes from an Extism memory offset.
fn read_bytes_at(offset: u64) -> Option<Vec<u8>> {
    if offset == 0 {
        return None;
    }
    let mem = Memory::find(offset).expect("invalid memory offset");
    Some(mem.to_vec())
}

/// Helper: read a string from an Extism memory offset.
fn read_string_at(offset: u64) -> Option<String> {
    read_bytes_at(offset).map(|b| String::from_utf8(b).expect("invalid UTF-8"))
}

/// Helper: read a context variable by key.
fn read_context(key: &str) -> Option<String> {
    let key_offset = alloc_string(key);
    let result_offset = unsafe { get_context(key_offset) };
    read_string_at(result_offset)
}

/// Helper: read a context variable and parse the JSON-wrapped value.
fn read_context_string(key: &str) -> Option<String> {
    read_context(key).and_then(|s| serde_json::from_str::<String>(&s).ok())
}

/// Encode `balanceOf(address)` calldata.
///
/// ERC-20 balanceOf function selector: 0x70a08231
/// Followed by the address left-padded to 32 bytes.
fn encode_balance_of(address: &str) -> Vec<u8> {
    // Function selector: keccak256("balanceOf(address)")[:4] = 0x70a08231
    let selector: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];

    // Strip "0x" prefix from address and decode
    let addr_hex = address.strip_prefix("0x").unwrap_or(address);
    let addr_bytes = hex_decode(addr_hex);

    // ABI-encode: selector + 32-byte left-padded address
    let mut calldata = Vec::with_capacity(4 + 32);
    calldata.extend_from_slice(&selector);

    // Left-pad address to 32 bytes (address is 20 bytes)
    let padding = 32 - addr_bytes.len().min(32);
    for _ in 0..padding {
        calldata.push(0u8);
    }
    calldata.extend_from_slice(&addr_bytes[..addr_bytes.len().min(32)]);

    calldata
}

/// Decode a uint256 from ABI-encoded return data.
/// Returns the value as a u128 (sufficient for most token balances).
fn decode_uint256(data: &[u8]) -> u128 {
    if data.len() < 32 {
        return 0;
    }
    // uint256 is big-endian, take the last 16 bytes for u128
    // (handles balances up to ~3.4 * 10^38, far more than any token supply)
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&data[16..32]);
    u128::from_be_bytes(bytes)
}

/// Simple hex decoder
fn hex_decode(hex: &str) -> Vec<u8> {
    let hex = hex.trim();
    if hex.is_empty() {
        return vec![];
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
        .collect()
}

#[derive(Deserialize)]
struct Params {
    #[serde(rename = ":tokenContract")]
    token_contract: Option<String>,
    #[serde(rename = ":userAddress")]
    user_address: Option<String>,
    #[serde(rename = ":minBalance")]
    min_balance: Option<String>,
    #[serde(rename = ":chainId")]
    chain_id: Option<i32>,
}

#[plugin_fn]
pub fn evaluate(input: String) -> FnResult<Vec<u8>> {
    let params: Params = serde_json::from_str(&input).unwrap_or(Params {
        token_contract: None,
        user_address: None,
        min_balance: None,
        chain_id: None,
    });

    // Read parameters from input or context
    let token_contract = params
        .token_contract
        .or_else(|| read_context_string(":tokenContract"))
        .unwrap_or_default();

    let user_address = params
        .user_address
        .or_else(|| read_context_string(":userAddress"))
        .unwrap_or_default();

    let min_balance_str = params
        .min_balance
        .or_else(|| read_context_string(":minBalance"))
        .unwrap_or_else(|| "0".to_string());

    let chain_id = params
        .chain_id
        .or_else(|| {
            read_context(":chainId")
                .and_then(|s| serde_json::from_str::<i32>(&s).ok())
        })
        .unwrap_or(1);

    // Parse minimum balance
    let min_balance: u128 = min_balance_str.parse().unwrap_or(0);

    // Encode balanceOf(userAddress) calldata
    let calldata = encode_balance_of(&user_address);

    // Call read_chain
    let contract_ptr = alloc_string(&token_contract);
    let calldata_ptr = alloc_bytes(&calldata);
    let result_ptr = unsafe { read_chain(chain_id, contract_ptr, calldata_ptr) };

    // Decode the result
    let result_bytes = match read_bytes_at(result_ptr) {
        Some(bytes) => bytes,
        None => return Ok(vec![0u8]), // Call failed
    };

    let balance = decode_uint256(&result_bytes);

    // Return true if balance >= minimum
    if balance >= min_balance {
        Ok(vec![1u8])
    } else {
        Ok(vec![0u8])
    }
}

fn main() {}
