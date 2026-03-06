//! # Read Chain Balance Fixture
//!
//! Demonstrates calling the `read_chain` host function to execute an
//! on-chain eth_call. This fixture:
//!
//! 1. Reads the contract address from context (":contractAddress")
//! 2. Reads the calldata from context (":calldata") — hex-encoded
//! 3. Reads the chain ID from context (":chainId")
//! 4. Calls `read_chain(chain_id, contract_ptr, calldata_ptr)`
//! 5. Returns true if the result is non-empty (call succeeded)
//!
//! This pattern is used for: ERC-20 balanceOf, allowance checks,
//! arbitrary view function calls, etc.

use extism_pdk::*;
use serde::Deserialize;

// Import the `read_chain` host function from the "taco" namespace.
// Signature: (chain_id: i32, contract_ptr: i64, calldata_ptr: i64) -> i64
// The i64 values are Extism PTR offsets into managed memory.
#[link(wasm_import_module = "taco")]
extern "C" {
    fn read_chain(chain_id: i32, contract_ptr: u64, calldata_ptr: u64) -> u64;
}

// Import get_context to read context variables.
#[link(wasm_import_module = "taco")]
extern "C" {
    fn get_context(key_ptr: u64) -> u64;
}

/// Helper: allocate a string in Extism memory and return the offset.
fn alloc_string(s: &str) -> u64 {
    let mem = Memory::from_bytes(s.as_bytes()).expect("failed to allocate");
    mem.offset()
}

/// Helper: read a string from an Extism memory offset.
/// Returns None if the offset is 0 (null/not found).
fn read_string_at(offset: u64) -> Option<String> {
    if offset == 0 {
        return None;
    }
    let mem = Memory::find(offset).expect("invalid memory offset");
    let bytes = mem.to_vec();
    Some(String::from_utf8(bytes).expect("invalid UTF-8"))
}

/// Helper: read a context variable by key. Returns the raw JSON string.
fn read_context(key: &str) -> Option<String> {
    let key_offset = alloc_string(key);
    let result_offset = unsafe { get_context(key_offset) };
    read_string_at(result_offset)
}

/// Input parameters (passed as JSON via Extism input, but we use context instead)
#[derive(Deserialize)]
struct Params {
    #[serde(rename = ":contractAddress")]
    contract_address: Option<String>,
    #[serde(rename = ":calldata")]
    calldata: Option<String>,
    #[serde(rename = ":chainId")]
    chain_id: Option<i32>,
}

#[plugin_fn]
pub fn evaluate(input: String) -> FnResult<Vec<u8>> {
    // Parse parameters from input JSON (context is passed as input)
    let params: Params = serde_json::from_str(&input).unwrap_or(Params {
        contract_address: None,
        calldata: None,
        chain_id: None,
    });

    // Get contract address — try input first, then context
    let contract_address = params
        .contract_address
        .or_else(|| {
            read_context(":contractAddress")
                .and_then(|s| serde_json::from_str::<String>(&s).ok())
        })
        .unwrap_or_default();

    // Get calldata (hex-encoded bytes)
    let calldata_hex = params
        .calldata
        .or_else(|| {
            read_context(":calldata")
                .and_then(|s| serde_json::from_str::<String>(&s).ok())
        })
        .unwrap_or_default();

    // Get chain ID
    let chain_id = params
        .chain_id
        .or_else(|| {
            read_context(":chainId")
                .and_then(|s| serde_json::from_str::<i32>(&s).ok())
        })
        .unwrap_or(1);

    // Strip "0x" prefix from calldata if present, then decode hex to bytes
    let calldata_clean = calldata_hex.strip_prefix("0x").unwrap_or(&calldata_hex);
    let calldata_bytes = hex_decode(calldata_clean);

    // Allocate contract address and calldata in Extism memory
    let contract_ptr = alloc_string(&contract_address);
    let calldata_mem = Memory::from_bytes(&calldata_bytes).expect("failed to alloc calldata");
    let calldata_ptr = calldata_mem.offset();

    // Call the host function
    let result_ptr = unsafe { read_chain(chain_id, contract_ptr, calldata_ptr) };

    // Return true (0x01) if we got a non-null result, false (0x00) otherwise
    if result_ptr != 0 {
        Ok(vec![1u8])
    } else {
        Ok(vec![0u8])
    }
}

/// Simple hex decoder (no external crate needed)
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

fn main() {}
