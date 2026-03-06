//! # Check Block Timestamp Fixture
//!
//! Demonstrates calling the `block_timestamp` host function and comparing
//! the result against a threshold. This fixture:
//!
//! 1. Reads ":chainId" from context (defaults to 1)
//! 2. Reads ":minTimestamp" from context (the threshold)
//! 3. Calls `block_timestamp(chain_id)` to get the latest block timestamp
//! 4. Returns true if timestamp >= minTimestamp
//!
//! This pattern is used for: time-locked access, expiry checks,
//! scheduled content releases, etc.

use extism_pdk::*;
use serde::Deserialize;

// Import block_timestamp from the "taco" namespace.
// Signature: (chain_id: i32) -> i64 (timestamp, or 0 on error)
#[link(wasm_import_module = "taco")]
extern "C" {
    fn block_timestamp(chain_id: i32) -> i64;
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

#[derive(Deserialize)]
struct Params {
    #[serde(rename = ":chainId")]
    chain_id: Option<i32>,
    #[serde(rename = ":minTimestamp")]
    min_timestamp: Option<i64>,
}

#[plugin_fn]
pub fn evaluate(input: String) -> FnResult<Vec<u8>> {
    // Parse parameters from input JSON
    let params: Params = serde_json::from_str(&input).unwrap_or(Params {
        chain_id: None,
        min_timestamp: None,
    });

    // Get chain ID (default to 1 = Ethereum mainnet)
    let chain_id = params
        .chain_id
        .or_else(|| {
            read_context(":chainId")
                .and_then(|s| serde_json::from_str::<i32>(&s).ok())
        })
        .unwrap_or(1);

    // Get minimum timestamp threshold
    let min_timestamp = params
        .min_timestamp
        .or_else(|| {
            read_context(":minTimestamp")
                .and_then(|s| serde_json::from_str::<i64>(&s).ok())
        })
        .unwrap_or(0);

    // Call the host function to get the current block timestamp
    let current_timestamp = unsafe { block_timestamp(chain_id) };

    // If timestamp is 0, the call failed (no provider, etc.)
    if current_timestamp == 0 {
        return Ok(vec![0u8]);
    }

    // Return true if current timestamp >= minimum threshold
    if current_timestamp >= min_timestamp {
        Ok(vec![1u8])
    } else {
        Ok(vec![0u8])
    }
}

fn main() {}
