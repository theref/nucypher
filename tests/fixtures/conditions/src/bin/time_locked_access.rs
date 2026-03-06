//! # Time-Locked Access Fixture
//!
//! Demonstrates time-based access control using `block_timestamp`.
//! Access is only granted within a specific time window.
//!
//! Flow:
//! 1. Read `:notBefore` and `:notAfter` timestamps from context
//! 2. Call `block_timestamp` for the specified chain
//! 3. Return true if notBefore <= timestamp <= notAfter
//!
//! Context variables:
//! - `:notBefore` — earliest allowed timestamp (inclusive, 0 = no lower bound)
//! - `:notAfter` — latest allowed timestamp (inclusive, 0 = no upper bound)
//! - `:chainId` — chain ID (defaults to 1)

use extism_pdk::*;
use serde::Deserialize;

#[link(wasm_import_module = "taco")]
extern "C" {
    fn block_timestamp(chain_id: i32) -> i64;
    fn get_context(key_ptr: u64) -> u64;
}

fn alloc_string(s: &str) -> u64 {
    let mem = Memory::from_bytes(s.as_bytes()).expect("failed to allocate");
    mem.offset()
}

fn read_string_at(offset: u64) -> Option<String> {
    if offset == 0 {
        return None;
    }
    let mem = Memory::find(offset).expect("invalid memory offset");
    let bytes = mem.to_vec();
    Some(String::from_utf8(bytes).expect("invalid UTF-8"))
}

fn read_context(key: &str) -> Option<String> {
    let key_offset = alloc_string(key);
    let result_offset = unsafe { get_context(key_offset) };
    read_string_at(result_offset)
}

#[derive(Deserialize)]
struct Params {
    #[serde(rename = ":notBefore")]
    not_before: Option<i64>,
    #[serde(rename = ":notAfter")]
    not_after: Option<i64>,
    #[serde(rename = ":chainId")]
    chain_id: Option<i32>,
}

#[plugin_fn]
pub fn evaluate(input: String) -> FnResult<Vec<u8>> {
    let params: Params = serde_json::from_str(&input).unwrap_or(Params {
        not_before: None,
        not_after: None,
        chain_id: None,
    });

    let chain_id = params
        .chain_id
        .or_else(|| {
            read_context(":chainId")
                .and_then(|s| serde_json::from_str::<i32>(&s).ok())
        })
        .unwrap_or(1);

    let not_before = params
        .not_before
        .or_else(|| {
            read_context(":notBefore")
                .and_then(|s| serde_json::from_str::<i64>(&s).ok())
        })
        .unwrap_or(0); // 0 = no lower bound

    let not_after = params
        .not_after
        .or_else(|| {
            read_context(":notAfter")
                .and_then(|s| serde_json::from_str::<i64>(&s).ok())
        })
        .unwrap_or(0); // 0 = no upper bound

    // Get current block timestamp
    let now = unsafe { block_timestamp(chain_id) };

    // If timestamp is 0, the call failed
    if now == 0 {
        return Ok(vec![0u8]);
    }

    // Check time window
    let after_start = not_before == 0 || now >= not_before;
    let before_end = not_after == 0 || now <= not_after;

    if after_start && before_end {
        Ok(vec![1u8])
    } else {
        Ok(vec![0u8])
    }
}

fn main() {}
