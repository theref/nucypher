//! # UserOp Batch Validator Fixture
//!
//! **Key demonstration of WASM conditions over the old JSON DSL.**
//!
//! This fixture validates ERC-4337 UserOperation `executeBatch` calldata —
//! something that was impossible with the old JSON condition DSL because it
//! required parsing nested dynamic ABI-encoded data.
//!
//! ## Why WASM matters here
//!
//! The old JSON DSL could only do simple comparisons on single return values.
//! It could NOT:
//! - Parse complex ABI-encoded calldata with dynamic arrays
//! - Apply conditional logic across multiple decoded fields
//! - Validate that ALL targets in a batch are on an allowlist
//! - Check that total value across a batch doesn't exceed a cap
//!
//! With WASM, we can write arbitrary validation logic in Rust, compiled to
//! a sandboxed module that runs deterministically on every node.
//!
//! ## What this fixture does
//!
//! Given `executeBatch(address[] targets, uint256[] values, bytes[] data)`:
//! 1. Decodes the batch calldata (ABI-encoded dynamic arrays)
//! 2. Validates that ALL target addresses are in the allowlist
//! 3. Validates that the total ETH value doesn't exceed a cap
//! 4. Returns true only if ALL validations pass
//!
//! ## Context variables
//! - `:calldata` — hex-encoded executeBatch calldata
//! - `:allowedTargets` — JSON array of allowed target addresses
//! - `:maxTotalValue` — maximum total value in wei (decimal string)

use extism_pdk::*;
use serde::Deserialize;

#[link(wasm_import_module = "taco")]
extern "C" {
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

fn read_context_string(key: &str) -> Option<String> {
    read_context(key).and_then(|s| serde_json::from_str::<String>(&s).ok())
}

fn read_context_json<T: serde::de::DeserializeOwned>(key: &str) -> Option<T> {
    read_context(key).and_then(|s| serde_json::from_str::<T>(&s).ok())
}

// ── ABI Decoding Helpers ──────────────────────────────────────────────
//
// executeBatch(address[] targets, uint256[] values, bytes[] data)
// Function selector: we skip the first 4 bytes.
//
// ABI layout for 3 dynamic params:
//   [0..32]   offset to targets array
//   [32..64]  offset to values array
//   [64..96]  offset to data array
//
// Each dynamic array:
//   [offset..offset+32]  length (N)
//   [offset+32..offset+32+N*32]  elements (padded to 32 bytes each)
//
// For bytes[], each element is itself a dynamic offset + length + data.

/// Read a uint256 (32 bytes big-endian) as u128 from ABI data.
fn read_uint256_as_u128(data: &[u8], offset: usize) -> u128 {
    if offset + 32 > data.len() {
        return 0;
    }
    // Take the lower 16 bytes (sufficient for most values)
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&data[offset + 16..offset + 32]);
    u128::from_be_bytes(bytes)
}

/// Read a uint256 as usize (for offsets and lengths).
fn read_uint256_as_usize(data: &[u8], offset: usize) -> usize {
    read_uint256_as_u128(data, offset) as usize
}

/// Decode an address from a 32-byte ABI word (last 20 bytes).
fn decode_abi_address(data: &[u8], offset: usize) -> String {
    if offset + 32 > data.len() {
        return String::new();
    }
    let addr_bytes = &data[offset + 12..offset + 32];
    let hex: String = addr_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    format!("0x{}", hex)
}

/// Decode the executeBatch calldata.
/// Returns (targets, values) or None if decoding fails.
fn decode_execute_batch(calldata: &[u8]) -> Option<(Vec<String>, Vec<u128>)> {
    // Skip the 4-byte function selector
    if calldata.len() < 4 {
        return None;
    }
    let data = &calldata[4..];

    // Read offsets for the 3 dynamic arrays
    if data.len() < 96 {
        return None;
    }
    let targets_offset = read_uint256_as_usize(data, 0);
    let values_offset = read_uint256_as_usize(data, 32);
    // let _data_offset = read_uint256_as_usize(data, 64); // not needed for this check

    // Decode targets array
    let num_targets = read_uint256_as_usize(data, targets_offset);
    let mut targets = Vec::with_capacity(num_targets);
    for i in 0..num_targets {
        let addr = decode_abi_address(data, targets_offset + 32 + i * 32);
        targets.push(addr);
    }

    // Decode values array
    let num_values = read_uint256_as_usize(data, values_offset);
    let mut values = Vec::with_capacity(num_values);
    for i in 0..num_values {
        let val = read_uint256_as_u128(data, values_offset + 32 + i * 32);
        values.push(val);
    }

    Some((targets, values))
}

fn hex_decode(hex: &str) -> Vec<u8> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex).trim();
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
    #[serde(rename = ":calldata")]
    calldata: Option<String>,
    #[serde(rename = ":allowedTargets")]
    allowed_targets: Option<Vec<String>>,
    #[serde(rename = ":maxTotalValue")]
    max_total_value: Option<String>,
}

#[plugin_fn]
pub fn evaluate(input: String) -> FnResult<Vec<u8>> {
    let params: Params = serde_json::from_str(&input).unwrap_or(Params {
        calldata: None,
        allowed_targets: None,
        max_total_value: None,
    });

    // Get calldata (hex-encoded)
    let calldata_hex = params
        .calldata
        .or_else(|| read_context_string(":calldata"))
        .unwrap_or_default();

    // Get allowlist
    let allowed_targets: Vec<String> = params
        .allowed_targets
        .or_else(|| read_context_json::<Vec<String>>(":allowedTargets"))
        .unwrap_or_default();

    // Get max total value
    let max_total_value_str = params
        .max_total_value
        .or_else(|| read_context_string(":maxTotalValue"))
        .unwrap_or_else(|| "0".to_string());
    let max_total_value: u128 = max_total_value_str.parse().unwrap_or(0);

    // Decode the calldata
    let calldata_bytes = hex_decode(&calldata_hex);
    let (targets, values) = match decode_execute_batch(&calldata_bytes) {
        Some((t, v)) => (t, v),
        None => return Ok(vec![0u8]), // Failed to decode = reject
    };

    // Normalize allowed targets to lowercase for comparison
    let allowed_lower: Vec<String> = allowed_targets
        .iter()
        .map(|a| a.to_lowercase())
        .collect();

    // Validation 1: ALL targets must be in the allowlist
    for target in &targets {
        if !allowed_lower.contains(&target.to_lowercase()) {
            return Ok(vec![0u8]); // Unauthorized target
        }
    }

    // Validation 2: Total value must not exceed cap (if cap > 0)
    if max_total_value > 0 {
        let total_value: u128 = values.iter().sum();
        if total_value > max_total_value {
            return Ok(vec![0u8]); // Value cap exceeded
        }
    }

    // All checks passed
    Ok(vec![1u8])
}

fn main() {}
