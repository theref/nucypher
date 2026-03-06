//! # Verify ECDSA Signature Fixture
//!
//! Demonstrates calling the `verify_ecdsa` host function to verify
//! an Ethereum ECDSA signature. This fixture:
//!
//! 1. Reads ":message", ":signature", ":address" from context
//! 2. Calls `verify_ecdsa(msg_ptr, sig_ptr, addr_ptr)`
//! 3. Returns true if the signature is valid for the given address
//!
//! This pattern is used for: proving wallet ownership, signed messages
//! as access credentials, delegated authorization, etc.

use extism_pdk::*;
use serde::Deserialize;

// Import verify_ecdsa from the "taco" namespace.
// Signature: (msg_ptr: i64, sig_ptr: i64, addr_ptr: i64) -> i32
// Returns 1 if valid, 0 if invalid.
#[link(wasm_import_module = "taco")]
extern "C" {
    fn verify_ecdsa(msg_ptr: u64, sig_ptr: u64, addr_ptr: u64) -> i32;
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

/// Helper: allocate bytes in Extism memory and return the offset.
fn alloc_bytes(data: &[u8]) -> u64 {
    let mem = Memory::from_bytes(data).expect("failed to allocate");
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

/// Helper: read a context variable by key.
fn read_context(key: &str) -> Option<String> {
    let key_offset = alloc_string(key);
    let result_offset = unsafe { get_context(key_offset) };
    read_string_at(result_offset)
}

/// Simple hex decoder
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
    #[serde(rename = ":message")]
    message: Option<String>,
    #[serde(rename = ":signature")]
    signature: Option<String>,
    #[serde(rename = ":address")]
    address: Option<String>,
}

#[plugin_fn]
pub fn evaluate(input: String) -> FnResult<Vec<u8>> {
    // Parse parameters
    let params: Params = serde_json::from_str(&input).unwrap_or(Params {
        message: None,
        signature: None,
        address: None,
    });

    // Get message (raw bytes)
    let message = params
        .message
        .or_else(|| {
            read_context(":message")
                .and_then(|s| serde_json::from_str::<String>(&s).ok())
        })
        .unwrap_or_default();

    // Get signature (hex-encoded)
    let signature_hex = params
        .signature
        .or_else(|| {
            read_context(":signature")
                .and_then(|s| serde_json::from_str::<String>(&s).ok())
        })
        .unwrap_or_default();

    // Get expected address
    let address = params
        .address
        .or_else(|| {
            read_context(":address")
                .and_then(|s| serde_json::from_str::<String>(&s).ok())
        })
        .unwrap_or_default();

    // Decode signature from hex to bytes
    let signature_bytes = hex_decode(&signature_hex);

    // Allocate in Extism memory
    let msg_ptr = alloc_bytes(message.as_bytes());
    let sig_ptr = alloc_bytes(&signature_bytes);
    let addr_ptr = alloc_string(&address);

    // Call the host function
    let is_valid = unsafe { verify_ecdsa(msg_ptr, sig_ptr, addr_ptr) };

    // Return result: 1 = valid signature, 0 = invalid
    if is_valid == 1 {
        Ok(vec![1u8])
    } else {
        Ok(vec![0u8])
    }
}

fn main() {}
