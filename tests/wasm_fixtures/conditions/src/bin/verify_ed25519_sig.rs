//! # Verify Ed25519 Signature Fixture
//!
//! Demonstrates calling the `verify_ed25519` host function to validate
//! an Ed25519 signature (e.g. from Discord interaction webhooks).
//!
//! Context variables:
//! - `:message` — raw message bytes (hex-encoded)
//! - `:signature` — 64-byte Ed25519 signature (hex-encoded)
//! - `:publicKey` — 32-byte Ed25519 public key (hex-encoded)

use extism_pdk::*;
use serde::Deserialize;

#[link(wasm_import_module = "taco")]
extern "C" {
    fn verify_ed25519(msg_ptr: u64, sig_ptr: u64, key_ptr: u64) -> i32;
    fn get_context(key_ptr: u64) -> u64;
}

fn alloc_string(s: &str) -> u64 {
    let mem = Memory::from_bytes(s.as_bytes()).expect("failed to allocate");
    mem.offset()
}

fn alloc_bytes(data: &[u8]) -> u64 {
    let mem = Memory::from_bytes(data).expect("failed to allocate");
    mem.offset()
}

fn read_string_at(offset: u64) -> Option<String> {
    if offset == 0 {
        return None;
    }
    let mem = Memory::find(offset).expect("invalid memory offset");
    Some(String::from_utf8(mem.to_vec()).expect("invalid UTF-8"))
}

fn read_context(key: &str) -> Option<String> {
    let key_offset = alloc_string(key);
    let result_offset = unsafe { get_context(key_offset) };
    read_string_at(result_offset)
}

fn read_context_string(key: &str) -> Option<String> {
    read_context(key).and_then(|s| serde_json::from_str::<String>(&s).ok())
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
    #[serde(rename = ":message")]
    message: Option<String>,
    #[serde(rename = ":signature")]
    signature: Option<String>,
    #[serde(rename = ":publicKey")]
    public_key: Option<String>,
}

#[plugin_fn]
pub fn evaluate(input: String) -> FnResult<Vec<u8>> {
    let params: Params = serde_json::from_str(&input).unwrap_or(Params {
        message: None,
        signature: None,
        public_key: None,
    });

    let message_hex = params
        .message
        .or_else(|| read_context_string(":message"))
        .unwrap_or_default();

    let signature_hex = params
        .signature
        .or_else(|| read_context_string(":signature"))
        .unwrap_or_default();

    let public_key_hex = params
        .public_key
        .or_else(|| read_context_string(":publicKey"))
        .unwrap_or_default();

    let message_bytes = hex_decode(&message_hex);
    let signature_bytes = hex_decode(&signature_hex);
    let public_key_bytes = hex_decode(&public_key_hex);

    let msg_ptr = alloc_bytes(&message_bytes);
    let sig_ptr = alloc_bytes(&signature_bytes);
    let key_ptr = alloc_bytes(&public_key_bytes);

    let is_valid = unsafe { verify_ed25519(msg_ptr, sig_ptr, key_ptr) };

    if is_valid == 1 {
        Ok(vec![1u8])
    } else {
        Ok(vec![0u8])
    }
}

fn main() {}
