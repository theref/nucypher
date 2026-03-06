//! # Verify JWT Token Fixture
//!
//! Demonstrates calling the `verify_jwt` host function to validate
//! a JWT token. This fixture:
//!
//! 1. Reads ":token", ":issuer", ":audience" from context
//! 2. Calls `verify_jwt(token_ptr, issuer_ptr, audience_ptr)`
//! 3. Returns true if the JWT is valid
//!
//! This pattern is used for: OAuth-based gating, SSO integration,
//! third-party identity verification, etc.

use extism_pdk::*;
use serde::Deserialize;

// Import verify_jwt from the "taco" namespace.
// Signature: (token_ptr: i64, issuer_ptr: i64, audience_ptr: i64) -> i32
// Returns 1 if valid, 0 if invalid.
// If issuer_ptr or audience_ptr is 0, those checks are skipped.
#[link(wasm_import_module = "taco")]
extern "C" {
    fn verify_jwt(token_ptr: u64, issuer_ptr: u64, audience_ptr: u64) -> i32;
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

/// Helper: read a context variable by key.
fn read_context(key: &str) -> Option<String> {
    let key_offset = alloc_string(key);
    let result_offset = unsafe { get_context(key_offset) };
    read_string_at(result_offset)
}

#[derive(Deserialize)]
struct Params {
    #[serde(rename = ":token")]
    token: Option<String>,
    #[serde(rename = ":issuer")]
    issuer: Option<String>,
    #[serde(rename = ":audience")]
    audience: Option<String>,
}

#[plugin_fn]
pub fn evaluate(input: String) -> FnResult<Vec<u8>> {
    // Parse parameters
    let params: Params = serde_json::from_str(&input).unwrap_or(Params {
        token: None,
        issuer: None,
        audience: None,
    });

    // Get JWT token
    let token = params
        .token
        .or_else(|| {
            read_context(":token")
                .and_then(|s| serde_json::from_str::<String>(&s).ok())
        })
        .unwrap_or_default();

    if token.is_empty() {
        return Ok(vec![0u8]); // No token = fail
    }

    // Get issuer (required by the host function)
    let issuer = params
        .issuer
        .or_else(|| {
            read_context(":issuer")
                .and_then(|s| serde_json::from_str::<String>(&s).ok())
        });

    // Get audience (optional)
    let audience = params
        .audience
        .or_else(|| {
            read_context(":audience")
                .and_then(|s| serde_json::from_str::<String>(&s).ok())
        });

    // Allocate strings in Extism memory
    let token_ptr = alloc_string(&token);

    // For issuer and audience, pass 0 if absent
    let issuer_ptr = match &issuer {
        Some(iss) => alloc_string(iss),
        None => 0u64,
    };

    let audience_ptr = match &audience {
        Some(aud) => alloc_string(aud),
        None => 0u64,
    };

    // Call the host function
    let is_valid = unsafe { verify_jwt(token_ptr, issuer_ptr, audience_ptr) };

    // Return result
    if is_valid == 1 {
        Ok(vec![1u8])
    } else {
        Ok(vec![0u8])
    }
}

fn main() {}
