//! # Fetch HTTPS Fixture
//!
//! Demonstrates calling the `http_get` host function to fetch data
//! from an HTTPS endpoint. This fixture:
//!
//! 1. Reads ":url" from context
//! 2. Calls `http_get(url_ptr)` to fetch the response
//! 3. Parses the JSON response and checks for a specific field
//! 4. Returns true if the response contains `"allowed": true`
//!
//! This pattern is used for: off-chain authorization checks,
//! API-based access control, oracle data verification, etc.

use extism_pdk::*;
use serde::Deserialize;

// Import http_get from the "taco" namespace.
// Signature: (url_ptr: i64) -> i64 (response body ptr, or 0 on error)
#[link(wasm_import_module = "taco")]
extern "C" {
    fn http_get(url_ptr: u64) -> u64;
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

/// Expected JSON response shape
#[derive(Deserialize)]
struct ApiResponse {
    allowed: Option<bool>,
}

#[derive(Deserialize)]
struct Params {
    #[serde(rename = ":url")]
    url: Option<String>,
}

#[plugin_fn]
pub fn evaluate(input: String) -> FnResult<Vec<u8>> {
    // Get the URL from input or context
    let params: Params = serde_json::from_str(&input).unwrap_or(Params { url: None });

    let url = params
        .url
        .or_else(|| {
            read_context(":url")
                .and_then(|s| serde_json::from_str::<String>(&s).ok())
        })
        .unwrap_or_default();

    if url.is_empty() {
        return Ok(vec![0u8]); // No URL provided
    }

    // Allocate URL in Extism memory and call the host function
    let url_ptr = alloc_string(&url);
    let response_ptr = unsafe { http_get(url_ptr) };

    // Check if we got a response
    let response_body = match read_string_at(response_ptr) {
        Some(body) => body,
        None => return Ok(vec![0u8]), // Request failed
    };

    // Parse the JSON response
    let api_response: ApiResponse = match serde_json::from_str(&response_body) {
        Ok(r) => r,
        Err(_) => return Ok(vec![0u8]), // Invalid JSON
    };

    // Return true if "allowed" is true
    match api_response.allowed {
        Some(true) => Ok(vec![1u8]),
        _ => Ok(vec![0u8]),
    }
}

fn main() {}
