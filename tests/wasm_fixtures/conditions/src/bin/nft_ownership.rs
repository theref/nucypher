//! # NFT Ownership Fixture
//!
//! Demonstrates gating access based on ERC-721 NFT ownership.
//!
//! Flow:
//! 1. Encode `ownerOf(tokenId)` calldata
//! 2. Call `read_chain` on the NFT contract
//! 3. Decode the returned address
//! 4. Compare against the requester's address
//! 5. Return true if the requester owns the token
//!
//! Context variables:
//! - `:nftContract` — ERC-721 contract address
//! - `:tokenId` — token ID to check ownership of
//! - `:userAddress` — address claiming ownership
//! - `:chainId` — chain ID (defaults to 1)

use extism_pdk::*;
use serde::Deserialize;

#[link(wasm_import_module = "taco")]
extern "C" {
    fn read_chain(chain_id: i32, contract_ptr: u64, calldata_ptr: u64) -> u64;
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

fn read_bytes_at(offset: u64) -> Option<Vec<u8>> {
    if offset == 0 {
        return None;
    }
    let mem = Memory::find(offset).expect("invalid memory offset");
    Some(mem.to_vec())
}

fn read_string_at(offset: u64) -> Option<String> {
    read_bytes_at(offset).map(|b| String::from_utf8(b).expect("invalid UTF-8"))
}

fn read_context(key: &str) -> Option<String> {
    let key_offset = alloc_string(key);
    let result_offset = unsafe { get_context(key_offset) };
    read_string_at(result_offset)
}

fn read_context_string(key: &str) -> Option<String> {
    read_context(key).and_then(|s| serde_json::from_str::<String>(&s).ok())
}

/// Encode `ownerOf(uint256)` calldata.
///
/// Function selector: keccak256("ownerOf(uint256)")[:4] = 0x6352211e
/// Followed by the tokenId as a 32-byte big-endian uint256.
fn encode_owner_of(token_id: u128) -> Vec<u8> {
    let selector: [u8; 4] = [0x63, 0x52, 0x21, 0x1e];

    let mut calldata = Vec::with_capacity(4 + 32);
    calldata.extend_from_slice(&selector);

    // uint256: 16 bytes of zero padding + 16 bytes of u128 big-endian
    calldata.extend_from_slice(&[0u8; 16]);
    calldata.extend_from_slice(&token_id.to_be_bytes());

    calldata
}

/// Decode an address from ABI-encoded return data.
/// Returns lowercase hex string with "0x" prefix.
fn decode_address(data: &[u8]) -> String {
    if data.len() < 32 {
        return String::new();
    }
    // Address is the last 20 bytes of the 32-byte word
    let addr_bytes = &data[12..32];
    let hex: String = addr_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    format!("0x{}", hex)
}

#[derive(Deserialize)]
struct Params {
    #[serde(rename = ":nftContract")]
    nft_contract: Option<String>,
    #[serde(rename = ":tokenId")]
    token_id: Option<String>,
    #[serde(rename = ":userAddress")]
    user_address: Option<String>,
    #[serde(rename = ":chainId")]
    chain_id: Option<i32>,
}

#[plugin_fn]
pub fn evaluate(input: String) -> FnResult<Vec<u8>> {
    let params: Params = serde_json::from_str(&input).unwrap_or(Params {
        nft_contract: None,
        token_id: None,
        user_address: None,
        chain_id: None,
    });

    let nft_contract = params
        .nft_contract
        .or_else(|| read_context_string(":nftContract"))
        .unwrap_or_default();

    let token_id_str = params
        .token_id
        .or_else(|| read_context_string(":tokenId"))
        .unwrap_or_else(|| "0".to_string());

    let user_address = params
        .user_address
        .or_else(|| read_context_string(":userAddress"))
        .unwrap_or_default();

    let chain_id = params
        .chain_id
        .or_else(|| {
            read_context(":chainId")
                .and_then(|s| serde_json::from_str::<i32>(&s).ok())
        })
        .unwrap_or(1);

    // Parse token ID
    let token_id: u128 = token_id_str.parse().unwrap_or(0);

    // Encode ownerOf(tokenId) calldata
    let calldata = encode_owner_of(token_id);

    // Call read_chain
    let contract_ptr = alloc_string(&nft_contract);
    let calldata_ptr = alloc_bytes(&calldata);
    let result_ptr = unsafe { read_chain(chain_id, contract_ptr, calldata_ptr) };

    // Decode the owner address
    let result_bytes = match read_bytes_at(result_ptr) {
        Some(bytes) => bytes,
        None => return Ok(vec![0u8]),
    };

    let owner = decode_address(&result_bytes);

    // Case-insensitive comparison of addresses
    let owns_token = owner.to_lowercase() == user_address.to_lowercase();

    if owns_token {
        Ok(vec![1u8])
    } else {
        Ok(vec![0u8])
    }
}

fn main() {}
