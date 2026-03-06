"""
WASM Host Functions (Extism)

Seven host functions registered via Extism's host_fn decorator:
- get_context(key_ptr) -> value_ptr
- read_chain(args_ptr) -> result_ptr
- http_get(url_ptr) -> result_ptr
- verify_jwt(args_ptr) -> i32
- verify_ecdsa(args_ptr) -> i32
- verify_ed25519(msg_ptr, sig_ptr, key_ptr) -> i32
- block_timestamp(chain_id: i32) -> i64

Host functions use Extism's managed memory model:
- Input: i64 offsets into Extism memory (allocated by guest via extism_alloc)
- Output: i64 offsets into Extism memory (allocated by host via plugin.alloc)
- Context/providers passed via plugin.host_context()

The host_context dict has the shape:
    {"providers": ConditionProviderManager, "context": dict}
"""

import json
from typing import List

import extism

from nucypher.policy.conditions.utils import ConditionProviderManager
from nucypher.utilities.logging import Logger

log = Logger("wasm-host")

# Limits
HTTP_RESPONSE_SIZE_LIMIT = 1 * 1024 * 1024  # 1 MB
HTTP_TIMEOUT = 10.0  # seconds


def _read_extism_string(plugin: extism.CurrentPlugin, ptr_val: extism.Val) -> str:
    """Read a UTF-8 string from Extism managed memory."""
    mem = plugin.memory_at_offset(ptr_val)
    return bytes(plugin.memory(mem)[:]).decode("utf-8")


def _read_extism_bytes(plugin: extism.CurrentPlugin, ptr_val: extism.Val) -> bytes:
    """Read raw bytes from Extism managed memory."""
    mem = plugin.memory_at_offset(ptr_val)
    return bytes(plugin.memory(mem)[:])


def _write_extism_bytes(plugin: extism.CurrentPlugin, data: bytes) -> int:
    """Write bytes to Extism managed memory. Returns the offset."""
    mem = plugin.alloc(len(data))
    plugin.memory(mem)[:] = data
    return mem.offset


def _get_host_context(plugin: extism.CurrentPlugin):
    """Extract providers and context from host_context."""
    ctx = plugin.host_context()
    if ctx is None:
        ctx = {}
    providers = ctx.get("providers", ConditionProviderManager(providers={}))
    context = ctx.get("context", {})
    return providers, context


# --- Host function implementations ---


@extism.host_fn(
    name="get_context",
    namespace="taco",
    signature=(
        [extism.ValType.PTR],  # key_ptr
        [extism.ValType.PTR],  # result_ptr (0 if not found)
    ),
)
def host_get_context(plugin, params, results, *user_data):
    """
    Retrieve a context parameter passed in with the decryption request.

    Input: Extism PTR to key string (e.g. ":userAddress")
    Output: Extism PTR to JSON-serialized value, or 0 if not found.
    """
    try:
        key = _read_extism_string(plugin, params[0])
        _, context = _get_host_context(plugin)
        value = context.get(key)
        if value is None:
            results[0] = extism.Val(extism.ValType.PTR, 0)
            return

        value_bytes = json.dumps(value).encode("utf-8")
        offset = _write_extism_bytes(plugin, value_bytes)
        results[0] = extism.Val(extism.ValType.PTR, offset)

    except Exception as e:
        log.warn(f"get_context failed: {e}")
        results[0] = extism.Val(extism.ValType.PTR, 0)


@extism.host_fn(
    name="read_chain",
    namespace="taco",
    signature=(
        [
            extism.ValType.I32,
            extism.ValType.PTR,
            extism.ValType.PTR,
        ],  # chain_id, contract_ptr, calldata_ptr
        [extism.ValType.PTR],  # result_ptr (0 on error)
    ),
)
def host_read_chain(plugin, params, results, *user_data):
    """
    Execute an eth_call against a specified chain.

    Input:
        chain_id (i32), contract_address_ptr (Extism PTR), calldata_ptr (Extism PTR)
    Output:
        Extism PTR to result bytes, or 0 on error.
    """
    try:
        chain_id = params[0].value
        contract_address = _read_extism_string(plugin, params[1])
        calldata = _read_extism_bytes(plugin, params[2])

        providers, _ = _get_host_context(plugin)

        from web3 import Web3

        def _execute(w3: Web3) -> bytes:
            result = w3.eth.call(
                {
                    "to": Web3.to_checksum_address(contract_address),
                    "data": calldata,
                }
            )
            return bytes(result)

        result_bytes = providers.exec_web3_call(
            chain_id=chain_id,
            fn=_execute,
        )

        offset = _write_extism_bytes(plugin, result_bytes)
        results[0] = extism.Val(extism.ValType.PTR, offset)

    except Exception as e:
        log.warn(f"read_chain failed: {e}")
        results[0] = extism.Val(extism.ValType.PTR, 0)


@extism.host_fn(
    name="http_get",
    namespace="taco",
    signature=(
        [extism.ValType.PTR],  # url_ptr
        [extism.ValType.PTR],  # result_ptr (0 on error)
    ),
)
def host_http_get(plugin, params, results, *user_data):
    """
    Make an HTTPS GET request and return the response body.

    Input: Extism PTR to URL string
    Output: Extism PTR to response body bytes, or 0 on error.
    Enforces: HTTPS only, response size cap, timeout.
    """
    try:
        url = _read_extism_string(plugin, params[0])

        # Security: HTTPS only
        if not url.startswith("https://"):
            log.warn(f"http_get rejected non-HTTPS URL: {url[:50]}")
            results[0] = extism.Val(extism.ValType.PTR, 0)
            return

        import requests

        response = requests.get(
            url,
            timeout=HTTP_TIMEOUT,
            stream=True,
        )
        response.raise_for_status()

        content = response.content[:HTTP_RESPONSE_SIZE_LIMIT]
        offset = _write_extism_bytes(plugin, content)
        results[0] = extism.Val(extism.ValType.PTR, offset)

    except Exception as e:
        log.warn(f"http_get failed: {e}")
        results[0] = extism.Val(extism.ValType.PTR, 0)


@extism.host_fn(
    name="verify_jwt",
    namespace="taco",
    signature=(
        [
            extism.ValType.PTR,
            extism.ValType.PTR,
            extism.ValType.PTR,
        ],  # token, issuer, audience
        [extism.ValType.I32],  # 1 if valid, 0 if invalid
    ),
)
def host_verify_jwt(plugin, params, results, *user_data):
    """
    Verify a JWT token's signature and claims.

    Input: token_ptr, issuer_ptr, audience_ptr (Extism PTRs; 0 means absent)
    Output: 1 if valid, 0 if invalid.
    """
    try:
        token = _read_extism_string(plugin, params[0])
        issuer = (
            _read_extism_string(plugin, params[1]) if params[1].value != 0 else None
        )
        audience = (
            _read_extism_string(plugin, params[2]) if params[2].value != 0 else None
        )

        if not issuer:
            results[0] = extism.Val(extism.ValType.I32, 0)
            return

        import jwt as pyjwt
        from jwt import PyJWKClient

        jwks_url = f"{issuer.rstrip('/')}/.well-known/jwks.json"
        jwk_client = PyJWKClient(jwks_url)
        signing_key = jwk_client.get_signing_key_from_jwt(token)

        pyjwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            issuer=issuer,
            audience=audience,
        )

        results[0] = extism.Val(extism.ValType.I32, 1)

    except Exception as e:
        log.warn(f"verify_jwt failed: {e}")
        results[0] = extism.Val(extism.ValType.I32, 0)


@extism.host_fn(
    name="verify_ecdsa",
    namespace="taco",
    signature=(
        [extism.ValType.PTR, extism.ValType.PTR, extism.ValType.PTR],  # msg, sig, addr
        [extism.ValType.I32],  # 1 if valid, 0 if invalid
    ),
)
def host_verify_ecdsa(plugin, params, results, *user_data):
    """
    Verify an ECDSA signature against an expected Ethereum address.

    Input: msg_ptr, sig_ptr, addr_ptr (Extism PTRs)
    Output: 1 if valid, 0 if invalid.
    """
    try:
        message = _read_extism_bytes(plugin, params[0])
        signature = _read_extism_bytes(plugin, params[1])
        expected_address = _read_extism_string(plugin, params[2])

        from nucypher.crypto.utils import verify_eip_191

        is_valid = verify_eip_191(
            address=expected_address,
            message=message,
            signature=signature,
        )
        results[0] = extism.Val(extism.ValType.I32, 1 if is_valid else 0)

    except Exception as e:
        log.warn(f"verify_ecdsa failed: {e}")
        results[0] = extism.Val(extism.ValType.I32, 0)


@extism.host_fn(
    name="verify_ed25519",
    namespace="taco",
    signature=(
        [extism.ValType.PTR, extism.ValType.PTR, extism.ValType.PTR],  # msg, sig, key
        [extism.ValType.I32],  # 1 if valid, 0 if invalid
    ),
)
def host_verify_ed25519(plugin, params, results, *user_data):
    """
    Verify an Ed25519 signature.

    Input: msg_ptr, sig_ptr, key_ptr (Extism PTRs)
        - msg: raw message bytes
        - sig: 64-byte Ed25519 signature
        - key: 32-byte Ed25519 public key
    Output: 1 if valid, 0 if invalid.
    """
    try:
        message = _read_extism_bytes(plugin, params[0])
        signature = _read_extism_bytes(plugin, params[1])
        public_key_bytes = _read_extism_bytes(plugin, params[2])

        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey

        verify_key = VerifyKey(public_key_bytes)
        verify_key.verify(message, signature)
        results[0] = extism.Val(extism.ValType.I32, 1)

    except (BadSignatureError, Exception) as e:
        log.warn(f"verify_ed25519 failed: {e}")
        results[0] = extism.Val(extism.ValType.I32, 0)


@extism.host_fn(
    name="block_timestamp",
    namespace="taco",
    signature=(
        [extism.ValType.I32],  # chain_id
        [extism.ValType.I64],  # timestamp (0 on error)
    ),
)
def host_block_timestamp(plugin, params, results, *user_data):
    """
    Return the latest block timestamp for a given chain.

    Input: chain_id (i32)
    Output: timestamp as i64, or 0 on error.
    """
    try:
        chain_id = params[0].value
        providers, _ = _get_host_context(plugin)

        from web3 import Web3

        def _get_timestamp(w3: Web3) -> int:
            block = w3.eth.get_block("latest")
            return block["timestamp"]

        timestamp = providers.exec_web3_call(
            chain_id=chain_id,
            fn=_get_timestamp,
        )
        results[0] = extism.Val(extism.ValType.I64, timestamp)

    except Exception as e:
        log.warn(f"block_timestamp failed: {e}")
        results[0] = extism.Val(extism.ValType.I64, 0)


# --- Collect all host functions ---

ALL_HOST_FUNCTIONS: List[extism.Function] = [
    host_get_context,
    host_read_chain,
    host_http_get,
    host_verify_jwt,
    host_verify_ecdsa,
    host_verify_ed25519,
    host_block_timestamp,
]
