"""Tests for WASM host functions (Extism)."""

from nucypher.policy.conditions.wasm.evaluator import WasmEvaluator
from tests.unit.conditions.wasm.conftest import (
    EXTISM_IMPORTS,
    MAKE_EXTISM_STRING,
    OUTPUT_BOOL,
)


class TestGetContext:
    """Test the get_context host function."""

    def test_key_found(self, wasm_context_check):
        evaluator = WasmEvaluator()
        result = evaluator.evaluate(wasm_context_check, context={":testKey": "hello"})
        assert result is True

    def test_key_not_found(self, wasm_context_check):
        evaluator = WasmEvaluator()
        result = evaluator.evaluate(wasm_context_check, context={":otherKey": "hello"})
        assert result is False

    def test_empty_context(self, wasm_context_check):
        evaluator = WasmEvaluator()
        result = evaluator.evaluate(wasm_context_check, context={})
        assert result is False

    def test_no_context(self, wasm_context_check):
        evaluator = WasmEvaluator()
        result = evaluator.evaluate(wasm_context_check)
        assert result is False

    def test_context_value_types(self, wat2wasm):
        """Context values of different types are serialized correctly."""
        wasm = wat2wasm(f"""
        (module
          {EXTISM_IMPORTS}
          (import "taco" "get_context" (func $get_context (param i64) (result i64)))
          (memory (export "memory") 1)
          (data (i32.const 1024) ":val")
          {MAKE_EXTISM_STRING}
          {OUTPUT_BOOL}

          (func (export "evaluate")
            (local $key_offset i64)
            (local $result_offset i64)
            ;; Copy ":val" to Extism memory
            i32.const 1024
            i32.const 4
            call $make_extism_string
            local.set $key_offset
            ;; Call get_context
            local.get $key_offset
            call $get_context
            local.set $result_offset
            ;; Return 1 if non-zero (found)
            local.get $result_offset
            i64.eqz
            i32.eqz
            call $output_bool
          )
        )
        """)
        evaluator = WasmEvaluator()

        # String value
        assert evaluator.evaluate(wasm, context={":val": "hello"}) is True
        # Integer value
        assert evaluator.evaluate(wasm, context={":val": 42}) is True
        # List value
        assert evaluator.evaluate(wasm, context={":val": [1, 2, 3]}) is True
        # Dict value
        assert evaluator.evaluate(wasm, context={":val": {"a": 1}}) is True
        # Boolean value
        assert evaluator.evaluate(wasm, context={":val": True}) is True

    def test_context_reads_actual_value(self, wat2wasm):
        """Verify the context value bytes are actually correct."""
        # This WAT reads :num via get_context, then reads the first byte
        # of the returned Extism memory to check the value.
        # For value 42, JSON is "42" -> first byte is '4' (ASCII 52)
        wasm = wat2wasm(f"""
        (module
          {EXTISM_IMPORTS}
          (import "extism:host/env" "load_u8" (func $load_u8 (param i64) (result i32)))
          (import "taco" "get_context" (func $get_context (param i64) (result i64)))
          (memory (export "memory") 1)
          (data (i32.const 1024) ":num")
          {MAKE_EXTISM_STRING}
          {OUTPUT_BOOL}

          (func (export "evaluate")
            (local $key_offset i64)
            (local $result_offset i64)
            (local $result_len i64)
            ;; Copy ":num" to Extism memory
            i32.const 1024
            i32.const 4
            call $make_extism_string
            local.set $key_offset
            ;; Call get_context
            local.get $key_offset
            call $get_context
            local.set $result_offset
            ;; Check if result is non-zero
            local.get $result_offset
            i64.eqz
            (if (then
              i32.const 0
              call $output_bool
              return
            ))
            ;; Read first byte from Extism memory
            local.get $result_offset
            call $load_u8
            ;; Check if it's '4' (ASCII 52) — first char of "42"
            i32.const 52
            i32.eq
            call $output_bool
          )
        )
        """)
        evaluator = WasmEvaluator()
        assert evaluator.evaluate(wasm, context={":num": 42}) is True
        assert evaluator.evaluate(wasm, context={":num": 99}) is False


class TestBlockTimestamp:
    """Test the block_timestamp host function (stubbed — needs Web3 provider)."""

    def test_no_provider_returns_zero(self, wat2wasm):
        """Without providers, block_timestamp returns 0."""
        wasm = wat2wasm(f"""
        (module
          {EXTISM_IMPORTS}
          (import "taco" "block_timestamp" (func $block_timestamp (param i32) (result i64)))
          (memory (export "memory") 1)
          {OUTPUT_BOOL}

          (func (export "evaluate")
            ;; Get timestamp for chain 1
            i32.const 1
            call $block_timestamp
            ;; Check if timestamp > 0 (it won't be without a provider)
            i64.const 0
            i64.gt_u
            ;; i64.gt_u already returns i32
            call $output_bool
          )
        )
        """)
        evaluator = WasmEvaluator()
        result = evaluator.evaluate(wasm)
        assert result is False


class TestReadChain:
    """Test the read_chain host function (stubbed — needs Web3 provider)."""

    def test_no_provider_returns_error(self, wat2wasm):
        """Without providers, read_chain returns 0 (null ptr)."""
        wasm = wat2wasm(f"""
        (module
          {EXTISM_IMPORTS}
          (import "taco" "read_chain" (func $read_chain (param i32 i64 i64) (result i64)))
          (memory (export "memory") 1)
          ;; Contract address and calldata in linear memory
          (data (i32.const 1024) "0x0000000000000000000000000000000000000001")
          (data (i32.const 2048) "\\70\\a0\\82\\31")
          {MAKE_EXTISM_STRING}
          {OUTPUT_BOOL}

          (func (export "evaluate")
            (local $contract_ptr i64)
            (local $calldata_ptr i64)
            (local $result_ptr i64)
            ;; Copy contract address to Extism memory
            i32.const 1024
            i32.const 42
            call $make_extism_string
            local.set $contract_ptr
            ;; Copy calldata to Extism memory
            i32.const 2048
            i32.const 4
            call $make_extism_string
            local.set $calldata_ptr
            ;; Call read_chain
            i32.const 1  ;; chain_id
            local.get $contract_ptr
            local.get $calldata_ptr
            call $read_chain
            local.set $result_ptr
            ;; Check if result is 0 (error)
            local.get $result_ptr
            i64.eqz
            ;; Return 0 (condition should fail when no provider)
            i32.eqz
            i32.eqz
            i32.eqz
            call $output_bool
          )
        )
        """)
        evaluator = WasmEvaluator()
        result = evaluator.evaluate(wasm)
        assert result is False  # No providers, read_chain fails


class TestHttpGet:
    """Test the http_get host function."""

    def test_non_https_rejected(self, wat2wasm):
        """HTTP (non-HTTPS) URLs are rejected."""
        wasm = wat2wasm(f"""
        (module
          {EXTISM_IMPORTS}
          (import "taco" "http_get" (func $http_get (param i64) (result i64)))
          (memory (export "memory") 1)
          ;; Non-HTTPS URL
          (data (i32.const 1024) "http://example.com/api")
          {MAKE_EXTISM_STRING}
          {OUTPUT_BOOL}

          (func (export "evaluate")
            (local $url_ptr i64)
            (local $result_ptr i64)
            ;; Copy URL to Extism memory
            i32.const 1024
            i32.const 22
            call $make_extism_string
            local.set $url_ptr
            ;; Call http_get
            local.get $url_ptr
            call $http_get
            local.set $result_ptr
            ;; Should return 0 for non-HTTPS
            local.get $result_ptr
            i64.eqz
            ;; i64.eqz already returns i32
            call $output_bool
          )
        )
        """)
        evaluator = WasmEvaluator()
        result = evaluator.evaluate(wasm)
        assert result is True  # 0 (null) means rejected, check returns true


class TestVerifyEcdsa:
    """Test the verify_ecdsa host function."""

    def test_invalid_signature_returns_false(self, wat2wasm):
        """Invalid signature returns 0 (false)."""
        wasm = wat2wasm(f"""
        (module
          {EXTISM_IMPORTS}
          (import "taco" "verify_ecdsa" (func $verify_ecdsa (param i64 i64 i64) (result i32)))
          (memory (export "memory") 1)
          ;; Dummy message
          (data (i32.const 1024) "hello")
          ;; Dummy signature (65 bytes of zeros)
          (data (i32.const 2048) "\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00\\00")
          ;; Dummy address
          (data (i32.const 3072) "0x0000000000000000000000000000000000000001")
          {MAKE_EXTISM_STRING}
          {OUTPUT_BOOL}

          (func (export "evaluate")
            (local $msg_ptr i64)
            (local $sig_ptr i64)
            (local $addr_ptr i64)
            ;; Copy data to Extism memory
            i32.const 1024
            i32.const 5
            call $make_extism_string
            local.set $msg_ptr
            i32.const 2048
            i32.const 65
            call $make_extism_string
            local.set $sig_ptr
            i32.const 3072
            i32.const 42
            call $make_extism_string
            local.set $addr_ptr
            ;; Call verify_ecdsa
            local.get $msg_ptr
            local.get $sig_ptr
            local.get $addr_ptr
            call $verify_ecdsa
            ;; Should return 0 for invalid sig
            call $output_bool
          )
        )
        """)
        evaluator = WasmEvaluator()
        result = evaluator.evaluate(wasm)
        assert result is False


class TestVerifyJwt:
    """Test the verify_jwt host function."""

    def test_no_issuer_returns_false(self, wat2wasm):
        """JWT verification without issuer returns 0."""
        wasm = wat2wasm(f"""
        (module
          {EXTISM_IMPORTS}
          (import "taco" "verify_jwt" (func $verify_jwt (param i64 i64 i64) (result i32)))
          (memory (export "memory") 1)
          ;; Dummy token
          (data (i32.const 1024) "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig")
          {MAKE_EXTISM_STRING}
          {OUTPUT_BOOL}

          (func (export "evaluate")
            (local $token_ptr i64)
            ;; Copy token to Extism memory
            i32.const 1024
            i32.const 50
            call $make_extism_string
            local.set $token_ptr
            ;; Call verify_jwt with token, 0 (no issuer), 0 (no audience)
            local.get $token_ptr
            i64.const 0  ;; no issuer
            i64.const 0  ;; no audience
            call $verify_jwt
            ;; Should return 0 without issuer
            call $output_bool
          )
        )
        """)
        evaluator = WasmEvaluator()
        result = evaluator.evaluate(wasm)
        assert result is False
