"""Fixtures for WASM condition tests (Extism PDK conventions)."""

import pytest
import wasmtime


@pytest.fixture
def wat2wasm():
    """Helper to compile WAT to WASM bytes."""

    def _compile(wat: str) -> bytes:
        return bytes(wasmtime.wat2wasm(wat))

    return _compile


# --- Extism PDK helpers used across WAT modules ---

# Common imports needed by all Extism PDK modules
EXTISM_IMPORTS = """
  (import "extism:host/env" "alloc" (func $alloc (param i64) (result i64)))
  (import "extism:host/env" "store_u8" (func $store_u8 (param i64 i32)))
  (import "extism:host/env" "output_set" (func $output_set (param i64 i64)))
  (import "extism:host/env" "length" (func $length (param i64) (result i64)))
  (import "extism:host/env" "input_length" (func $input_length (result i64)))
"""

# Helper function to copy from linear memory to Extism memory
MAKE_EXTISM_STRING = """
  (func $make_extism_string (param $ptr i32) (param $len i32) (result i64)
    (local $offset i64)
    (local $i i32)
    local.get $len
    i64.extend_i32_u
    call $alloc
    local.set $offset
    (block $done
      (loop $copy
        local.get $i
        local.get $len
        i32.ge_u
        br_if $done
        local.get $offset
        local.get $i
        i64.extend_i32_u
        i64.add
        local.get $ptr
        local.get $i
        i32.add
        i32.load8_u
        call $store_u8
        local.get $i
        i32.const 1
        i32.add
        local.set $i
        br $copy
      )
    )
    local.get $offset
  )
"""

# Helper to set a single-byte output (0 or 1)
OUTPUT_BOOL = """
  (func $output_bool (param $val i32)
    (local $offset i64)
    i64.const 1
    call $alloc
    local.set $offset
    local.get $offset
    local.get $val
    call $store_u8
    local.get $offset
    i64.const 1
    call $output_set
  )
"""


# --- Common WAT modules ---

WAT_ALWAYS_TRUE = f"""
(module
  {EXTISM_IMPORTS}
  (memory (export "memory") 1)
  {OUTPUT_BOOL}
  (func (export "evaluate")
    i32.const 1
    call $output_bool
  )
)
"""

WAT_ALWAYS_FALSE = f"""
(module
  {EXTISM_IMPORTS}
  (memory (export "memory") 1)
  {OUTPUT_BOOL}
  (func (export "evaluate")
    i32.const 0
    call $output_bool
  )
)
"""

WAT_INFINITE_LOOP = f"""
(module
  {EXTISM_IMPORTS}
  (memory (export "memory") 1)
  (func (export "evaluate")
    (loop $inf br $inf)
  )
)
"""

WAT_NO_EVALUATE = f"""
(module
  {EXTISM_IMPORTS}
  (memory (export "memory") 1)
  {OUTPUT_BOOL}
  (func (export "other")
    i32.const 1
    call $output_bool
  )
)
"""

WAT_NO_MEMORY = f"""
(module
  {EXTISM_IMPORTS}
  {OUTPUT_BOOL}
  (func (export "evaluate")
    i32.const 1
    call $output_bool
  )
)
"""

WAT_CONTEXT_CHECK = f"""
(module
  {EXTISM_IMPORTS}
  (import "taco" "get_context" (func $get_context (param i64) (result i64)))
  (memory (export "memory") 1)
  (data (i32.const 1024) ":testKey")
  {MAKE_EXTISM_STRING}
  {OUTPUT_BOOL}

  (func (export "evaluate")
    (local $key_offset i64)
    (local $result_offset i64)
    ;; Copy ":testKey" from linear memory to Extism memory
    i32.const 1024
    i32.const 8
    call $make_extism_string
    local.set $key_offset
    ;; Call get_context
    local.get $key_offset
    call $get_context
    local.set $result_offset
    ;; Return 1 if result is non-zero (key found), 0 otherwise
    local.get $result_offset
    i64.eqz
    i32.eqz
    call $output_bool
  )
)
"""

WAT_READS_CONTEXT_LENGTH = f"""
(module
  {EXTISM_IMPORTS}
  (memory (export "memory") 1)
  {OUTPUT_BOOL}

  (func (export "evaluate")
    ;; Check if input length > 2 (more than just "{{}}")
    call $input_length
    i64.const 2
    i64.gt_u
    i32.wrap_i64
    call $output_bool
  )
)
"""

# WAT that grows memory beyond limits
WAT_MEMORY_HOG = f"""
(module
  {EXTISM_IMPORTS}
  (memory (export "memory") 1 256)
  {OUTPUT_BOOL}

  (func (export "evaluate")
    ;; Try to grow memory by 200 pages (12.8 MB)
    i32.const 200
    memory.grow
    ;; memory.grow returns -1 on failure, previous page count on success
    i32.const -1
    i32.eq
    ;; Return 1 if growth failed (limit enforced), 0 if it succeeded
    call $output_bool
  )
)
"""

WAT_UNREACHABLE = f"""
(module
  {EXTISM_IMPORTS}
  (memory (export "memory") 1)
  (func (export "evaluate")
    unreachable
  )
)
"""

WAT_OUT_OF_BOUNDS = f"""
(module
  {EXTISM_IMPORTS}
  (memory (export "memory") 1)
  (func (export "evaluate")
    ;; Try to read past end of 64KB memory
    i32.const 100000
    i32.load
    drop
  )
)
"""


@pytest.fixture
def wasm_always_true(wat2wasm):
    return wat2wasm(WAT_ALWAYS_TRUE)


@pytest.fixture
def wasm_always_false(wat2wasm):
    return wat2wasm(WAT_ALWAYS_FALSE)


@pytest.fixture
def wasm_infinite_loop(wat2wasm):
    return wat2wasm(WAT_INFINITE_LOOP)


@pytest.fixture
def wasm_no_evaluate(wat2wasm):
    return wat2wasm(WAT_NO_EVALUATE)


@pytest.fixture
def wasm_context_check(wat2wasm):
    return wat2wasm(WAT_CONTEXT_CHECK)
