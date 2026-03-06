"""Tests for the WASM evaluator — sandbox, fuel, memory, timeouts (Extism)."""

import pytest

from nucypher.policy.conditions.wasm.evaluator import (
    EvaluationTimeout,
    FuelExhausted,
    InvalidWasmModule,
    MemoryLimitExceeded,
    WasmEvaluationError,
    WasmEvaluator,
)
from tests.unit.conditions.wasm.conftest import (
    EXTISM_IMPORTS,
    OUTPUT_BOOL,
    WAT_OUT_OF_BOUNDS,
    WAT_UNREACHABLE,
)


class TestBasicEvaluation:
    """Test basic WASM evaluation."""

    def test_always_true(self, wasm_always_true):
        evaluator = WasmEvaluator()
        assert evaluator.evaluate(wasm_always_true) is True

    def test_always_false(self, wasm_always_false):
        evaluator = WasmEvaluator()
        assert evaluator.evaluate(wasm_always_false) is False

    def test_no_memory_module(self, wat2wasm):
        """Module without memory export still works."""
        wasm = wat2wasm(f"""
        (module
          {EXTISM_IMPORTS}
          {OUTPUT_BOOL}
          (func (export "evaluate")
            i32.const 1
            call $output_bool
          )
        )
        """)
        evaluator = WasmEvaluator()
        assert evaluator.evaluate(wasm) is True

    def test_context_passed_as_input(self, wat2wasm):
        """Context JSON is passed as Extism input and has length > 2."""
        wasm = wat2wasm(f"""
        (module
          {EXTISM_IMPORTS}
          (memory (export "memory") 1)
          {OUTPUT_BOOL}
          (func (export "evaluate")
            ;; Check if input length > 2 (more than just "{{}}")
            call $input_length
            i64.const 2
            i64.gt_u
            ;; i64.gt_u already returns i32
            call $output_bool
          )
        )
        """)
        evaluator = WasmEvaluator()
        # With context containing data
        assert evaluator.evaluate(wasm, context={"key": "value"}) is True
        # Empty context is "{}" which is 2 bytes, not > 2
        assert evaluator.evaluate(wasm, context={}) is False

    def test_non_one_return_is_false(self, wat2wasm):
        """Any output byte other than 1 is treated as False."""
        for val in [0, 2, 42, 255]:
            wasm = wat2wasm(f"""
            (module
              {EXTISM_IMPORTS}
              (memory (export "memory") 1)
              (func $output_byte (param $val i32)
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
              (func (export "evaluate")
                i32.const {val}
                call $output_byte
              )
            )
            """)
            evaluator = WasmEvaluator()
            result = evaluator.evaluate(wasm)
            if val == 1:
                assert result is True
            else:
                assert result is False, f"Expected False for output byte {val}"

    def test_empty_output_is_false(self, wat2wasm):
        """Module that produces no output is treated as False."""
        wasm = wat2wasm(f"""
        (module
          {EXTISM_IMPORTS}
          (memory (export "memory") 1)
          (func (export "evaluate")
            ;; Do nothing, no output_set
            nop
          )
        )
        """)
        evaluator = WasmEvaluator()
        assert evaluator.evaluate(wasm) is False


class TestSandbox:
    """Test sandbox enforcement — fuel, memory, timeout."""

    def test_fuel_exhaustion(self, wasm_infinite_loop):
        """Module that loops exhausts fuel budget."""
        evaluator = WasmEvaluator(fuel=100, timeout_ms=5000)
        with pytest.raises((FuelExhausted, EvaluationTimeout)):
            evaluator.evaluate(wasm_infinite_loop)

    def test_timeout(self, wasm_infinite_loop):
        """Module that loops hits wall-clock timeout."""
        evaluator = WasmEvaluator(fuel=10_000_000_000, timeout_ms=500)
        with pytest.raises((EvaluationTimeout, FuelExhausted)):
            evaluator.evaluate(wasm_infinite_loop)

    def test_memory_limit_enforced(self, wat2wasm):
        """Memory growth is bounded by Extism manifest memory limits.

        Extism traps with OOM when memory.grow exceeds max_pages,
        rather than letting memory.grow return -1 gracefully.
        """
        wasm = wat2wasm(f"""
        (module
          {EXTISM_IMPORTS}
          (memory (export "memory") 1 256)
          {OUTPUT_BOOL}
          (func (export "evaluate")
            ;; Try to grow memory by 200 pages (12.8 MB)
            i32.const 200
            memory.grow
            ;; memory.grow returns -1 on failure
            i32.const -1
            i32.eq
            call $output_bool
          )
        )
        """)
        # Small max_pages — growth of 200 pages triggers OOM trap
        evaluator = WasmEvaluator(max_pages=2)
        with pytest.raises(MemoryLimitExceeded):
            evaluator.evaluate(wasm)

    def test_custom_fuel_budget(self, wasm_always_true):
        """Custom fuel budget is respected for simple modules."""
        evaluator = WasmEvaluator(fuel=100_000)
        assert evaluator.evaluate(wasm_always_true) is True


class TestErrorHandling:
    """Test error handling for malformed/invalid modules."""

    def test_invalid_bytes(self):
        evaluator = WasmEvaluator()
        with pytest.raises(InvalidWasmModule, match="Failed to compile"):
            evaluator.evaluate(b"not wasm bytecode")

    def test_empty_bytes(self):
        evaluator = WasmEvaluator()
        with pytest.raises(InvalidWasmModule):
            evaluator.evaluate(b"")

    def test_missing_evaluate_export(self, wasm_no_evaluate):
        evaluator = WasmEvaluator()
        with pytest.raises(InvalidWasmModule, match="missing required export"):
            evaluator.evaluate(wasm_no_evaluate)

    def test_trap_on_unreachable(self, wat2wasm):
        """Module that hits unreachable instruction raises error."""
        wasm = wat2wasm(WAT_UNREACHABLE)
        evaluator = WasmEvaluator()
        with pytest.raises(WasmEvaluationError):
            evaluator.evaluate(wasm)

    def test_out_of_bounds_memory_access(self, wat2wasm):
        """Module that accesses out-of-bounds memory raises error."""
        wasm = wat2wasm(WAT_OUT_OF_BOUNDS)
        evaluator = WasmEvaluator()
        with pytest.raises(WasmEvaluationError):
            evaluator.evaluate(wasm)


class TestModuleCache:
    """Test compiled module caching."""

    def test_cache_populated(self, wasm_always_true):
        """First evaluation compiles and caches the module."""
        evaluator = WasmEvaluator()
        assert len(evaluator._compiled_cache) == 0
        evaluator.evaluate(wasm_always_true)
        assert len(evaluator._compiled_cache) == 1

    def test_cache_reused(self, wasm_always_true):
        """Second evaluation of same bytecode reuses cached compilation."""
        evaluator = WasmEvaluator()
        evaluator.evaluate(wasm_always_true)
        evaluator.evaluate(wasm_always_true)
        assert len(evaluator._compiled_cache) == 1

    def test_different_modules_cached_separately(
        self, wasm_always_true, wasm_always_false
    ):
        """Different bytecodes get separate cache entries."""
        evaluator = WasmEvaluator()
        evaluator.evaluate(wasm_always_true)
        evaluator.evaluate(wasm_always_false)
        assert len(evaluator._compiled_cache) == 2
