"""Tests for WasmCondition and ConditionLingo."""

import pytest

from nucypher.policy.conditions.exceptions import (
    InvalidCondition,
    InvalidConditionLingo,
)
from nucypher.policy.conditions.lingo import ConditionLingo
from nucypher.policy.conditions.utils import (
    ConditionEvalError,
    evaluate_condition_lingo,
)
from nucypher.policy.conditions.wasm.conditions import WasmCondition


class TestWasmCondition:
    """Test WasmCondition creation and verification."""

    def test_create(self, wasm_always_true):
        cond = WasmCondition(wasm_bytes=wasm_always_true, name="test")
        assert cond.condition_type == "wasm"
        assert cond.name == "test"
        assert len(cond.id) == 16

    def test_verify_true(self, wasm_always_true):
        cond = WasmCondition(wasm_bytes=wasm_always_true)
        result, value = cond.verify()
        assert result is True
        assert value == 1

    def test_verify_false(self, wasm_always_false):
        cond = WasmCondition(wasm_bytes=wasm_always_false)
        result, value = cond.verify()
        assert result is False
        assert value == 0

    def test_verify_with_context(self, wasm_context_check):
        cond = WasmCondition(wasm_bytes=wasm_context_check)
        result, _ = cond.verify(**{":testKey": "hello"})
        assert result is True

        result, _ = cond.verify()
        assert result is False

    def test_empty_bytes_rejected(self):
        with pytest.raises(InvalidCondition, match="cannot be empty"):
            WasmCondition(wasm_bytes=b"")

    def test_invalid_magic_rejected(self):
        with pytest.raises(InvalidCondition, match="magic number"):
            WasmCondition(wasm_bytes=b"not wasm")

    def test_bytearray_accepted(self, wasm_always_true):
        """bytearray (from wat2wasm) is accepted alongside bytes."""
        cond = WasmCondition(wasm_bytes=bytearray(wasm_always_true))
        assert cond.wasm_bytes == wasm_always_true


class TestWasmConditionSerialization:
    """Test serialization/deserialization round-trips."""

    def test_to_dict(self, wasm_always_true):
        cond = WasmCondition(wasm_bytes=wasm_always_true, name="test")
        d = cond.to_dict()
        assert d["conditionType"] == "wasm"
        assert "wasmBytecode" in d
        assert d["name"] == "test"

    def test_from_dict(self, wasm_always_true):
        cond = WasmCondition(wasm_bytes=wasm_always_true, name="test")
        d = cond.to_dict()
        cond2 = WasmCondition.from_dict(d)
        assert cond == cond2

    def test_to_json_from_json(self, wasm_always_true):
        cond = WasmCondition(wasm_bytes=wasm_always_true)
        j = cond.to_json()
        cond2 = WasmCondition.from_json(j)
        assert cond == cond2

    def test_to_bytes_from_bytes(self, wasm_always_true):
        cond = WasmCondition(wasm_bytes=wasm_always_true)
        b = cond.to_bytes()
        cond2 = WasmCondition.from_bytes(b)
        assert cond == cond2

    def test_from_dict_wrong_type(self):
        with pytest.raises(InvalidCondition, match="Expected conditionType"):
            WasmCondition.from_dict({"conditionType": "contract"})

    def test_from_dict_missing_bytecode(self):
        with pytest.raises(InvalidCondition, match="Missing wasmBytecode"):
            WasmCondition.from_dict({"conditionType": "wasm"})

    def test_from_dict_invalid_base64(self):
        with pytest.raises(InvalidCondition, match="Invalid base64"):
            WasmCondition.from_dict(
                {
                    "conditionType": "wasm",
                    "wasmBytecode": "not-valid-base64!!!",
                }
            )

    def test_equality(self, wasm_always_true, wasm_always_false):
        cond1 = WasmCondition(wasm_bytes=wasm_always_true)
        cond2 = WasmCondition(wasm_bytes=wasm_always_true)
        cond3 = WasmCondition(wasm_bytes=wasm_always_false)

        assert cond1 == cond2
        assert cond1 != cond3
        assert hash(cond1) == hash(cond2)

    def test_repr(self, wasm_always_true):
        cond = WasmCondition(wasm_bytes=wasm_always_true)
        r = repr(cond)
        assert "WasmCondition" in r
        assert "id=" in r
        assert "size=" in r


class TestConditionLingo:
    """Test the ConditionLingo wrapper."""

    def test_create(self, wasm_always_true):
        cond = WasmCondition(wasm_bytes=wasm_always_true)
        lingo = ConditionLingo(condition=cond)
        assert lingo.version == "2.0.0"
        assert len(lingo.id) == 6

    def test_eval_true(self, wasm_always_true):
        cond = WasmCondition(wasm_bytes=wasm_always_true)
        lingo = ConditionLingo(condition=cond)
        assert lingo.eval() is True

    def test_eval_false(self, wasm_always_false):
        cond = WasmCondition(wasm_bytes=wasm_always_false)
        lingo = ConditionLingo(condition=cond)
        assert lingo.eval() is False

    def test_from_dict(self, wasm_always_true):
        cond = WasmCondition(wasm_bytes=wasm_always_true)
        lingo = ConditionLingo(condition=cond)
        d = lingo.to_dict()

        lingo2 = ConditionLingo.from_dict(d)
        assert lingo2.version == lingo.version
        assert lingo2.condition == lingo.condition

    def test_from_json(self, wasm_always_true):
        cond = WasmCondition(wasm_bytes=wasm_always_true)
        lingo = ConditionLingo(condition=cond)
        j = lingo.to_json()

        lingo2 = ConditionLingo.from_json(j)
        assert lingo2.condition == lingo.condition

    def test_bytes_roundtrip(self, wasm_always_true):
        cond = WasmCondition(wasm_bytes=wasm_always_true)
        lingo = ConditionLingo(condition=cond)
        b = bytes(lingo)

        lingo2 = ConditionLingo.from_bytes(b)
        assert lingo2.condition == lingo.condition

    def test_from_dict_empty(self):
        with pytest.raises(InvalidConditionLingo, match="Empty"):
            ConditionLingo.from_dict(None)

    def test_from_dict_missing_version(self):
        with pytest.raises(InvalidConditionLingo, match="Missing version"):
            ConditionLingo.from_dict({"condition": {}})

    def test_from_dict_missing_condition(self):
        with pytest.raises(InvalidConditionLingo, match="Missing condition"):
            ConditionLingo.from_dict({"version": "2.0.0"})

    def test_from_dict_unsupported_type(self):
        with pytest.raises(InvalidConditionLingo, match="Unsupported condition type"):
            ConditionLingo.from_dict(
                {
                    "version": "2.0.0",
                    "condition": {"conditionType": "contract"},
                }
            )


class TestEvaluateConditionLingo:
    """Test the evaluate_condition_lingo entry point (used by Ursula)."""

    def test_satisfied(self, wasm_always_true):
        cond = WasmCondition(wasm_bytes=wasm_always_true)
        lingo = ConditionLingo(condition=cond)
        # Should not raise
        evaluate_condition_lingo(condition_lingo=lingo.to_dict())

    def test_not_satisfied(self, wasm_always_false):
        cond = WasmCondition(wasm_bytes=wasm_always_false)
        lingo = ConditionLingo(condition=cond)
        with pytest.raises(ConditionEvalError) as exc_info:
            evaluate_condition_lingo(condition_lingo=lingo.to_dict())
        assert exc_info.value.status_code == 403
        assert "not satisfied" in exc_info.value.message

    def test_invalid_lingo(self):
        with pytest.raises(ConditionEvalError) as exc_info:
            evaluate_condition_lingo(
                condition_lingo={
                    "version": "2.0.0",
                    "condition": {"conditionType": "invalid"},
                }
            )
        assert exc_info.value.status_code == 400

    def test_empty_lingo(self):
        # Empty/None lingo should not raise
        evaluate_condition_lingo(condition_lingo=None)
        evaluate_condition_lingo(condition_lingo={})

    def test_with_context(self, wasm_context_check):
        cond = WasmCondition(wasm_bytes=wasm_context_check)
        lingo = ConditionLingo(condition=cond)
        lingo_dict = lingo.to_dict()

        # With matching context
        evaluate_condition_lingo(
            condition_lingo=lingo_dict,
            context={":testKey": "value"},
        )

        # Without matching context
        with pytest.raises(ConditionEvalError):
            evaluate_condition_lingo(
                condition_lingo=lingo_dict,
                context={":wrongKey": "value"},
            )
