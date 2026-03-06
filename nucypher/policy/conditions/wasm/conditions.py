"""
WASM Condition

A Condition that wraps WASM bytecode. Replaces all JSON condition types
with a single type that evaluates arbitrary WASM modules in a sandbox.
"""

import base64
import hashlib
import json
from typing import Any, Dict, Optional, Tuple

from nucypher.policy.conditions.exceptions import (
    InvalidCondition,
)
from nucypher.policy.conditions.utils import ConditionProviderManager
from nucypher.policy.conditions.wasm.evaluator import WasmEvaluator

CONDITION_TYPE = "wasm"


class WasmCondition:
    """
    A condition defined by WASM bytecode.

    The WASM module must export:
      evaluate(context_ptr: i32) -> i32
        Returns 1 (allow) or 0 (deny).

    The module may import host functions from the "taco" namespace:
      - read_chain, http_get, verify_jwt, verify_ecdsa, block_timestamp, get_context
    """

    def __init__(self, wasm_bytes: bytes, name: Optional[str] = None):
        if not wasm_bytes:
            raise InvalidCondition("WASM bytecode cannot be empty")
        if not isinstance(wasm_bytes, (bytes, bytearray)):
            raise InvalidCondition("WASM bytecode must be bytes")
        wasm_bytes = bytes(wasm_bytes)
        # Check WASM magic number: \x00asm
        if not wasm_bytes[:4] == b"\x00asm":
            raise InvalidCondition("Invalid WASM bytecode: missing magic number")
        self.wasm_bytes = wasm_bytes
        self.name = name
        self._evaluator = WasmEvaluator()

    @property
    def condition_type(self) -> str:
        return CONDITION_TYPE

    @property
    def id(self) -> str:
        """Content-addressable ID based on SHA-256 of the WASM bytecode."""
        return hashlib.sha256(self.wasm_bytes).hexdigest()[:16]

    def verify(
        self,
        providers: Optional[ConditionProviderManager] = None,
        **context,
    ) -> Tuple[bool, Any]:
        """
        Evaluate the WASM condition.

        Returns:
            Tuple of (result: bool, value: Any).
            result is True if evaluate() returns 1, False otherwise.
            value is the raw i32 return value.
        """
        result = self._evaluator.evaluate(
            wasm_bytes=self.wasm_bytes,
            providers=providers,
            context=context,
        )
        return result, int(result)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a dictionary for storage/transmission."""
        return {
            "conditionType": CONDITION_TYPE,
            "wasmBytecode": base64.b64encode(self.wasm_bytes).decode("ascii"),
            "name": self.name,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WasmCondition":
        """Deserialize from a dictionary."""
        condition_type = data.get("conditionType")
        if condition_type != CONDITION_TYPE:
            raise InvalidCondition(
                f"Expected conditionType '{CONDITION_TYPE}', got '{condition_type}'"
            )
        bytecode_b64 = data.get("wasmBytecode")
        if not bytecode_b64:
            raise InvalidCondition("Missing wasmBytecode field")
        try:
            wasm_bytes = base64.b64decode(bytecode_b64)
        except Exception as e:
            raise InvalidCondition(f"Invalid base64 in wasmBytecode: {e}") from e
        return cls(wasm_bytes=wasm_bytes, name=data.get("name"))

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, data: str) -> "WasmCondition":
        return cls.from_dict(json.loads(data))

    def to_bytes(self) -> bytes:
        """Serialize to bytes for on-chain storage or ciphertext binding."""
        return self.to_json().encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "WasmCondition":
        return cls.from_json(data.decode("utf-8"))

    def __repr__(self):
        return f"WasmCondition(id={self.id}, size={len(self.wasm_bytes)})"

    def __eq__(self, other):
        if not isinstance(other, WasmCondition):
            return NotImplemented
        return self.wasm_bytes == other.wasm_bytes

    def __hash__(self):
        return hash(self.wasm_bytes)
