"""
Condition Lingo — WASM-based condition evaluation.

This module provides the ConditionLingo wrapper that deserializes
and evaluates WASM conditions. Replaces the previous JSON DSL system.
"""

import json
from hashlib import md5
from typing import Any, Dict

from nucypher.policy.conditions.exceptions import (
    InvalidConditionLingo,
)
from nucypher.policy.conditions.types import Lingo
from nucypher.policy.conditions.wasm.conditions import WasmCondition
from nucypher.utilities.logging import Logger

# Keep this constant accessible for signing conditions
SIGNING_CONDITION_OBJECT_CONTEXT_VAR = ":signingConditionObject"


class ConditionLingo:
    """
    A versioned wrapper around a WasmCondition.

    Flat wire format:
    {
        "version": "2.0.0",
        "wasm": "<base64-encoded .wasm bytecode>",
        "name": "optional-name",
        "inputs": [":param1", ":param2"]
    }
    """

    VERSION = "2.0.0"

    def __init__(self, condition: WasmCondition, version: str = VERSION):
        self.condition = condition
        self.version = version
        self._json_cache = None
        self.id = md5(self.to_json().encode("utf-8")).hexdigest()[:6]
        self.log = Logger(self.__class__.__name__)

    @classmethod
    def from_dict(cls, data: Lingo) -> "ConditionLingo":
        if not data:
            raise InvalidConditionLingo("Empty condition lingo")

        version = data.get("version")
        if not version:
            raise InvalidConditionLingo("Missing version in condition lingo")

        wasm_b64 = data.get("wasm")
        if not wasm_b64:
            raise InvalidConditionLingo("Missing wasm field in condition lingo")

        try:
            condition = WasmCondition.from_dict(data)
        except Exception as e:
            raise InvalidConditionLingo(f"Invalid WASM condition: {e}") from e

        return cls(condition=condition, version=version)

    @classmethod
    def from_json(cls, data) -> "ConditionLingo":
        if isinstance(data, str):
            data = json.loads(data)
        return cls.from_dict(data)

    @classmethod
    def from_bytes(cls, data: bytes) -> "ConditionLingo":
        return cls.from_json(data.decode("utf-8"))

    def to_dict(self) -> Dict[str, Any]:
        return self.condition.to_dict()

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    def __bytes__(self) -> bytes:
        return self.to_json().encode("utf-8")

    def __repr__(self):
        return (
            f"ConditionLingo(version={self.version}, "
            f"id={self.id}, condition={self.condition})"
        )

    def eval(
        self,
        providers=None,
        debug_mode: bool = False,
        **context,
    ) -> bool:
        """Evaluate the condition. Returns True if satisfied."""
        result, value = self.condition.verify(providers=providers, **context)

        if not result and debug_mode:
            self.log.debug(
                f"Condition evaluation failed; ({self}). "
                f"Condition returned: {value}"
            )

        return result
