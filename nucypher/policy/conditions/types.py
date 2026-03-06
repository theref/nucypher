"""Type definitions for the condition system."""

import sys
from typing import Any, Dict

if sys.version_info >= (3, 11):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

# Context
ContextDict = Dict[str, Any]


# WASM Condition
class WasmConditionDict(TypedDict):
    conditionType: str  # "wasm"
    wasmBytecode: str  # base64-encoded .wasm bytecode


# Condition Lingo (versioned wrapper)
class Lingo(TypedDict):
    version: str
    condition: WasmConditionDict


# Alias for backward compatibility
ConditionDict = WasmConditionDict
