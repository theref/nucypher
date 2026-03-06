"""Type definitions for the condition system."""

import sys
from typing import Any, Dict, List

if sys.version_info >= (3, 11):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

# Context
ContextDict = Dict[str, Any]


# Flat wire format for WASM conditions
class Lingo(TypedDict, total=False):
    version: str
    wasm: str  # base64-encoded .wasm bytecode
    name: str
    inputs: List[str]  # declared context parameters
