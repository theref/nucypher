"""
WASM Condition Evaluator (Extism)

Core evaluation engine using Extism. Loads .wasm bytecode as an Extism plugin,
registers host functions, and executes evaluate() -> bytes.

WASM modules must follow Extism PDK conventions:
- Import extism:host/env functions (alloc, store_u8, output_set, etc.)
- Export a void evaluate() function
- Use output_set to return a 1-byte result (0x01 = true, 0x00 = false)

Sandbox guarantees:
- Fuel metering (CPU budget per execution)
- Memory limits (max_pages in manifest)
- Timeout (timeout_ms in manifest)
- No ambient I/O (only host functions provide external access)
"""

import base64
import hashlib
import json
from typing import Any, Dict, Optional

import extism
from extism_sys import ffi as _ffi
from extism_sys import lib as _lib

from nucypher.policy.conditions.exceptions import ConditionEvaluationFailed
from nucypher.policy.conditions.utils import ConditionProviderManager
from nucypher.policy.conditions.wasm.host_functions import ALL_HOST_FUNCTIONS
from nucypher.utilities.logging import Logger

log = Logger("wasm-evaluator")

# Sandbox defaults
DEFAULT_FUEL = 1_000_000
DEFAULT_MAX_PAGES = 16  # 16 pages = 1 MB
DEFAULT_TIMEOUT_MS = 30_000  # 30 seconds


class WasmEvaluationError(ConditionEvaluationFailed):
    """Raised when WASM evaluation fails."""


class FuelExhausted(WasmEvaluationError):
    """Raised when a WASM module exhausts its fuel budget."""


class MemoryLimitExceeded(WasmEvaluationError):
    """Raised when a WASM module exceeds its memory limit."""


class EvaluationTimeout(WasmEvaluationError):
    """Raised when a WASM module exceeds its wall-clock timeout."""


class InvalidWasmModule(WasmEvaluationError):
    """Raised when a WASM module is malformed or missing required exports."""


class HostFunctionError(WasmEvaluationError):
    """Raised when a host function encounters an error during execution."""


class _FueledPlugin:
    """
    Thin wrapper around Extism C API plugin pointer that provides
    a .call() interface compatible with extism.Plugin, with fuel support.
    """

    def __init__(self, plugin_ptr, compiled_ptr, fn_metas, timeout_ms):
        self._plugin = plugin_ptr
        self._compiled = compiled_ptr
        self._fn_metas = fn_metas  # prevent GC
        self._timeout_ms = timeout_ms

    def function_exists(self, name: str) -> bool:
        return _lib.extism_plugin_function_exists(self._plugin, name.encode())

    def call(self, function_name: str, data: bytes, host_context=None) -> bytes:
        if host_context is not None:
            ctx_handle = _ffi.new_handle(host_context)
            rc = _lib.extism_plugin_call_with_host_context(
                self._plugin, function_name.encode(), data, len(data), ctx_handle
            )
        else:
            rc = _lib.extism_plugin_call(
                self._plugin, function_name.encode(), data, len(data)
            )

        if rc != 0:
            error = _lib.extism_plugin_error(self._plugin)
            if error != _ffi.NULL:
                error_msg = _ffi.string(error).decode()
            else:
                error_msg = f"Error code: {rc}"
            raise extism.Error(error_msg)

        out_len = _lib.extism_plugin_output_length(self._plugin)
        out_data = _lib.extism_plugin_output_data(self._plugin)
        if out_len > 0:
            buf = _ffi.buffer(out_data, out_len)
            return bytes(buf)
        return b""

    def cancel_handle(self):
        return extism.CancelHandle(_lib.extism_plugin_cancel_handle(self._plugin))

    def __del__(self):
        if hasattr(self, "_plugin") and self._plugin is not None:
            _lib.extism_plugin_free(self._plugin)
            self._plugin = None
        if hasattr(self, "_compiled") and self._compiled is not None:
            _lib.extism_compiled_plugin_free(self._compiled)
            self._compiled = None


class WasmEvaluator:
    """
    Evaluates WASM condition modules in a sandboxed Extism runtime.

    Each evaluation creates a fresh Plugin instance with fuel/memory/timeout limits.
    Compiled modules are cached by content hash to avoid redundant compilation.
    WASM modules must follow Extism PDK conventions.
    """

    def __init__(
        self,
        fuel: int = DEFAULT_FUEL,
        max_pages: int = DEFAULT_MAX_PAGES,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
    ):
        self.fuel = fuel
        self.max_pages = max_pages
        self.timeout_ms = timeout_ms
        self._compiled_cache: Dict[str, Any] = {}

    def _get_compiled(self, wasm_bytes: bytes):
        """Get or create a compiled plugin pointer, caching by content hash."""
        cache_key = hashlib.sha256(wasm_bytes).hexdigest()

        if cache_key in self._compiled_cache:
            compiled_ptr, fn_metas = self._compiled_cache[cache_key]
            return compiled_ptr, fn_metas

        manifest = {
            "wasm": [{"data": base64.b64encode(wasm_bytes).decode()}],
            "memory": {"max_pages": self.max_pages},
            "timeout_ms": self.timeout_ms,
        }
        manifest_bytes = json.dumps(manifest).encode()

        fn_metas = [
            extism.extism._ExtismFunctionMetadata(f) for f in ALL_HOST_FUNCTIONS
        ]
        fn_ptrs = [m.pointer for m in fn_metas]

        errmsg = _ffi.new("char**")
        if len(fn_ptrs) > 0:
            fn_array = _ffi.new("ExtismFunction*[]", fn_ptrs)
        else:
            fn_array = _ffi.NULL

        compiled_ptr = _lib.extism_compiled_plugin_new_with_fuel_limit(
            manifest_bytes,
            len(manifest_bytes),
            fn_array,
            len(fn_ptrs),
            False,  # wasi
            self.fuel,
            errmsg,
        )

        if compiled_ptr == _ffi.NULL:
            msg = _ffi.string(errmsg[0]).decode()
            _lib.extism_plugin_new_error_free(errmsg[0])
            raise InvalidWasmModule(f"Failed to compile WASM module: {msg}")

        self._compiled_cache[cache_key] = (compiled_ptr, fn_metas)
        return compiled_ptr, fn_metas

    def _instantiate(self, compiled_ptr, fn_metas):
        """Create a fresh plugin instance from a compiled module."""
        errmsg = _ffi.new("char**")
        plugin_ptr = _lib.extism_plugin_new_from_compiled(compiled_ptr, errmsg)
        if plugin_ptr == _ffi.NULL:
            msg = _ffi.string(errmsg[0]).decode()
            _lib.extism_plugin_new_error_free(errmsg[0])
            raise InvalidWasmModule(f"Failed to instantiate WASM plugin: {msg}")
        return _FueledPlugin(plugin_ptr, None, fn_metas, self.timeout_ms)

    def evaluate(
        self,
        wasm_bytes: bytes,
        providers: Optional[ConditionProviderManager] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Evaluate a WASM condition module.

        Args:
            wasm_bytes: Raw .wasm bytecode (must follow Extism PDK conventions)
            providers: Provider manager for blockchain connections
            context: User-supplied context variables (e.g. :userAddress)

        Returns:
            True if condition is satisfied (output byte is 0x01), False otherwise.

        Raises:
            InvalidWasmModule: If the module is malformed or missing exports
            FuelExhausted: If the module exceeds its CPU budget
            EvaluationTimeout: If the module exceeds its wall-clock timeout
            MemoryLimitExceeded: If the module exceeds memory limits
            HostFunctionError: If a host function fails
            WasmEvaluationError: For other evaluation errors
        """
        context = context or {}
        providers = providers or ConditionProviderManager(providers={})

        # Compile (cached) and instantiate
        try:
            compiled_ptr, fn_metas = self._get_compiled(wasm_bytes)
            plugin = self._instantiate(compiled_ptr, fn_metas)
        except InvalidWasmModule:
            raise
        except extism.Error as e:
            raise InvalidWasmModule(f"Failed to compile WASM module: {e}") from e
        except Exception as e:
            raise InvalidWasmModule(f"Failed to compile WASM module: {e}") from e

        # Validate exports
        if not plugin.function_exists("evaluate"):
            raise InvalidWasmModule("WASM module missing required export: 'evaluate'")

        # Build host context for host functions
        host_context = {
            "providers": providers,
            "context": context,
        }

        # Pass context data as input (JSON-serialized)
        input_data = json.dumps(context).encode("utf-8")

        # Execute
        try:
            result = plugin.call("evaluate", input_data, host_context=host_context)
        except extism.Error as e:
            error_msg = str(e)
            if "fuel" in error_msg.lower():
                raise FuelExhausted("WASM evaluation exhausted fuel budget") from e
            elif "timeout" in error_msg.lower():
                raise EvaluationTimeout("WASM evaluation timed out") from e
            elif "oom" in error_msg.lower() or "memory" in error_msg.lower():
                raise MemoryLimitExceeded(
                    "WASM evaluation exceeded memory limit"
                ) from e
            else:
                raise WasmEvaluationError(f"WASM evaluation error: {e}") from e

        # Interpret result: first byte == 0x01 means true
        if len(result) >= 1:
            return result[0] == 1
        return False
