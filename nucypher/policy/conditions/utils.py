"""Utilities for the condition evaluation system."""

import re
from http import HTTPStatus
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from web3 import Web3
from web3.middleware import abi_middleware, attrdict_middleware
from web3.types import Middleware

from nucypher.policy.conditions.exceptions import (
    ConditionEvaluationFailed,
    InvalidConditionLingo,
    NoConnectionToChain,
)
from nucypher.policy.conditions.types import ContextDict, Lingo
from nucypher.utilities.endpoint import (
    RPCEndpoint,
    RPCEndpointManager,
    ThreadLocalSessionManager,
)
from nucypher.utilities.logging import Logger

__LOGGER = Logger("condition-eval")


class ConditionProviderManager:
    """
    Concurrency-friendly RPC endpoint manager which is responsible for managing
    RPC endpoints for different chains and executing web3 calls with proper error handling
    and endpoint selection.
    """

    _DEFAULT_WEB3_CALL_TIMEOUT = 5.0

    def __init__(
        self,
        providers: Dict[int, List[str]],
        preferential_providers: Optional[Dict[int, List[str]]] = None,
    ):
        self._session_manager = ThreadLocalSessionManager()
        self._rpc_endpoint_managers = dict()

        preferential_providers = preferential_providers or {}
        for chain_id, preferred_providers in preferential_providers.items():
            other_providers = providers.get(chain_id, [])
            if set(preferred_providers) & set(other_providers):
                raise ValueError(
                    f"Preferential providers for chain ID {chain_id} cannot overlap with other providers"
                )

            self._rpc_endpoint_managers[chain_id] = RPCEndpointManager(
                session_manager=self._session_manager,
                preferred_endpoints=preferred_providers,
                endpoints=other_providers,
            )

        for chain_id, endpoint_list in providers.items():
            if chain_id not in self._rpc_endpoint_managers:
                self._rpc_endpoint_managers[chain_id] = RPCEndpointManager(
                    session_manager=self._session_manager,
                    endpoints=endpoint_list,
                )

        self.logger = Logger(__name__)

    def supported_chains(self) -> Set[int]:
        return set(self._rpc_endpoint_managers.keys())

    @staticmethod
    def _sort_by_failures_then_latency(stats: RPCEndpoint.EndpointStats) -> Tuple:
        return (
            stats.consecutive_unreachable_failures,
            stats.consecutive_request_failures,
            stats.ewma_latency_ms,
        )

    @staticmethod
    def _get_default_middlewares() -> Sequence[Tuple[Middleware, str]]:
        return [
            (attrdict_middleware, "attrdict"),
            (abi_middleware, "abi"),
        ]

    def exec_web3_call(
        self,
        chain_id: int,
        fn: Callable[[Web3], Any],
        request_timeout: Union[float, Tuple[float, float]] = _DEFAULT_WEB3_CALL_TIMEOUT,
    ) -> Any:
        manager = self._rpc_endpoint_managers.get(chain_id, None)
        if not manager:
            raise NoConnectionToChain(chain=chain_id)

        default_middlewares = self._get_default_middlewares()
        return manager.call(
            fn=fn,
            request_timeout=request_timeout,
            endpoint_sort_strategy=self._sort_by_failures_then_latency,
            override_middleware_stack=default_middlewares,
        )


class ConditionEvalError(Exception):
    """Exception when executing condition evaluation."""
    def __init__(self, message: str, status_code: int):
        self.message = message
        self.status_code = status_code


def evaluate_condition_lingo(
    condition_lingo: Lingo,
    providers: Optional[ConditionProviderManager] = None,
    context: Optional[ContextDict] = None,
    log: Logger = __LOGGER,
    debug_mode: bool = False,
):
    """
    Evaluates condition lingo with the given providers and user-supplied context.
    If all conditions are satisfied this function returns None.
    Raises ConditionEvalError on failure.
    """
    from nucypher.policy.conditions.lingo import ConditionLingo
    from nucypher.policy.conditions.wasm.evaluator import WasmEvaluationError

    context = context or dict()
    providers = providers or ConditionProviderManager(providers=dict())
    error = None

    try:
        if condition_lingo:
            lingo = ConditionLingo.from_dict(condition_lingo)
            log.debug(
                f"Evaluating WASM condition lingo id#{str(lingo.id)}: {condition_lingo}"
            )

            result = lingo.eval(debug_mode=debug_mode, providers=providers, **context)
            if not result:
                error = ConditionEvalError(
                    "Conditions not satisfied", HTTPStatus.FORBIDDEN
                )
    except InvalidConditionLingo as e:
        error = ConditionEvalError(
            f"Invalid condition grammar: {e}",
            HTTPStatus.BAD_REQUEST,
        )
    except WasmEvaluationError as e:
        error = ConditionEvalError(
            f"Condition evaluation failed: {e}",
            HTTPStatus.BAD_REQUEST,
        )
    except NoConnectionToChain as e:
        error = ConditionEvalError(
            f"Node does not have a connection to chain ID {e.chain}",
            HTTPStatus.NOT_IMPLEMENTED,
        )
    except ConditionEvaluationFailed as e:
        error = ConditionEvalError(
            f"Decryption condition not evaluated: {e}", HTTPStatus.BAD_REQUEST
        )
    except Exception as e:
        message = (
            f"Unexpected exception while evaluating "
            f"decryption condition ({e.__class__.__name__}): {e}"
        )
        error = ConditionEvalError(message, HTTPStatus.INTERNAL_SERVER_ERROR)
        log.warn(message)

    if error:
        log.warn(error.message)
        raise error


# --- Utility functions kept for external use ---


def to_camelcase(s):
    parts = iter(s.split("_"))
    return next(parts) + "".join(i.title() for i in parts)


def camel_case_to_snake(data: str) -> str:
    data = re.sub(r"(?<!^)(?=[A-Z])", "_", data).lower()
    return data
