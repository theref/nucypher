"""
 This file is part of nucypher.

 nucypher is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 nucypher is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with nucypher.  If not, see <https://www.gnu.org/licenses/>.
"""

import random
import time
from http import HTTPStatus
from typing import List, Optional, Tuple, Type
from unittest.mock import ANY, MagicMock, Mock, patch

import pytest
from web3 import Web3
from web3.manager import RequestManager

from nucypher.policy.conditions.exceptions import (
    ConditionEvaluationFailed,
    InvalidConditionLingo,
    NoConnectionToChain,
)
from nucypher.policy.conditions.lingo import ConditionLingo
from nucypher.policy.conditions.utils import (
    ConditionEvalError,
    ConditionProviderManager,
    camel_case_to_snake,
    evaluate_condition_lingo,
    to_camelcase,
)
from nucypher.policy.conditions.wasm.evaluator import WasmEvaluationError
from nucypher.utilities.endpoint import RPCEndpoint

FAILURE_CASE_EXCEPTION_CODE_MATCHING = [
    # (exception, constructor parameters, expected status code)
    (InvalidConditionLingo, None, HTTPStatus.BAD_REQUEST),
    (WasmEvaluationError, ["error"], HTTPStatus.BAD_REQUEST),
    (NoConnectionToChain, [1], HTTPStatus.NOT_IMPLEMENTED),
    (ConditionEvaluationFailed, None, HTTPStatus.BAD_REQUEST),
    (Exception, None, HTTPStatus.INTERNAL_SERVER_ERROR),
]


@pytest.mark.parametrize("failure_case", FAILURE_CASE_EXCEPTION_CODE_MATCHING)
def test_evaluate_condition_exception_cases(
    failure_case: Tuple[Type[Exception], Optional[List], int]
):
    exception_class, exception_constructor_params, expected_status_code = failure_case
    exception_constructor_params = exception_constructor_params or []

    condition_lingo = Mock()
    condition_lingo.eval.side_effect = exception_class(*exception_constructor_params)

    with patch(
        "nucypher.policy.conditions.lingo.ConditionLingo.from_dict"
    ) as mocked_from_dict:
        mocked_from_dict.return_value = condition_lingo

        with pytest.raises(ConditionEvalError) as eval_error:
            evaluate_condition_lingo(
                condition_lingo=condition_lingo
            )  # provider and context default to empty dicts
        assert eval_error.value.status_code == expected_status_code


def test_evaluate_condition_invalid_lingo():
    with pytest.raises(ConditionEvalError) as eval_error:
        evaluate_condition_lingo(
            condition_lingo={
                "version": ConditionLingo.VERSION,
                "condition": {"dont_mind_me": "nothing_to_see_here"},
            }
        )  # provider and context default to empty dicts
    assert "Invalid condition grammar" in eval_error.value.message
    assert eval_error.value.status_code == HTTPStatus.BAD_REQUEST


def test_evaluate_condition_eval_returns_false():
    condition_lingo = Mock()
    condition_lingo.eval.return_value = False

    with patch(
        "nucypher.policy.conditions.lingo.ConditionLingo.from_dict"
    ) as mocked_from_dict:
        mocked_from_dict.return_value = condition_lingo

        with pytest.raises(ConditionEvalError) as eval_error:
            evaluate_condition_lingo(
                condition_lingo=condition_lingo,
                providers=ConditionProviderManager({}),
                context={"key": "value"},  # fake context
            )
        assert eval_error.value.status_code == HTTPStatus.FORBIDDEN


def test_evaluate_condition_eval_returns_true():
    condition_lingo = Mock()
    condition_lingo.eval.return_value = True

    with patch(
        "nucypher.policy.conditions.lingo.ConditionLingo.from_dict"
    ) as mocked_from_dict:
        mocked_from_dict.return_value = condition_lingo

        evaluate_condition_lingo(
            condition_lingo=condition_lingo,
            providers=ConditionProviderManager({}),
            context={
                "key1": "value1",
                "key2": "value2",
            },  # multiple values in fake context
        )


@pytest.mark.parametrize(
    "test_case",
    (
        ("nounderscores", "nounderscores"),
        ("one_underscore", "oneUnderscore"),
        ("two_under_scores", "twoUnderScores"),
    ),
)
def test_to_from_camel_case(test_case: Tuple[str, str]):
    # test to_camelcase()
    snake_case, camel_case = test_case
    result = to_camelcase(snake_case)
    assert result == camel_case

    # test camel_case_to_snake()
    result = camel_case_to_snake(camel_case)
    assert result == snake_case


class TestConditionProviderManager:
    """
    Tests for ConditionProviderManager.

    NOTE: The actual logic of making web3 calls and sorting endpoints is tested in the
    RPCEndpointManager tests.
    """

    def test_preferential_overlap_raises(self):
        providers = {2: ["https://provider.test"]}
        preferential = {2: ["https://provider.test"]}  # overlap
        with pytest.raises(
            ValueError, match="Preferential providers for chain ID 2 cannot overlap"
        ):
            ConditionProviderManager(
                providers=providers, preferential_providers=preferential
            )

    def test_supported_chains_and_manager_construction(self, mocker):
        providers = {
            2: ["https://p1.test"],
            4: ["https://p4.test"],
            3: ["https://p2.test", "https://p3.test"],
        }
        preferential = {2: ["https://pref.test"]}

        # Patch out the real RPCEndpointManager to avoid network/configuration side effects.
        fake_manager = MagicMock()
        with mocker.patch(
            "nucypher.policy.conditions.utils.RPCEndpointManager",
            return_value=fake_manager,
        ):
            m = ConditionProviderManager(
                providers=providers, preferential_providers=preferential
            )
            chains = m.supported_chains()
            assert chains == {2, 3, 4}

    def test_default_middlewares(self):
        """
        Defensive unit test that ensures that if the web3.py default middleware list changes
        that we are made aware of that, and should revisit the defaults used by ConditionProviderManager.
        """
        w3 = Web3()
        web3_default_middlewares = RequestManager.default_middlewares(w3)
        expected_web3_middlewares = {
            "gas_price_strategy",
            "name_to_address",
            "attrdict",
            "validation",
            "abi",
            "gas_estimate",
        }
        for middleware, name in web3_default_middlewares:
            assert name in expected_web3_middlewares, "unexpected middleware"

        condition_provider_middlewares = (
            ConditionProviderManager._get_default_middlewares()
        )
        expected_condition_provider_middlewares = {"attrdict", "abi"}
        for middleware, name in condition_provider_middlewares:
            assert (
                name in expected_condition_provider_middlewares
            ), "unexpected ConditionProviderManager middleware"

    def test_exec_web3_call_no_connection_to_chain(self, mocker):
        m = ConditionProviderManager(providers={2: ["https://p.test"]})
        with pytest.raises(NoConnectionToChain, match="No connection to chain ID 1"):
            _ = m.exec_web3_call(chain_id=1, fn=lambda w3: None)

    def test_exec_web3_call_invokes_endpoint_manager_call(self, mocker):
        mock_mgr = MagicMock()
        result = "You can change your wife, your politics, your religion. But never, never can you change your favorite football team."  # - Eric Cantona
        mock_mgr.call.return_value = result

        def mock_fn(w3):
            return "no saying"

        with mocker.patch(
            "nucypher.policy.conditions.utils.RPCEndpointManager", return_value=mock_mgr
        ):
            m = ConditionProviderManager(providers={2: ["https://p.test"]})
            res = m.exec_web3_call(chain_id=2, fn=mock_fn)

        assert res == result
        mock_mgr.call.assert_called_once()
        mock_mgr.call.assert_called_with(
            fn=mock_fn,
            request_timeout=ConditionProviderManager._DEFAULT_WEB3_CALL_TIMEOUT,
            endpoint_sort_strategy=ConditionProviderManager._sort_by_failures_then_latency,
            override_middleware_stack=[(ANY, "attrdict"), (ANY, "abi")],
        )

        customized_timeout = 10.0
        with mocker.patch(
            "nucypher.policy.conditions.utils.RPCEndpointManager", return_value=mock_mgr
        ):
            m = ConditionProviderManager(providers={2: ["https://p.test"]})
            res = m.exec_web3_call(
                chain_id=2, fn=mock_fn, request_timeout=customized_timeout
            )

        assert res == result
        # customized timeout and default sorting strategy provided
        mock_mgr.call.assert_called_with(
            fn=mock_fn,
            request_timeout=customized_timeout,
            endpoint_sort_strategy=ConditionProviderManager._sort_by_failures_then_latency,
            override_middleware_stack=[(ANY, "attrdict"), (ANY, "abi")],
        )

    @pytest.mark.parametrize(
        "stats_2_sort_scenario",
        [
            "lower_latency",
            "lower_request_failures",
            "higher_unreachable_failures",
            "equal_stats",
        ],
    )
    def test_sort_by_failures_then_latency(self, stats_2_sort_scenario):
        ewma_latency_ms = 6.4
        consecutive_request_failures = 3
        consecutive_unreachable_failures = 0

        stats = RPCEndpoint.EndpointStats(
            latest_latency_ms=4.2,
            ewma_latency_ms=ewma_latency_ms,
            consecutive_request_failures=consecutive_request_failures,
            consecutive_unreachable_failures=consecutive_unreachable_failures,
            num_in_flight_usage=4,
            in_flight_capacity=20,
            last_used=time.time() - 10,
        )
        assert ConditionProviderManager._sort_by_failures_then_latency(stats) == (
            consecutive_unreachable_failures,
            consecutive_request_failures,
            ewma_latency_ms,
        )

        # check sorting
        stats_2_ewma_latency_ms = (
            stats.ewma_latency_ms
            if stats_2_sort_scenario != "lower_latency"
            else stats.ewma_latency_ms - 1
        )
        stats_2_consecutive_request_failures = (
            stats.consecutive_request_failures
            if stats_2_sort_scenario != "lower_request_failures"
            else stats.consecutive_request_failures - 2
        )
        stats_2_consecutive_unreachable_failures = (
            stats.consecutive_unreachable_failures
            if stats_2_sort_scenario != "higher_unreachable_failures"
            else stats.consecutive_unreachable_failures + 1
        )

        stats_2 = RPCEndpoint.EndpointStats(
            latest_latency_ms=stats.latest_latency_ms,
            ewma_latency_ms=stats_2_ewma_latency_ms,
            consecutive_request_failures=stats_2_consecutive_request_failures,
            consecutive_unreachable_failures=stats_2_consecutive_unreachable_failures,
            num_in_flight_usage=stats.num_in_flight_usage,
            in_flight_capacity=stats.in_flight_capacity,
            last_used=stats.last_used,
        )

        stats_values = [stats, stats_2]
        random.shuffle(stats_values)
        sorted_values = sorted(
            stats_values, key=ConditionProviderManager._sort_by_failures_then_latency
        )

        if stats_2_sort_scenario == "higher_unreachable_failures":
            assert sorted_values == [stats, stats_2]
        elif stats_2_sort_scenario == "equal_stats":
            assert sorted_values == stats_values  # no change in original order
        else:
            # stats_2 has lower values
            assert sorted_values == [stats_2, stats]
