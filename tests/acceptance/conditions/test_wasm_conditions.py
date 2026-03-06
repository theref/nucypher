"""
Acceptance tests for WASM condition evaluation against a real testerchain.

Exercises the full evaluation path: WASM bytecode -> Extism runtime ->
host functions -> testerchain (ERC-20 balanceOf, block timestamps, etc.)
"""

from pathlib import Path

import pytest
from web3 import Web3

from nucypher.policy.conditions.exceptions import NoConnectionToChain
from nucypher.policy.conditions.lingo import ConditionLingo
from nucypher.policy.conditions.utils import evaluate_condition_lingo
from nucypher.policy.conditions.wasm.conditions import WasmCondition

FIXTURES_DIR = Path(__file__).parents[2] / "wasm_fixtures" / "conditions" / "out"


class _TesterchainProviderManager:
    """Minimal ConditionProviderManager duck-type that routes calls to the testerchain."""

    def __init__(self, w3: Web3):
        self._w3 = w3
        self._chain_id = w3.eth.chain_id

    def exec_web3_call(self, chain_id, fn, **kwargs):
        if chain_id != self._chain_id:
            raise NoConnectionToChain(chain=chain_id)
        return fn(self._w3)

    def supported_chains(self):
        return {self._chain_id}


@pytest.fixture(scope="module")
def testerchain_w3(testerchain):
    return testerchain.client.w3


@pytest.fixture(scope="module")
def testerchain_providers(testerchain_w3):
    return _TesterchainProviderManager(testerchain_w3)


@pytest.fixture(scope="module")
def chain_id(testerchain_w3):
    return testerchain_w3.eth.chain_id


# --- ERC-20 Token Gate ---


class TestERC20TokenGate:
    """Test the erc20_token_gate.wasm fixture against a real deployed ERC-20."""

    @pytest.fixture(scope="class")
    def erc20_wasm(self):
        return (FIXTURES_DIR / "erc20_token_gate.wasm").read_bytes()

    def test_balance_above_threshold_passes(
        self,
        erc20_wasm,
        t_token,
        deployer_account,
        testerchain_providers,
        chain_id,
    ):
        """Deployer holds tokens — condition should pass."""
        condition = WasmCondition(wasm_bytes=erc20_wasm, name="erc20-gate")
        result, _ = condition.verify(
            providers=testerchain_providers,
            **{
                ":tokenContract": t_token.address,
                ":userAddress": deployer_account.address,
                ":minBalance": "1",
                ":chainId": chain_id,
            },
        )
        assert result is True

    def test_balance_below_threshold_fails(
        self,
        erc20_wasm,
        t_token,
        accounts,
        testerchain_providers,
        chain_id,
    ):
        """Empty account has no tokens — condition should fail."""
        empty_account = accounts.unassigned_accounts[0]
        condition = WasmCondition(wasm_bytes=erc20_wasm, name="erc20-gate")
        result, _ = condition.verify(
            providers=testerchain_providers,
            **{
                ":tokenContract": t_token.address,
                ":userAddress": empty_account,
                ":minBalance": "1000000000000000000",
                ":chainId": chain_id,
            },
        )
        assert result is False

    def test_through_evaluate_condition_lingo(
        self,
        erc20_wasm,
        t_token,
        deployer_account,
        testerchain_providers,
        chain_id,
    ):
        """Full path: evaluate_condition_lingo -> ConditionLingo -> WasmCondition -> host."""
        condition = WasmCondition(wasm_bytes=erc20_wasm, name="erc20-gate")
        lingo = ConditionLingo(condition).to_dict()
        # Should not raise (condition passes)
        evaluate_condition_lingo(
            condition_lingo=lingo,
            providers=testerchain_providers,
            context={
                ":tokenContract": t_token.address,
                ":userAddress": deployer_account.address,
                ":minBalance": "1",
                ":chainId": chain_id,
            },
        )


# --- Block Timestamp ---


class TestBlockTimestamp:
    """Test the check_block_timestamp.wasm fixture against the testerchain."""

    @pytest.fixture(scope="class")
    def timestamp_wasm(self):
        return (FIXTURES_DIR / "check_block_timestamp.wasm").read_bytes()

    def test_past_timestamp_passes(
        self,
        timestamp_wasm,
        testerchain_providers,
        chain_id,
    ):
        """Minimum timestamp of 1 (1970) — should always pass."""
        condition = WasmCondition(wasm_bytes=timestamp_wasm, name="time-check")
        result, _ = condition.verify(
            providers=testerchain_providers,
            **{
                ":minTimestamp": 1,
                ":chainId": chain_id,
            },
        )
        assert result is True

    def test_future_timestamp_fails(
        self,
        timestamp_wasm,
        testerchain_providers,
        chain_id,
    ):
        """Minimum timestamp far in the future — should fail."""
        condition = WasmCondition(wasm_bytes=timestamp_wasm, name="time-check")
        result, _ = condition.verify(
            providers=testerchain_providers,
            **{
                ":minTimestamp": 99999999999,
                ":chainId": chain_id,
            },
        )
        assert result is False


# --- Context Passthrough ---


class TestContextPassthrough:
    """Test that context variables flow through the full serialization/evaluation path."""

    def test_context_via_evaluate_condition_lingo(self):
        """Context dict flows through evaluate_condition_lingo to WASM input."""
        wasm_bytes = (FIXTURES_DIR / "always_true.wasm").read_bytes()
        condition = WasmCondition(wasm_bytes=wasm_bytes, name="always-true")
        lingo = ConditionLingo(condition).to_dict()
        # Should not raise
        evaluate_condition_lingo(
            condition_lingo=lingo,
            context={":userAddress": "0x1234567890123456789012345678901234567890"},
        )

    def test_serialization_roundtrip(self):
        """Lingo serializes to dict and deserializes back correctly."""
        wasm_bytes = (FIXTURES_DIR / "always_true.wasm").read_bytes()
        condition = WasmCondition(wasm_bytes=wasm_bytes, name="always-true")
        lingo = ConditionLingo(condition)

        lingo_dict = lingo.to_dict()
        restored = ConditionLingo.from_dict(lingo_dict)
        assert restored.condition == condition
        assert restored.eval() is True


# --- Error Handling ---


class TestErrorHandling:
    """Test error paths through evaluate_condition_lingo."""

    def test_garbage_wasm_rejected(self):
        """Invalid WASM bytecode raises InvalidCondition."""
        from nucypher.policy.conditions.exceptions import InvalidCondition

        with pytest.raises(InvalidCondition, match="missing magic number"):
            WasmCondition(wasm_bytes=b"not wasm bytes")

    def test_fuel_exhaustion(self):
        """WASM module that runs out of fuel raises FuelExhausted."""
        from nucypher.policy.conditions.wasm.evaluator import (
            FuelExhausted,
            WasmEvaluator,
        )

        wasm_bytes = (FIXTURES_DIR / "always_true.wasm").read_bytes()
        evaluator = WasmEvaluator(fuel=1)
        with pytest.raises(FuelExhausted):
            evaluator.evaluate(wasm_bytes)

    def test_condition_eval_returns_false_gives_forbidden(self):
        """WASM condition returning false -> ConditionEvalError with FORBIDDEN."""
        from http import HTTPStatus

        from nucypher.policy.conditions.utils import ConditionEvalError

        wasm_bytes = (FIXTURES_DIR / "always_false.wasm").read_bytes()
        condition = WasmCondition(wasm_bytes=wasm_bytes, name="always-false")
        lingo = ConditionLingo(condition).to_dict()

        with pytest.raises(ConditionEvalError) as exc_info:
            evaluate_condition_lingo(condition_lingo=lingo)
        assert exc_info.value.status_code == HTTPStatus.FORBIDDEN
