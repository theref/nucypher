from collections import defaultdict

import pytest
from web3 import HTTPProvider

from nucypher.policy.conditions.evm import _CONDITION_CHAINS, RPCCondition
from nucypher.policy.conditions.lingo import ConditionLingo, ConditionType
from nucypher.utilities.logging import GlobalLoggerSettings
from tests.constants import TESTERCHAIN_CHAIN_ID
from tests.utils.policy import make_message_kits

GlobalLoggerSettings.start_text_file_logging()


def make_multichain_evm_conditions(bob, chain_ids):
    """This is a helper function to make a set of conditions that are valid on multiple chains."""
    operands = list()
    for chain_id in chain_ids:
        operand = [
            {
                "conditionType": ConditionType.TIME.value,
                "returnValueTest": {"value": "0", "comparator": ">"},
                "method": "blocktime",
                "chain": chain_id,
            },
            {
                "conditionType": ConditionType.RPC.value,
                "chain": chain_id,
                "method": "eth_getBalance",
                "parameters": [bob.checksum_address, "latest"],
                "returnValueTest": {"comparator": ">=", "value": "10000000000000"},
            },
        ]
        operands.extend(operand)

    _conditions = {
        "version": ConditionLingo.VERSION,
        "condition": {
            "conditionType": ConditionType.COMPOUND.value,
            "operator": "and",
            "operands": operands,
        },
    }
    return _conditions


@pytest.fixture(scope="module")
def chain_ids(module_mocker):
    ids = [
        TESTERCHAIN_CHAIN_ID,
        TESTERCHAIN_CHAIN_ID + 1,
        TESTERCHAIN_CHAIN_ID + 2,
        123456789,
    ]
    module_mocker.patch.dict(
        _CONDITION_CHAINS, {cid: "fakechain/mainnet" for cid in ids}
    )
    return ids


@pytest.fixture(scope="module", autouse=True)
def multichain_ursulas(ursulas, chain_ids):
    base_uri = "tester://multichain.{}"
    base_fallback_uri = "tester://multichain.fallback.{}"
    provider_uris = [base_uri.format(i) for i in range(len(chain_ids))]
    fallback_provider_uris = [
        base_fallback_uri.format(i) for i in range(len(chain_ids))
    ]
    mocked_condition_providers = {
        cid: {HTTPProvider(uri), HTTPProvider(furi)}
        for cid, uri, furi in zip(chain_ids, provider_uris, fallback_provider_uris)
    }
    for ursula in ursulas:
        ursula.condition_providers = mocked_condition_providers
    return ursulas


@pytest.fixture(scope="module")
def conditions(bob, chain_ids):
    _conditions = make_multichain_evm_conditions(bob, chain_ids)
    return _conditions


@pytest.fixture(scope="module")
def monkeymodule():
    from _pytest.monkeypatch import MonkeyPatch

    mpatch = MonkeyPatch()
    yield mpatch
    mpatch.undo()


@pytest.fixture(scope="module")
def mock_rpc_condition(module_mocker, testerchain, monkeymodule):
    def configure_mock(condition, provider, *args, **kwargs):
        condition.provider = provider
        return testerchain.w3

    monkeymodule.setattr(RPCCondition, "_configure_w3", configure_mock)
    configure_spy = module_mocker.spy(RPCCondition, "_configure_w3")

    chain_id_check_mock = module_mocker.patch.object(RPCCondition, "_check_chain_id")
    return configure_spy, chain_id_check_mock


def test_single_retrieve_with_multichain_conditions(
    enacted_policy, bob, multichain_ursulas, conditions, mock_rpc_condition, mocker
):
    bob.remember_node(multichain_ursulas[0])
    bob.start_learning_loop()

    messages, message_kits = make_message_kits(enacted_policy.public_key, conditions)
    policy_info_kwargs = dict(
        encrypted_treasure_map=enacted_policy.treasure_map,
        alice_verifying_key=enacted_policy.publisher_verifying_key,
    )

    cleartexts = bob.retrieve_and_decrypt(
        message_kits=message_kits,
        **policy_info_kwargs,
    )

    assert cleartexts == messages


def test_single_decryption_request_with_faulty_rpc_endpoint(
    enacted_policy, bob, multichain_ursulas, conditions, mock_rpc_condition
):
    bob.remember_node(multichain_ursulas[0])
    bob.start_learning_loop()

    messages, message_kits = make_message_kits(enacted_policy.public_key, conditions)
    policy_info_kwargs = dict(
        encrypted_treasure_map=enacted_policy.treasure_map,
        alice_verifying_key=enacted_policy.publisher_verifying_key,
    )

    calls = defaultdict(int)
    original_execute_call = RPCCondition._execute_call

    def faulty_execute_call(*args, **kwargs):
        """Intercept the call to the RPC endpoint and raise an exception on the second call."""
        nonlocal calls
        rpc_call = args[0]
        calls[rpc_call.chain] += 1
        if (
            calls[rpc_call.chain] == 2
            and "tester://multichain.0" in rpc_call.provider.endpoint_uri
        ):
            # simulate a network error
            raise ConnectionError("Something went wrong with the network")
        elif calls[rpc_call.chain] == 3:
            # check the provider is the fallback
            this_uri = rpc_call.provider.endpoint_uri
            assert "fallback" in this_uri
        return original_execute_call(*args, **kwargs)

    RPCCondition._execute_call = faulty_execute_call
    cleartexts = bob.retrieve_and_decrypt(
        message_kits=message_kits,
        **policy_info_kwargs,
    )
    assert cleartexts == messages
    RPCCondition._execute_call = original_execute_call
