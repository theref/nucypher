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
import copy
import json

import mock
import pytest

from nucypher.policy.conditions.base import ReencryptionCondition
from nucypher.policy.conditions.context import _recover_user_address
from nucypher.policy.conditions.lingo import ConditionLingo
from tests.integration.characters.test_bob_handles_frags import _make_message_kits

VALID_USER_ADDRESS_CONTEXT = {
    ":userAddress": {
        "signature": "0x7268bf563bcbc6a11e4b2928dc639657791dd6c3e3bf921620a9d170c8d879383ac6ec9fd2440c71a18d5d5e8030dfe338b58828a2e74ea0d992586f19f0ef7c1c",
        "typedData": {
            "types": {
                "Wallet": [
                    {"name": "address", "type": "address"},
                    {"name": "signatureText", "type": "string"},
                    {"name": "blockNumber", "type": "uint256"},
                    {"name": "blockHash", "type": "bytes32"},
                ],
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "salt", "type": "bytes32"},
                ],
            },
            "domain": {
                "name": "tDec",
                "version": "1",
                "chainId": 80001,
                "salt": "0x3e6365d35fd4e53cbc00b080b0742b88f8b735352ea54c0534ed6a2e44a83ff0",
            },
            "message": {
                "address": "0x474E32B3163FE3aE21C72D40aE465e028dAd6202",
                "signatureText": "I'm an owner of address 0x474E32B3163FE3aE21C72D40aE465e028dAd6202 as of block number 28117088",
                "blockNumber": 28117088,
                "blockHash": "0x104dfae58be4a9b15d59ce447a565302d5658914f1093f10290cd846fbe258b7",
            },
            "primaryType": "Wallet",
        },
        "address": "0x474E32B3163FE3aE21C72D40aE465e028dAd6202",
    }
}


def _dont_validate_user_address(context_variable: str, **context):
    return context[":userAddress"]["address"]


@pytest.mark.parametrize("expected_entry", ["address", "signature", "typedData"])
def test_user_address_context_missing_entries(expected_entry):
    context = copy.deepcopy(VALID_USER_ADDRESS_CONTEXT)
    del context[":userAddress"][expected_entry]
    with pytest.raises(ReencryptionCondition.InvalidContextVariableData):
        _recover_user_address(**context)


def test_user_address_context_verification(testerchain):
    # valid user address context - signature matches address
    address = _recover_user_address(**VALID_USER_ADDRESS_CONTEXT)
    assert address == VALID_USER_ADDRESS_CONTEXT[":userAddress"]["address"]

    # invalid user address context - signature does not match address
    # internals are mutable - deepcopy
    invalid_user_address_context = copy.deepcopy(VALID_USER_ADDRESS_CONTEXT)
    invalid_user_address_context[":userAddress"][
        "address"
    ] = testerchain.etherbase_account
    with pytest.raises(ReencryptionCondition.ContextVariableVerificationFailed):
        _recover_user_address(**invalid_user_address_context)

    # invalid user address context - signature does not match address
    # internals are mutable - deepcopy
    invalid_user_address_context = copy.deepcopy(VALID_USER_ADDRESS_CONTEXT)
    signature = (
        "0x93252ddff5f90584b27b5eef1915b23a8b01a703be56c8bf0660647c15cb75e9"
        "1983bde9877eaad11da5a3ebc9b64957f1c182536931f9844d0c600f0c41293d1b"
    )
    invalid_user_address_context[":userAddress"]["signature"] = signature
    with pytest.raises(ReencryptionCondition.ContextVariableVerificationFailed):
        _recover_user_address(**invalid_user_address_context)


@mock.patch(
    "nucypher.policy.conditions.evm.get_context_value",
    side_effect=_dont_validate_user_address,
)
def test_erc20_evm_condition_evaluation(
    get_context_value_mock, testerchain, evm_condition
):
    context = {":userAddress": {"address": testerchain.unassigned_accounts[0]}}
    result, value = evm_condition.verify(provider=testerchain.provider, **context)
    assert result is True

    context[":userAddress"]["address"] = testerchain.etherbase_account
    result, value = evm_condition.verify(provider=testerchain.provider, **context)
    assert result is False


def test_erc20_evm_condition_evaluation_with_custom_context_variable(
    testerchain, custom_context_variable_evm_condition
):
    context = {":addressToUse": testerchain.unassigned_accounts[0]}
    result, value = custom_context_variable_evm_condition.verify(
        provider=testerchain.provider, **context
    )
    assert result is True

    context[":addressToUse"] = testerchain.etherbase_account
    result, value = custom_context_variable_evm_condition.verify(
        provider=testerchain.provider, **context
    )
    assert result is False


@pytest.mark.skip('Need a way to handle user inputs like HRAC as context variables')
def test_subscription_manager_condition_evaluation(testerchain, subscription_manager_condition):
    context = {":hrac": None}
    result, value = subscription_manager_condition.verify(
        provider=testerchain.provider, **context
    )
    assert result is True
    result, value = subscription_manager_condition.verify(provider=testerchain.provider)
    assert result is False


@mock.patch(
    "nucypher.policy.conditions.evm.get_context_value",
    side_effect=_dont_validate_user_address,
)
def test_rpc_condition_evaluation(get_context_value_mock, testerchain, rpc_condition):
    context = {":userAddress": {"address": testerchain.unassigned_accounts[0]}}
    result, value = rpc_condition.verify(provider=testerchain.provider, **context)
    assert result is True


@mock.patch(
    "nucypher.policy.conditions.evm.get_context_value",
    side_effect=_dont_validate_user_address,
)
def test_time_condition_evaluation(
    get_context_value_mock, testerchain, timelock_condition
):
    context = {":userAddress": {"address": testerchain.unassigned_accounts[0]}}
    result, value = timelock_condition.verify(provider=testerchain.provider, **context)
    assert result is True


def test_simple_compound_conditions_evaluation(testerchain):
    # TODO Improve internals of evaluation here (natural vs recursive approach)
    conditions = [
        {'returnValueTest': {'value': '0', 'comparator': '>'}, 'method': 'timelock'},
        {'operator': 'and'},
        {'returnValueTest': {'value': '99999999999999999', 'comparator': '<'}, 'method': 'timelock'},
        {'operator': 'and'},
        {'returnValueTest': {'value': '0', 'comparator': '>'}, 'method': 'timelock'}
    ]
    conditions = json.dumps(conditions)
    lingo = ConditionLingo.from_json(conditions)
    result = lingo.eval()
    assert result is True


@mock.patch(
    "nucypher.policy.conditions.evm.get_context_value",
    side_effect=_dont_validate_user_address,
)
def test_onchain_conditions_lingo_evaluation(
    get_context_value_mock,
    testerchain,
    timelock_condition,
    rpc_condition,
    evm_condition,
    lingo,
):
    context = {":userAddress": {"address": testerchain.etherbase_account}}
    result = lingo.eval(provider=testerchain.provider, **context)
    assert result is True


def test_single_retrieve_with_onchain_conditions(enacted_blockchain_policy, blockchain_bob, blockchain_ursulas):
    blockchain_bob.start_learning_loop()
    conditions = [
        {'returnValueTest': {'value': '0', 'comparator': '>'}, 'method': 'timelock'},
        {'operator': 'and'},
        {"chain": "testerchain",
         "method": "eth_getBalance",
         "parameters": [
             blockchain_bob.checksum_address,
             "latest"
         ],
         "returnValueTest": {
             "comparator": ">=",
             "value": "10000000000000"
         }
        }

    ]
    messages, message_kits = _make_message_kits(enacted_blockchain_policy.public_key, conditions)
    policy_info_kwargs = dict(
        encrypted_treasure_map=enacted_blockchain_policy.treasure_map,
        alice_verifying_key=enacted_blockchain_policy.publisher_verifying_key,
    )

    cleartexts = blockchain_bob.retrieve_and_decrypt(
        message_kits=message_kits,
        **policy_info_kwargs,
    )

    assert cleartexts == messages
