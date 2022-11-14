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


import json
from pathlib import Path

import pytest
from web3 import Web3

import nucypher
import tests.data
from nucypher.blockchain.eth.agents import (
    ContractAgency,
    NucypherTokenAgent,
    SubscriptionManagerAgent,
)
from nucypher.blockchain.eth.signers.software import Web3Signer
from nucypher.blockchain.eth.sol.compile.compile import multiversion_compile
from nucypher.blockchain.eth.sol.compile.types import SourceBundle
from nucypher.crypto.powers import TransactingPower
from nucypher.policy.conditions.context import USER_ADDRESS_CONTEXT
from nucypher.policy.conditions.evm import ContractCondition, RPCCondition
from nucypher.policy.conditions.lingo import AND, OR, ConditionLingo, ReturnValueTest
from nucypher.policy.conditions.time import TimeCondition
from tests.constants import TESTERCHAIN_CHAIN_ID

VECTORS_FILE = Path(tests.__file__).parent / "data" / "test_conditions.json"


with open(VECTORS_FILE, 'r') as file:
    VECTORS = json.loads(file.read())


@pytest.fixture(autouse=True)
def mock_condition_blockchains(mocker):
    """adds testerchain to permitted conditional chains"""
    mocker.patch.object(
        nucypher.policy.conditions.evm, "_CONDITION_CHAINS", tuple([131277322940537])
    )


@pytest.fixture()
def ERC1155_balance_condition_data():
    VECTORS['ERC1155_balance']['chain'] = TESTERCHAIN_CHAIN_ID
    data = json.dumps(VECTORS['ERC1155_balance'])
    return data


@pytest.fixture()
def ERC1155_balance_condition(ERC1155_balance_condition_data):
    data = ERC1155_balance_condition_data
    condition = ContractCondition.from_json(data)
    return condition


@pytest.fixture()
def ERC20_balance_condition_data():
    VECTORS['ERC20_balance']['chain'] = TESTERCHAIN_CHAIN_ID
    data = json.dumps(VECTORS['ERC20_balance'])
    return data


@pytest.fixture()
def ERC20_balance_condition(ERC20_balance_condition_data):
    data = ERC20_balance_condition_data
    condition = ContractCondition.from_json(data)
    return condition


@pytest.fixture
def rpc_condition():
    condition = RPCCondition(
        method="eth_getBalance",
        chain=TESTERCHAIN_CHAIN_ID,
        return_value_test=ReturnValueTest("==", Web3.to_wei(1_000_000, "ether")),
        parameters=[USER_ADDRESS_CONTEXT],
    )
    return condition


@pytest.fixture
def erc20_evm_condition(test_registry, agency):
    token = ContractAgency.get_agent(NucypherTokenAgent, registry=test_registry)
    condition = ContractCondition(
        contract_address=token.contract.address,
        method="balanceOf",
        standard_contract_type="ERC20",
        chain=TESTERCHAIN_CHAIN_ID,
        return_value_test=ReturnValueTest("==", 0),
        parameters=[USER_ADDRESS_CONTEXT],
    )
    return condition


@pytest.fixture
def custom_context_variable_erc20_condition(
    test_registry, agency, testerchain, mock_condition_blockchains
):
    token = ContractAgency.get_agent(NucypherTokenAgent, registry=test_registry)
    condition = ContractCondition(
        contract_address=token.contract.address,
        method="balanceOf",
        standard_contract_type="ERC20",
        chain=TESTERCHAIN_CHAIN_ID,
        return_value_test=ReturnValueTest("==", 0),
        parameters=[":addressToUse"],
    )
    return condition


@pytest.fixture
def erc721_contract(testerchain, test_registry):
    solidity_root = Path(__file__).parent / "contracts"
    source_bundle = SourceBundle(base_path=solidity_root)
    compiled_constracts = multiversion_compile([source_bundle], True)
    testerchain._raw_contract_cache = compiled_constracts

    origin, *everybody_else = testerchain.client.accounts
    transacting_power = TransactingPower(
        account=origin, signer=Web3Signer(testerchain.client)
    )
    contract, receipt = testerchain.deploy_contract(
        transacting_power=transacting_power,
        registry=test_registry,
        contract_name="ConditionNFT",
    )
    # mint an NFT with tokenId = 1
    tx = contract.functions.mint(origin, 1).transact({"from": origin})
    testerchain.wait_for_receipt(tx)

    return contract


@pytest.fixture
def erc721_evm_condition_owner(erc721_contract):
    condition = ContractCondition(
        contract_address=erc721_contract.address,
        method="ownerOf",
        standard_contract_type="ERC721",
        chain=TESTERCHAIN_CHAIN_ID,
        return_value_test=ReturnValueTest("==", ":userAddress"),
        parameters=[
            ":tokenId",
        ],
    )
    return condition


@pytest.fixture
def erc721_evm_condition_balanceof(erc721_contract):
    condition = ContractCondition(
        contract_address=erc721_contract.address,
        method="balanceOf",
        standard_contract_type="ERC721",
        chain=TESTERCHAIN_CHAIN_ID,
        return_value_test=ReturnValueTest(">", 0),
        parameters=[
            ":userAddress",
        ],
    )

    return condition


@pytest.fixture
def subscription_manager_is_active_policy_condition(test_registry, agency):
    subscription_manager = ContractAgency.get_agent(
        SubscriptionManagerAgent,
        registry=test_registry
    )
    condition = ContractCondition(
        contract_address=subscription_manager.contract.address,
        function_abi=subscription_manager.contract.find_functions_by_name(
            "isPolicyActive"
        )[0].abi,
        method="isPolicyActive",
        chain=TESTERCHAIN_CHAIN_ID,
        return_value_test=ReturnValueTest("==", True),
        parameters=[":hrac"],
    )
    return condition


@pytest.fixture
def subscription_manager_get_policy_zeroized_policy_struct_condition(
    test_registry, agency
):
    subscription_manager = ContractAgency.get_agent(
        SubscriptionManagerAgent, registry=test_registry
    )
    condition = ContractCondition(
        contract_address=subscription_manager.contract.address,
        function_abi=subscription_manager.contract.find_functions_by_name("getPolicy")[
            0
        ].abi,
        method="getPolicy",
        chain=TESTERCHAIN_CHAIN_ID,
        return_value_test=ReturnValueTest("==", ":expectedPolicyStruct"),
        parameters=[":hrac"],
    )
    return condition


@pytest.fixture
def timelock_condition():
    condition = TimeCondition(
        return_value_test=ReturnValueTest('>', 0)
    )
    return condition


@pytest.fixture()
def lingo(erc721_evm_condition_balanceof,
          timelock_condition,
          rpc_condition,
          erc20_evm_condition):
    lingo = ConditionLingo(
        conditions=[
            erc721_evm_condition_balanceof,
            OR,
            timelock_condition,
            OR,
            rpc_condition,
            AND,
            erc20_evm_condition,
        ]
    )
    return lingo
