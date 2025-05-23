from typing import (
    Any,
    List,
    Optional,
    Tuple,
)

from eth_typing import ChecksumAddress
from eth_utils import to_checksum_address
from marshmallow import (
    ValidationError,
    fields,
    post_load,
    validate,
    validates,
    validates_schema,
)
from marshmallow.validate import OneOf
from typing_extensions import override
from web3 import Web3
from web3.types import ABIFunction

from nucypher.policy.conditions import STANDARD_ABI_CONTRACT_TYPES
from nucypher.policy.conditions.base import (
    ExecutionCall,
)
from nucypher.policy.conditions.context import (
    is_context_variable,
    resolve_any_context_variables,
)
from nucypher.policy.conditions.exceptions import (
    RequiredContextVariable,
    RPCExecutionFailed,
)
from nucypher.policy.conditions.lingo import (
    AnyField,
    ConditionType,
    ExecutionCallAccessControlCondition,
    ReturnValueTest,
)
from nucypher.policy.conditions.utils import (
    ConditionProviderManager,
    camel_case_to_snake,
)
from nucypher.policy.conditions.validation import (
    align_comparator_value_with_abi,
    get_unbound_contract_function,
    validate_contract_function_expected_return_type,
    validate_function_abi,
)

# TODO: Move this to a more appropriate location,
#  but be sure to change the mocks in tests too.
# Permitted blockchains for condition evaluation
from nucypher.utilities import logging


class RPCCall(ExecutionCall):
    LOG = logging.Logger(__name__)

    ALLOWED_METHODS = {
        # RPC
        "eth_getBalance": int,
    }  # TODO other allowed methods (tDEC #64)

    class Schema(ExecutionCall.Schema):
        chain = fields.Int(required=True, strict=True)
        method = fields.Str(
            required=True,
            error_messages={
                "required": "Undefined method name",
                "null": "Undefined method name",
            },
        )
        parameters = fields.List(AnyField, required=False, allow_none=True)

        @validates("method")
        def validate_method(self, value):
            if value not in RPCCall.ALLOWED_METHODS:
                raise ValidationError(
                    f"'{value}' is not a permitted RPC endpoint for condition evaluation."
                )

        @post_load
        def make(self, data, **kwargs):
            return RPCCall(**data)

    def __init__(
        self,
        chain: int,
        method: str,
        parameters: Optional[List[Any]] = None,
    ):
        self.chain = chain
        self.method = method
        self.parameters = parameters
        super().__init__()

    def _get_web3_py_function(self, w3: Web3, rpc_method: str):
        web3_py_method = camel_case_to_snake(rpc_method)
        rpc_function = getattr(
            w3.eth, web3_py_method
        )  # bind contract function (only exposes the eth API)
        return rpc_function

    def execute(self, providers: ConditionProviderManager, **context) -> Any:
        resolved_parameters = []
        if self.parameters:
            resolved_parameters = resolve_any_context_variables(
                param=self.parameters, providers=providers, **context
            )

        endpoints = providers.web3_endpoints(self.chain)

        latest_error = ""
        for w3 in endpoints:
            try:
                result = self._execute(w3, resolved_parameters)
                break
            except RequiredContextVariable:
                raise
            except Exception as e:
                latest_error = f"RPC call '{self.method}' failed: {e}"
                self.LOG.warn(f"{latest_error}, attempting to try next endpoint.")
                # Something went wrong. Try the next endpoint.
                continue
        else:
            # Fuck.
            raise RPCExecutionFailed(
                f"RPC call '{self.method}' failed; latest error - {latest_error}"
            )

        return result

    def _execute(self, w3: Web3, resolved_parameters: List[Any]) -> Any:
        """Execute onchain read and return result."""
        rpc_endpoint_, rpc_method = self.method.split("_", 1)
        rpc_function = self._get_web3_py_function(w3, rpc_method)
        rpc_result = rpc_function(*resolved_parameters)  # RPC read
        return rpc_result


class RPCCondition(ExecutionCallAccessControlCondition):
    EXECUTION_CALL_TYPE = RPCCall
    CONDITION_TYPE = ConditionType.RPC.value

    class Schema(ExecutionCallAccessControlCondition.Schema, RPCCall.Schema):
        condition_type = fields.Str(
            validate=validate.Equal(ConditionType.RPC.value), required=True
        )

        @validates_schema()
        def validate_expected_return_type(self, data, **kwargs):
            method = data.get("method")
            return_value_test = data.get("return_value_test")

            expected_return_type = RPCCall.ALLOWED_METHODS[method]
            comparator_value = return_value_test.value
            if is_context_variable(comparator_value):
                return

            if not isinstance(return_value_test.value, expected_return_type):
                raise ValidationError(
                    field_name="return_value_test",
                    message=f"Return value comparison for '{method}' call output "
                    f"should be '{expected_return_type}' and not '{type(comparator_value)}'.",
                )

        @post_load
        def make(self, data, **kwargs):
            return RPCCondition(**data)

    def __repr__(self) -> str:
        r = f"{self.__class__.__name__}(function={self.method}, chain={self.chain})"
        return r

    def __init__(
        self,
        chain: int,
        method: str,
        return_value_test: ReturnValueTest,
        condition_type: str = ConditionType.RPC.value,
        name: Optional[str] = None,
        parameters: Optional[List[Any]] = None,
        *args,
        **kwargs,
    ):
        super().__init__(
            chain=chain,
            method=method,
            return_value_test=return_value_test,
            condition_type=condition_type,
            name=name,
            parameters=parameters,
            *args,
            **kwargs,
        )

    @property
    def method(self):
        return self.execution_call.method

    @property
    def chain(self):
        return self.execution_call.chain

    @property
    def parameters(self):
        return self.execution_call.parameters

    def _align_comparator_value_with_abi(
        self, return_value_test: ReturnValueTest
    ) -> ReturnValueTest:
        return return_value_test

    def verify(
        self, providers: ConditionProviderManager, **context
    ) -> Tuple[bool, Any]:
        resolved_return_value_test = self.return_value_test.with_resolved_context(
            providers=providers, **context
        )
        return_value_test = self._align_comparator_value_with_abi(
            resolved_return_value_test
        )

        result = self.execution_call.execute(providers=providers, **context)

        eval_result = return_value_test.eval(result)  # test
        return eval_result, result


class ContractCall(RPCCall):
    class Schema(RPCCall.Schema):
        contract_address = fields.Str(required=True)
        standard_contract_type = fields.Str(
            required=False,
            validate=OneOf(
                STANDARD_ABI_CONTRACT_TYPES,
                error="Invalid standard contract type: {input}",
            ),
            allow_none=True,
        )
        function_abi = fields.Dict(required=False, allow_none=True)

        @post_load
        def make(self, data, **kwargs):
            return ContractCall(**data)

        @validates("contract_address")
        def validate_contract_address(self, value):
            try:
                to_checksum_address(value)
            except ValueError:
                raise ValidationError(f"Invalid checksum address: '{value}'")

        @override
        @validates("method")
        def validate_method(self, value):
            return

        @validates("function_abi")
        def validate_abi(self, value):
            # needs to be done before schema validation
            if value:
                try:
                    validate_function_abi(value)
                except ValueError as e:
                    raise ValidationError(
                        field_name="function_abi", message=str(e)
                    ) from e

        @validates_schema
        def validate_standard_contract_type_or_function_abi(self, data, **kwargs):
            method = data.get("method")
            standard_contract_type = data.get("standard_contract_type")
            function_abi = data.get("function_abi")

            # validate xor of standard contract type and function abi
            if not (bool(standard_contract_type) ^ bool(function_abi)):
                raise ValidationError(
                    field_name="standard_contract_type",
                    message=f"Provide a standard contract type or function ABI; got ({standard_contract_type}, {function_abi}).",
                )

            # validate function abi with method name (not available for field validation)
            if function_abi:
                try:
                    validate_function_abi(function_abi, method_name=method)
                except ValueError as e:
                    raise ValidationError(
                        field_name="function_abi", message=str(e)
                    ) from e

            # validate contract
            contract_address = to_checksum_address(data.get("contract_address"))
            try:
                get_unbound_contract_function(
                    contract_address=contract_address,
                    method=method,
                    standard_contract_type=standard_contract_type,
                    function_abi=function_abi,
                )
            except ValueError as e:
                raise ValidationError(str(e)) from e

    def __init__(
        self,
        method: str,
        contract_address: ChecksumAddress,
        standard_contract_type: Optional[str] = None,
        function_abi: Optional[ABIFunction] = None,
        *args,
        **kwargs,
    ):
        # preprocessing
        contract_address = to_checksum_address(contract_address)
        self.contract_address = contract_address
        self.standard_contract_type = standard_contract_type
        self.function_abi = function_abi

        super().__init__(method=method, *args, **kwargs)

        # contract function already validated - so should not raise an exception
        self.contract_function = get_unbound_contract_function(
            contract_address=self.contract_address,
            method=self.method,
            standard_contract_type=self.standard_contract_type,
            function_abi=self.function_abi,
        )

    def _execute(self, w3: Web3, resolved_parameters: List[Any]) -> Any:
        """Execute onchain read and return result."""
        self.contract_function.w3 = w3
        bound_contract_function = self.contract_function(
            *resolved_parameters
        )  # bind contract function
        contract_result = bound_contract_function.call()  # onchain read
        return contract_result


class ContractCondition(RPCCondition):
    EXECUTION_CALL_TYPE = ContractCall
    CONDITION_TYPE = ConditionType.CONTRACT.value

    class Schema(RPCCondition.Schema, ContractCall.Schema):
        condition_type = fields.Str(
            validate=validate.Equal(ConditionType.CONTRACT.value), required=True
        )

        @validates_schema()
        def validate_expected_return_type(self, data, **kwargs):
            # validate that contract function is correct
            try:
                contract_function = get_unbound_contract_function(
                    contract_address=data.get("contract_address"),
                    method=data.get("method"),
                    standard_contract_type=data.get("standard_contract_type"),
                    function_abi=data.get("function_abi"),
                )
            except ValueError as e:
                raise ValidationError(str(e)) from e

            # validate return type based on contract function
            return_value_test = data.get("return_value_test")
            try:
                validate_contract_function_expected_return_type(
                    contract_function=contract_function,
                    return_value_test=return_value_test,
                )
            except ValueError as e:
                raise ValidationError(
                    field_name="return_value_test",
                    message=str(e),
                ) from e

        @post_load
        def make(self, data, **kwargs):
            return ContractCondition(**data)

    def __init__(
        self,
        method: str,
        contract_address: ChecksumAddress,
        condition_type: str = ConditionType.CONTRACT.value,
        standard_contract_type: Optional[str] = None,
        function_abi: Optional[ABIFunction] = None,
        *args,
        **kwargs,
    ):
        super().__init__(
            method=method,
            condition_type=condition_type,
            contract_address=contract_address,
            standard_contract_type=standard_contract_type,
            function_abi=function_abi,
            *args,
            **kwargs,
        )

    @property
    def function_abi(self):
        return self.execution_call.function_abi

    @property
    def standard_contract_type(self):
        return self.execution_call.standard_contract_type

    @property
    def contract_function(self):
        return self.execution_call.contract_function

    @property
    def contract_address(self):
        return self.execution_call.contract_address

    def __repr__(self) -> str:
        r = (
            f"{self.__class__.__name__}(function={self.method}, "
            f"contract={self.contract_address}, "
            f"chain={self.chain})"
        )
        return r

    def _align_comparator_value_with_abi(
        self, return_value_test: ReturnValueTest
    ) -> ReturnValueTest:
        return align_comparator_value_with_abi(
            abi=self.contract_function.contract_abi[0],
            return_value_test=return_value_test,
        )
