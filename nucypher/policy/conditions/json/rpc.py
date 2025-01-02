from abc import ABC
from typing import Any, Optional

from marshmallow import ValidationError, fields, post_load, validate, validates
from marshmallow.fields import Url
from typing_extensions import override

from nucypher.policy.conditions.context import is_context_variable
from nucypher.policy.conditions.exceptions import (
    JsonRequestException,
)
from nucypher.policy.conditions.json.base import (
    BaseJsonRequestCondition,
    HTTPMethod,
    JSONPathField,
    JsonRequestCall,
)
from nucypher.policy.conditions.lingo import (
    ConditionType,
    ExecutionCallAccessControlCondition,
    ReturnValueTest,
)


class BaseJsonRPCCall(JsonRequestCall, ABC):
    class Schema(JsonRequestCall.Schema):
        method = fields.Str(required=True)
        params = fields.Field(required=False, allow_none=True)
        query = JSONPathField(required=False, allow_none=True)
        authorization_token = fields.Str(required=False, allow_none=True)

        @validates("authorization_token")
        def validate_auth_token(self, value):
            if value and not is_context_variable(value):
                raise ValidationError(
                    f"Invalid value for authorization token; expected a context variable, but got '{value}'"
                )

    def __init__(
        self,
        method: str,
        params: Optional[Any] = None,
        query: Optional[str] = None,
        authorization_token: Optional[str] = None,
    ):
        self.method = method
        self.params = params or []

        parameters = {
            "jsonrpc": "2.0",
            "method": self.method,
            "params": self.params,
            "id": 1,  # any id will do
        }
        super().__init__(
            http_method=HTTPMethod.POST,
            parameters=parameters,
            query=query,
            authorization_token=authorization_token,
        )

    @override
    def _execute(self, endpoint, **context):
        data = self._fetch(endpoint, **context)

        # response contains a value for either "result" or "error"
        error = data.get("error")
        if error:
            raise JsonRequestException(
                f"JSON RPC Request failed with error in response: code={error['code']}, msg={error['message']}"
            )

        # obtain result first then perform query
        result = data.get("result")
        if not result:
            raise JsonRequestException(
                f"Malformed JSON RPC response, no 'result' field - data={data}"
            )
        query_result = self._query_response(result, **context)
        return query_result


class JsonEndpointRPCCall(BaseJsonRPCCall):
    class Schema(BaseJsonRPCCall.Schema):
        endpoint = Url(required=True, relative=False, schemes=["https"])

        @post_load
        def make(self, data, **kwargs):
            return JsonEndpointRPCCall(**data)

    def __init__(
        self,
        endpoint: str,
        method: str,
        params: Optional[Any] = None,
        query: Optional[str] = None,
        authorization_token: Optional[str] = None,
    ):
        self.endpoint = endpoint
        super().__init__(
            method=method,
            params=params,
            query=query,
            authorization_token=authorization_token,
        )

    @override
    def execute(self, **context) -> Any:
        return super()._execute(endpoint=self.endpoint, **context)


class JsonRpcCondition(BaseJsonRequestCondition):
    """
    A JSON RPC condition is a condition that can be evaluated by performing a POST on a JSON
    HTTPS endpoint. The response must return an HTTP 200 with valid JSON RPC 2.0 response.
    The response will be deserialized as JSON and parsed using jsonpath.
    """

    EXECUTION_CALL_TYPE = JsonEndpointRPCCall
    CONDITION_TYPE = ConditionType.JSONRPC.value

    class Schema(
        ExecutionCallAccessControlCondition.Schema, JsonEndpointRPCCall.Schema
    ):
        condition_type = fields.Str(
            validate=validate.Equal(ConditionType.JSONRPC.value), required=True
        )

        @post_load
        def make(self, data, **kwargs):
            return JsonRpcCondition(**data)

    def __init__(
        self,
        endpoint: str,
        method: str,
        return_value_test: ReturnValueTest,
        params: Optional[Any] = None,
        query: Optional[str] = None,
        authorization_token: Optional[str] = None,
        condition_type: Optional[str] = ConditionType.JSONRPC.value,
        name: Optional[str] = None,
    ):
        super().__init__(
            endpoint=endpoint,
            method=method,
            return_value_test=return_value_test,
            params=params,
            query=query,
            authorization_token=authorization_token,
            condition_type=condition_type,
            name=name,
        )

    @property
    def endpoint(self):
        return self.execution_call.endpoint

    @property
    def method(self):
        return self.execution_call.method

    @property
    def params(self):
        return self.execution_call.params

    @property
    def query(self):
        return self.execution_call.query

    @property
    def authorization_token(self):
        return self.execution_call.authorization_token

    @property
    def timeout(self):
        return self.execution_call.timeout
