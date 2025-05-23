import copy
import itertools

import pytest

from nucypher.policy.conditions.context import (
    USER_ADDRESS_CONTEXT,
    USER_ADDRESS_EIP4361_EXTERNAL_CONTEXT,
    _resolve_user_address,
    get_context_value,
    is_context_variable,
    resolve_any_context_variables,
)
from nucypher.policy.conditions.exceptions import (
    ContextVariableVerificationFailed,
    InvalidConditionContext,
    InvalidContextVariableData,
)
from nucypher.policy.conditions.lingo import (
    ReturnValueTest,
)
from tests.constants import INT256_MIN, UINT256_MAX

INVALID_CONTEXT_PARAM_NAMES = [
    ":",
    ":)",
    ":!",
    ":3",
    ":superñoño",
    ":::::this//is       🍌 🍌 🍌 ",
    ":123 \"$%'+-?\n  jarl!! cobarde!!",
]

VALID_CONTEXT_PARAM_NAMES = [
    ":foo",
    ":_bar",
    ":bar_",
    ":_bar_",
    ":VAR",
    ":a1234",
    ":snake_case",
    ":camelCase",
    ":_",  # TODO: not sure if we should allow this one, tbh
]

DEFINITELY_NOT_CONTEXT_PARAM_NAMES = ["1234", "foo", "", 123]

CONTEXT = {":foo": 1234, ":bar": "'BAR'"}

VALUES_WITH_RESOLUTION = [
    ([], []),
    (42, 42),
    (True, True),
    ("'bar'", "'bar'"),
    ([42, True, "'bar'"], [42, True, "'bar'"]),
    (":foo", 1234),
    ([":foo", True, "'bar'"], [1234, True, "'bar'"]),
    ([":foo", ":foo", 5, [99, [":bar"]]], [1234, 1234, 5, [99, ["'BAR'"]]]),
]


def test_is_context_variable():
    for variable in VALID_CONTEXT_PARAM_NAMES:
        assert is_context_variable(variable)

    for variable in DEFINITELY_NOT_CONTEXT_PARAM_NAMES:
        assert not is_context_variable(variable)

    for variable in INVALID_CONTEXT_PARAM_NAMES:
        assert not is_context_variable(variable)


def test_resolve_context_variable():
    for value, resolution in VALUES_WITH_RESOLUTION:
        assert resolution == resolve_any_context_variables(value, **CONTEXT)


def test_resolve_any_context_variables():
    for params_with_resolution, value_with_resolution in itertools.product(
        VALUES_WITH_RESOLUTION, repeat=2
    ):
        params, resolved_params = params_with_resolution
        value, resolved_value = value_with_resolution
        return_value_test = ReturnValueTest(comparator="==", value=value)
        resolved_parameters = resolve_any_context_variables([params], **CONTEXT)
        resolved_return_value = return_value_test.with_resolved_context(**CONTEXT)
        assert resolved_parameters == [resolved_params]
        assert resolved_return_value.comparator == return_value_test.comparator
        assert resolved_return_value.index == return_value_test.index
        assert resolved_return_value.value == resolved_value


@pytest.mark.parametrize(
    "value, expected_resolved_value",
    [
        (":foo", UINT256_MAX),
        (":bar", INT256_MIN),
        (
            [":foo", 12, ":bar", "5555555555", "endWith_n"],
            [UINT256_MAX, 12, INT256_MIN, "5555555555", "endWith_n"],
        ),
        (
            [":foo", ":foo", 5, [99, [":bar"]]],
            [UINT256_MAX, UINT256_MAX, 5, [99, [INT256_MIN]]],
        ),
    ],
)
def test_resolve_big_int_context_variables(value, expected_resolved_value):
    # bigints have the 'n' suffix
    context = {":foo": f"{UINT256_MAX}n", ":bar": f"{INT256_MIN}n"}

    # use with parameters
    resolved_value = resolve_any_context_variables(value, **context)
    assert resolved_value == expected_resolved_value

    return_value_test = ReturnValueTest(comparator="==", value=value)
    resolved_return_value = return_value_test.with_resolved_context(**context)
    assert resolved_return_value.value == resolved_value


@pytest.mark.parametrize(
    "value, expected_resolution",
    [
        (
            "https://api.github.com/user/:foo/:bar",
            "https://api.github.com/user/1234/BAR",
        ),
        (
            "The cost of :bar is $:foo; $:foo is too expensive for :bar",
            "The cost of BAR is $1234; $1234 is too expensive for BAR",
        ),
        # graphql query
        (
            """{
                organization(login: ":bar") {
                  teams(first: :foo, userLogins: [":bar"]) {
                    totalCount
                    edges {
                      node {
                        id
                        name
                        description
                      }
                    }
                  }
                }
            }""",
            """{
                organization(login: "BAR") {
                  teams(first: 1234, userLogins: ["BAR"]) {
                    totalCount
                    edges {
                      node {
                        id
                        name
                        description
                      }
                    }
                  }
                }
            }""",
        ),
    ],
)
def test_resolve_context_variable_within_substring(value, expected_resolution):
    context = {":foo": 1234, ":bar": "BAR"}
    resolved_value = resolve_any_context_variables(value, **context)
    assert expected_resolution == resolved_value


@pytest.mark.parametrize(
    "value, expected_resolution",
    [
        (
            {
                "book_name": ":bar",
                "price": "$:foo",
                "description": ":bar is a book about foo and bar.",
            },
            {
                "book_name": "BAR",
                "price": "$1234",
                "description": "BAR is a book about foo and bar.",
            },
        )
    ],
)
def test_resolve_context_variable_within_dictionary(value, expected_resolution):
    context = {":foo": 1234, ":bar": "BAR"}
    resolved_value = resolve_any_context_variables(value, **context)
    assert expected_resolution == resolved_value

@pytest.mark.parametrize("expected_entry", ["address", "signature", "typedData"])
@pytest.mark.parametrize(
    "context_variable_name, valid_user_address_fixture",
    [
        (USER_ADDRESS_CONTEXT, "valid_eip4361_auth_message"),
        (USER_ADDRESS_CONTEXT, "valid_eip712_auth_message"),  # allowed for now
        (USER_ADDRESS_EIP4361_EXTERNAL_CONTEXT, "valid_eip4361_auth_message"),
    ],
)
def test_user_address_context_missing_required_entries(
    expected_entry, context_variable_name, valid_user_address_fixture, request
):
    valid_user_address_auth_message = request.getfixturevalue(
        valid_user_address_fixture
    )
    context = {context_variable_name: valid_user_address_auth_message}
    del context[context_variable_name][expected_entry]
    with pytest.raises(InvalidContextVariableData):
        get_context_value(context_variable_name, **context)


@pytest.mark.parametrize(
    "context_variable_name, valid_user_address_fixture",
    [
        (USER_ADDRESS_CONTEXT, "valid_eip4361_auth_message"),
        (USER_ADDRESS_CONTEXT, "valid_eip712_auth_message"),  # allowed for now
        (USER_ADDRESS_EIP4361_EXTERNAL_CONTEXT, "valid_eip4361_auth_message"),
    ],
)
def test_user_address_context_invalid_typed_data(
    context_variable_name, valid_user_address_fixture, request
):
    valid_user_address_auth_message = request.getfixturevalue(
        valid_user_address_fixture
    )
    # invalid typed data
    context = {context_variable_name: valid_user_address_auth_message}
    context[context_variable_name]["typedData"] = dict(
        randomSaying="Comparison is the thief of joy."  # -– Theodore Roosevelt
    )
    with pytest.raises(InvalidContextVariableData):
        get_context_value(context_variable_name, **context)


@pytest.mark.parametrize(
    "context_variable_name, valid_user_address_fixture",
    [
        # EIP712 message not compatible with EIP4361 context variable
        (USER_ADDRESS_EIP4361_EXTERNAL_CONTEXT, "valid_eip712_auth_message"),
    ],
)
def test_user_address_context_variable_with_incompatible_auth_message(
    context_variable_name, valid_user_address_fixture, request
):
    valid_user_address_auth_message = request.getfixturevalue(
        valid_user_address_fixture
    )
    # scheme in message is unexpected for context variable name
    context = {context_variable_name: valid_user_address_auth_message}
    with pytest.raises(InvalidContextVariableData, match="UnexpectedScheme"):
        get_context_value(context_variable_name, **context)


@pytest.mark.parametrize(
    "context_variable_name, valid_user_address_fixture",
    [
        (USER_ADDRESS_CONTEXT, "valid_eip4361_auth_message"),
        (USER_ADDRESS_CONTEXT, "valid_eip712_auth_message"),  # allowed for now
        (USER_ADDRESS_EIP4361_EXTERNAL_CONTEXT, "valid_eip4361_auth_message"),
    ],
)
def test_user_address_context_variable_verification(
    context_variable_name,
    valid_user_address_fixture,
    get_random_checksum_address,
    request,
):
    valid_user_address_auth_message = request.getfixturevalue(
        valid_user_address_fixture
    )
    valid_user_address_context = {
        context_variable_name: valid_user_address_auth_message
    }

    # call underlying directive directly (appease codecov)
    address = _resolve_user_address(
        user_address_context_variable=context_variable_name,
        **valid_user_address_context,
    )
    assert address == valid_user_address_context[context_variable_name]["address"]

    # valid user address context
    address = get_context_value(context_variable_name, **valid_user_address_context)
    assert address == valid_user_address_context[context_variable_name]["address"]

    # invalid user address context - signature does not match address
    # internals are mutable - deepcopy
    mismatch_with_address_context = copy.deepcopy(valid_user_address_context)
    mismatch_with_address_context[context_variable_name][
        "address"
    ] = get_random_checksum_address()
    with pytest.raises(ContextVariableVerificationFailed):
        get_context_value(context_variable_name, **mismatch_with_address_context)

    # invalid user address context - signature does not match address
    # internals are mutable - deepcopy
    mismatch_with_address_context = copy.deepcopy(valid_user_address_context)
    signature = (
        "0x93252ddff5f90584b27b5eef1915b23a8b01a703be56c8bf0660647c15cb75e9"
        "1983bde9877eaad11da5a3ebc9b64957f1c182536931f9844d0c600f0c41293d1b"
    )
    mismatch_with_address_context[context_variable_name]["signature"] = signature
    with pytest.raises(ContextVariableVerificationFailed):
        get_context_value(context_variable_name, **mismatch_with_address_context)

    # invalid signature
    # internals are mutable - deepcopy
    invalid_signature_context = copy.deepcopy(valid_user_address_context)
    invalid_signature_context[context_variable_name][
        "signature"
    ] = "0xdeadbeef"  # invalid signature
    with pytest.raises(InvalidConditionContext):
        get_context_value(context_variable_name, **invalid_signature_context)
