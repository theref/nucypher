import random
from unittest.mock import Mock

import pytest

from nucypher.policy.conditions.base import AccessControlCondition
from nucypher.policy.conditions.exceptions import (
    InvalidCondition,
    InvalidConditionLingo,
)
from nucypher.policy.conditions.lingo import (
    AndCompoundCondition,
    CompoundAccessControlCondition,
    ConditionType,
    ConditionVariable,
    NotCompoundCondition,
    OrCompoundCondition,
    SequentialAccessControlCondition,
)


@pytest.fixture(scope="function")
def mock_conditions():
    condition_1 = Mock(spec=AccessControlCondition)
    condition_1.verify.return_value = (True, 1)
    condition_1.to_dict.return_value = {
        "value": 1
    }  # needed for "id" value calc for CompoundAccessControlCondition

    condition_2 = Mock(spec=AccessControlCondition)
    condition_2.verify.return_value = (True, 2)
    condition_2.to_dict.return_value = {"value": 2}

    condition_3 = Mock(spec=AccessControlCondition)
    condition_3.verify.return_value = (True, 3)
    condition_3.to_dict.return_value = {"value": 3}

    condition_4 = Mock(spec=AccessControlCondition)
    condition_4.verify.return_value = (True, 4)
    condition_4.to_dict.return_value = {"value": 4}

    return condition_1, condition_2, condition_3, condition_4


def test_invalid_compound_condition(time_condition, rpc_condition):
    for operator in CompoundAccessControlCondition.OPERATORS:
        if operator == CompoundAccessControlCondition.NOT_OPERATOR:
            operands = [time_condition]
        else:
            operands = [time_condition, rpc_condition]

        # invalid condition type
        with pytest.raises(InvalidCondition, match=ConditionType.COMPOUND.value):
            _ = CompoundAccessControlCondition(
                condition_type=ConditionType.TIME.value,
                operator=operator,
                operands=operands,
            )

    # invalid operator - 1 operand
    with pytest.raises(InvalidCondition):
        _ = CompoundAccessControlCondition(operator="5True", operands=[time_condition])

    # invalid operator - 2 operands
    with pytest.raises(InvalidCondition):
        _ = CompoundAccessControlCondition(
            operator="5True", operands=[time_condition, rpc_condition]
        )

    # no operands
    with pytest.raises(InvalidCondition):
        _ = CompoundAccessControlCondition(
            operator=random.choice(CompoundAccessControlCondition.OPERATORS),
            operands=[],
        )

    # > 1 operand for not operator
    with pytest.raises(InvalidCondition):
        _ = CompoundAccessControlCondition(
            operator=CompoundAccessControlCondition.NOT_OPERATOR,
            operands=[time_condition, rpc_condition],
        )

    # < 2 operands for or operator
    with pytest.raises(InvalidCondition):
        _ = CompoundAccessControlCondition(
            operator=CompoundAccessControlCondition.OR_OPERATOR,
            operands=[time_condition],
        )

    # < 2 operands for and operator
    with pytest.raises(InvalidCondition):
        _ = CompoundAccessControlCondition(
            operator=CompoundAccessControlCondition.AND_OPERATOR,
            operands=[rpc_condition],
        )

    # exceeds max operands
    operands = list()
    for i in range(CompoundAccessControlCondition.MAX_NUM_CONDITIONS + 1):
        operands.append(rpc_condition)
    with pytest.raises(InvalidCondition):
        _ = CompoundAccessControlCondition(
            operator=CompoundAccessControlCondition.OR_OPERATOR,
            operands=operands,
        )
    with pytest.raises(InvalidCondition):
        _ = CompoundAccessControlCondition(
            operator=CompoundAccessControlCondition.AND_OPERATOR,
            operands=operands,
        )


@pytest.mark.parametrize("operator", CompoundAccessControlCondition.OPERATORS)
def test_compound_condition_schema_validation(operator, time_condition, rpc_condition):
    if operator == CompoundAccessControlCondition.NOT_OPERATOR:
        operands = [time_condition]
    else:
        operands = [time_condition, rpc_condition]

    compound_condition = CompoundAccessControlCondition(
        operator=operator, operands=operands
    )
    compound_condition_dict = compound_condition.to_dict()

    # no issues here
    CompoundAccessControlCondition.from_dict(compound_condition_dict)

    # no issues with optional name
    compound_condition_dict["name"] = "my_contract_condition"
    CompoundAccessControlCondition.from_dict(compound_condition_dict)

    with pytest.raises(InvalidConditionLingo):
        # incorrect condition type
        compound_condition_dict = compound_condition.to_dict()
        compound_condition_dict["condition_type"] = ConditionType.RPC.value
        CompoundAccessControlCondition.from_dict(compound_condition_dict)

    with pytest.raises(InvalidConditionLingo):
        # invalid operator
        compound_condition_dict = compound_condition.to_dict()
        compound_condition_dict["operator"] = "5True"
        CompoundAccessControlCondition.from_dict(compound_condition_dict)

    with pytest.raises(InvalidConditionLingo):
        # no operator
        compound_condition_dict = compound_condition.to_dict()
        del compound_condition_dict["operator"]
        CompoundAccessControlCondition.from_dict(compound_condition_dict)

    with pytest.raises(InvalidConditionLingo):
        # no operands
        compound_condition_dict = compound_condition.to_dict()
        del compound_condition_dict["operands"]
        CompoundAccessControlCondition.from_dict(compound_condition_dict)


@pytest.mark.usefixtures("mock_skip_schema_validation")
def test_and_condition_and_short_circuit(mock_conditions):
    condition_1, condition_2, condition_3, condition_4 = mock_conditions

    and_condition = AndCompoundCondition(
        operands=[
            condition_1,
            condition_2,
            condition_3,
            condition_4,
        ]
    )

    # ensure that all conditions evaluated when all return True
    result, value = and_condition.verify(providers={})
    assert result is True
    assert len(value) == 4, "all conditions evaluated"
    assert value == [1, 2, 3, 4]

    # ensure that short circuit happens when 1st condition is false
    condition_1.verify.return_value = (False, 1)
    result, value = and_condition.verify(providers={})
    assert result is False
    assert len(value) == 1, "only one condition evaluated"
    assert value == [1]

    # short circuit occurs for 3rd entry
    condition_1.verify.return_value = (True, 1)
    condition_3.verify.return_value = (False, 3)
    result, value = and_condition.verify(providers={})
    assert result is False
    assert len(value) == 3, "3-of-4 conditions evaluated"
    assert value == [1, 2, 3]


@pytest.mark.usefixtures("mock_skip_schema_validation")
def test_or_condition_and_short_circuit(mock_conditions):
    condition_1, condition_2, condition_3, condition_4 = mock_conditions

    or_condition = OrCompoundCondition(
        operands=[
            condition_1,
            condition_2,
            condition_3,
            condition_4,
        ]
    )

    # ensure that only first condition evaluated when first is True
    condition_1.verify.return_value = (True, 1)  # short circuit here
    result, value = or_condition.verify(providers={})
    assert result is True
    assert len(value) == 1, "only first condition needs to be evaluated"
    assert value == [1]

    # ensure first True condition is returned
    condition_1.verify.return_value = (False, 1)
    condition_2.verify.return_value = (False, 2)
    condition_3.verify.return_value = (True, 3)  # short circuit here

    result, value = or_condition.verify(providers={})
    assert result is True
    assert len(value) == 3, "third condition causes short circuit"
    assert value == [1, 2, 3]

    # no short circuit occurs when all are False
    condition_1.verify.return_value = (False, 1)
    condition_2.verify.return_value = (False, 2)
    condition_3.verify.return_value = (False, 3)
    condition_4.verify.return_value = (False, 4)

    result, value = or_condition.verify(providers={})
    assert result is False
    assert len(value) == 4, "all conditions evaluated"
    assert value == [1, 2, 3, 4]


@pytest.mark.usefixtures("mock_skip_schema_validation")
def test_compound_condition(mock_conditions):
    condition_1, condition_2, condition_3, condition_4 = mock_conditions

    compound_condition = AndCompoundCondition(
        operands=[
            OrCompoundCondition(
                operands=[
                    condition_1,
                    condition_2,
                    condition_3,
                ]
            ),
            condition_4,
        ]
    )

    # all conditions are True
    result, value = compound_condition.verify(providers={})
    assert result is True
    assert len(value) == 2, "or_condition and condition_4"
    assert value == [[1], 4]

    # or condition is False
    condition_1.verify.return_value = (False, 1)
    condition_2.verify.return_value = (False, 2)
    condition_3.verify.return_value = (False, 3)
    result, value = compound_condition.verify(providers={})
    assert result is False
    assert len(value) == 1, "or_condition"
    assert value == [
        [1, 2, 3]
    ]  # or-condition does not short circuit, but and-condition is short-circuited because or-condition is False

    # or condition is True but condition 4 is False
    condition_1.verify.return_value = (True, 1)
    condition_4.verify.return_value = (False, 4)

    result, value = compound_condition.verify(providers={})
    assert result is False
    assert len(value) == 2, "or_condition and condition_4"
    assert value == [
        [1],
        4,
    ]  # or-condition short-circuited because condition_1 was True

    # condition_4 is now true
    condition_4.verify.return_value = (True, 4)
    result, value = compound_condition.verify(providers={})
    assert result is True
    assert len(value) == 2, "or_condition and condition_4"
    assert value == [
        [1],
        4,
    ]  # or-condition short-circuited because condition_1 was True


def test_nested_compound_condition_too_many_nested_levels(
    rpc_condition, time_condition
):
    with pytest.raises(
        InvalidCondition, match="nested levels of multi-conditions are allowed"
    ):
        _ = AndCompoundCondition(
            operands=[
                OrCompoundCondition(
                    operands=[
                        rpc_condition,
                        AndCompoundCondition(
                            operands=[
                                time_condition,
                                rpc_condition,
                            ]
                        ),
                    ]
                ),
                time_condition,
            ]
        )


def test_nested_sequential_condition_too_many_nested_levels(
    rpc_condition, time_condition
):
    with pytest.raises(
        InvalidCondition, match="nested levels of multi-conditions are allowed"
    ):
        _ = AndCompoundCondition(
            operands=[
                OrCompoundCondition(
                    operands=[
                        rpc_condition,
                        SequentialAccessControlCondition(
                            condition_variables=[
                                ConditionVariable("var2", time_condition),
                                ConditionVariable("var3", rpc_condition),
                            ]
                        ),
                    ]
                ),
                time_condition,
            ]
        )


@pytest.mark.usefixtures("mock_skip_schema_validation")
def test_nested_compound_condition(mock_conditions):
    condition_1, condition_2, condition_3, condition_4 = mock_conditions

    nested_compound_condition = AndCompoundCondition(
        operands=[
            OrCompoundCondition(
                operands=[
                    condition_1,
                    condition_2,
                    condition_3,
                ]
            ),
            condition_4,
        ]
    )

    # all conditions are True
    result, value = nested_compound_condition.verify(providers={})
    assert result is True
    assert len(value) == 2, "or_condition (condition_1) and condition_4"
    assert value == [[1], 4]  # or short-circuited since condition_1 is True

    # set condition_1 to False so condition_2 must be evaluated
    condition_1.verify.return_value = (False, 1)

    result, value = nested_compound_condition.verify(providers={})
    assert result is True
    assert len(value) == 2, "or_condition (condition_2) and condition_4"
    assert value == [
        [1, 2],
        4,
    ]  # or short-circuited since condition_2 is True

    # set condition_3 to False so condition_3 must be evaluated
    condition_2.verify.return_value = (False, 2)

    result, value = nested_compound_condition.verify(providers={})
    assert result is True
    assert len(value) == 2, "or_condition (condition_3) and condition_4"
    assert value == [
        [1, 2, 3],
        4,
    ]  # or short-circuited since condition_3 is True

    # set condition_4 to False so that overall result flips to False
    # (even though condition_3 is still True)
    condition_4.verify.return_value = (False, 4)
    result, value = nested_compound_condition.verify(providers={})
    assert result is False
    assert len(value) == 2, "or_condition and condition_4"
    assert value == [[1, 2, 3], 4]


@pytest.mark.usefixtures("mock_skip_schema_validation")
def test_not_compound_condition(mock_conditions):
    condition_1, condition_2, condition_3, condition_4 = mock_conditions

    not_condition = NotCompoundCondition(operand=condition_1)

    #
    # simple `not`
    #
    condition_1.verify.return_value = (True, 1)
    result, value = not_condition.verify(providers={})
    assert result is False
    assert value == 1

    condition_1.verify.return_value = (False, 2)
    result, value = not_condition.verify(providers={})
    assert result is True
    assert value == 2

    #
    # `not` of `or` condition
    #

    # only True
    condition_1.verify.return_value = (True, 1)
    condition_2.verify.return_value = (True, 2)
    condition_3.verify.return_value = (True, 3)

    or_condition = OrCompoundCondition(
        operands=[
            condition_1,
            condition_2,
            condition_3,
        ]
    )
    not_condition = NotCompoundCondition(operand=or_condition)
    or_result, or_value = or_condition.verify(providers={})
    result, value = not_condition.verify(providers={})
    assert result is False
    assert result is (not or_result)
    assert value == or_value

    # only False
    condition_1.verify.return_value = (False, 1)
    condition_2.verify.return_value = (False, 2)
    condition_3.verify.return_value = (False, 3)
    or_result, or_value = or_condition.verify(providers={})
    result, value = not_condition.verify(providers={})
    assert result is True
    assert result is (not or_result)
    assert value == or_value

    # mixture of True/False
    condition_1.verify.return_value = (False, 1)
    condition_2.verify.return_value = (False, 2)
    condition_3.verify.return_value = (True, 3)
    or_result, or_value = or_condition.verify(providers={})
    result, value = not_condition.verify(providers={})
    assert result is False
    assert result is (not or_result)
    assert value == or_value

    #
    # `not` of `and` condition
    #

    # only True
    condition_1.verify.return_value = (True, 1)
    condition_2.verify.return_value = (True, 2)
    condition_3.verify.return_value = (True, 3)

    and_condition = AndCompoundCondition(
        operands=[
            condition_1,
            condition_2,
            condition_3,
        ]
    )
    not_condition = NotCompoundCondition(operand=and_condition)

    and_result, and_value = and_condition.verify(providers={})
    result, value = not_condition.verify(providers={})
    assert result is False
    assert result is (not and_result)
    assert value == and_value

    # only False
    condition_1.verify.return_value = (False, 1)
    condition_2.verify.return_value = (False, 2)
    condition_3.verify.return_value = (False, 3)
    and_result, and_value = and_condition.verify(providers={})
    result, value = not_condition.verify(providers={})
    assert result is True
    assert result is (not and_result)
    assert value == and_value

    # mixture of True/False
    condition_1.verify.return_value = (False, 1)
    condition_2.verify.return_value = (True, 2)
    condition_3.verify.return_value = (False, 3)
    and_result, and_value = and_condition.verify(providers={})
    result, value = not_condition.verify(providers={})
    assert result is True
    assert result is (not and_result)
    assert value == and_value
