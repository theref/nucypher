import pytest

from nucypher.policy.conditions.exceptions import (
    InvalidCondition,
    InvalidConditionLingo,
)
from nucypher.policy.conditions.lingo import ConditionType, ReturnValueTest
from nucypher.policy.conditions.time import TimeCondition, TimeRPCCall
from tests.constants import TESTERCHAIN_CHAIN_ID


def test_invalid_time_condition():
    # invalid condition type
    with pytest.raises(InvalidCondition, match=ConditionType.TIME.value):
        _ = TimeCondition(
            condition_type=ConditionType.COMPOUND.value,
            return_value_test=ReturnValueTest(">", 0),
            chain=TESTERCHAIN_CHAIN_ID,
            method=TimeRPCCall.METHOD,
        )

    # invalid method
    with pytest.raises(InvalidCondition):
        _ = TimeCondition(
            return_value_test=ReturnValueTest(">", 0),
            chain=TESTERCHAIN_CHAIN_ID,
            method="time_after_time",
        )


def test_time_condition_schema_validation(time_condition):
    condition_dict = time_condition.to_dict()

    # no issues here
    TimeCondition.from_dict(condition_dict)

    # no issues with optional name
    condition_dict["name"] = "my_time_machine"
    TimeCondition.from_dict(condition_dict)

    with pytest.raises(InvalidConditionLingo):
        # no method
        condition_dict = time_condition.to_dict()
        del condition_dict["method"]
        TimeCondition.from_dict(condition_dict)

    with pytest.raises(InvalidConditionLingo):
        # no returnValueTest defined
        condition_dict = time_condition.to_dict()
        del condition_dict["returnValueTest"]
        TimeCondition.from_dict(condition_dict)

    with pytest.raises(InvalidConditionLingo):
        # invalid method name
        condition_dict = time_condition.to_dict()
        condition_dict["method"] = "my_blocktime"
        TimeCondition.from_dict(condition_dict)

    with pytest.raises(InvalidConditionLingo):
        # chain id not an integer
        condition_dict = time_condition.to_dict()
        condition_dict["chain"] = str(TESTERCHAIN_CHAIN_ID)
        TimeCondition.from_dict(condition_dict)


@pytest.mark.parametrize(
    "invalid_value", ["0x123456", 10.15, [1], [1, 2, 3], [True, [1, 2], "0x0"]]
)
def test_time_condition_invalid_comparator_value_type(invalid_value, time_condition):
    with pytest.raises(InvalidCondition, match="must be an integer"):
        _ = TimeCondition(
            chain=time_condition.chain,
            return_value_test=ReturnValueTest(
                comparator=time_condition.return_value_test.comparator,
                value=invalid_value,
            ),
        )
