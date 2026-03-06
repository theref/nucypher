from pathlib import Path

import pytest

from nucypher.blockchain.eth import domains
from nucypher.blockchain.eth.signers.software import InMemorySigner
from nucypher.characters.chaotic import (
    NiceGuyEddie,
    ThisBobAlwaysDecrypts,
    ThisBobAlwaysFails,
)
from nucypher.characters.lawful import Ursula
from nucypher.policy.conditions.lingo import ConditionLingo
from nucypher.policy.conditions.wasm.conditions import WasmCondition
from tests.constants import (
    MOCK_ETH_PROVIDER_URI,
    MOCK_REGISTRY_FILEPATH,
)

_WASM_PATH = (
    Path(__file__).parents[2]
    / "wasm_fixtures"
    / "conditions"
    / "out"
    / "always_true.wasm"
)


def _attempt_decryption(BobClass, plaintext, testerchain):
    trinket = 80  # Doens't matter.

    enrico = NiceGuyEddie(encrypting_key=trinket, signer=InMemorySigner())
    bob = BobClass(
        registry=MOCK_REGISTRY_FILEPATH,
        domain=domains.LYNX,
        eth_endpoint=MOCK_ETH_PROVIDER_URI,
        polygon_endpoint=MOCK_ETH_PROVIDER_URI,
    )

    wasm_condition = WasmCondition(
        wasm_bytes=_WASM_PATH.read_bytes(), name="always-true"
    )
    definitely_false_condition = ConditionLingo(wasm_condition).to_dict()

    threshold_message_kit = enrico.encrypt_for_dkg(
        plaintext=plaintext,
        conditions=definitely_false_condition,
    )

    decrypted_cleartext = bob.threshold_decrypt(
        threshold_message_kit=threshold_message_kit,
    )

    return decrypted_cleartext


def test_user_controls_success(testerchain):
    plaintext = b"ever thus to deadbeats"
    result = _attempt_decryption(ThisBobAlwaysDecrypts, plaintext, testerchain)
    assert bytes(result) == bytes(plaintext)


def test_user_controls_failure(testerchain):
    plaintext = b"ever thus to deadbeats"
    with pytest.raises(Ursula.NotEnoughUrsulas):
        _ = _attempt_decryption(ThisBobAlwaysFails, plaintext, testerchain)
