"""
Tests for WASM condition demonstration fixtures (compiled Rust -> .wasm).

These tests load pre-compiled .wasm fixtures from tests/wasm_fixtures/conditions/out/
and exercise them with mocked providers, verifying the full evaluation pipeline
from WasmEvaluator through host functions.

Rebuild fixtures with: cd tests/wasm_fixtures/conditions && bash build.sh
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from nucypher.policy.conditions.utils import ConditionProviderManager
from nucypher.policy.conditions.wasm.conditions import WasmCondition
from nucypher.policy.conditions.wasm.evaluator import WasmEvaluator

# Path to compiled fixture .wasm files
FIXTURES_DIR = (
    Path(__file__).parent.parent.parent.parent / "wasm_fixtures" / "conditions" / "out"
)

# Rust-compiled modules need more memory pages than hand-written WAT modules.
# The Rust allocator (dlmalloc) and serde_json need heap space for parsing.
RUST_MAX_PAGES = 256  # 256 * 64KB = 16 MB


def _load_fixture(name: str) -> bytes:
    """Load a compiled .wasm fixture by name."""
    path = FIXTURES_DIR / f"{name}.wasm"
    if not path.exists():
        pytest.skip(
            f"Fixture {name}.wasm not found. Run: cd tests/wasm_fixtures/conditions && bash build.sh"
        )
    return path.read_bytes()


def _mock_providers(chain_responses=None, block_timestamps=None):
    """
    Create a mock ConditionProviderManager.

    Args:
        chain_responses: dict mapping (chain_id,) to bytes response for eth_call
        block_timestamps: dict mapping chain_id to timestamp (int)
    """
    chain_responses = chain_responses or {}
    block_timestamps = block_timestamps or {}

    providers = MagicMock(spec=ConditionProviderManager)

    def mock_exec_web3_call(chain_id, fn, **kwargs):
        # Create a mock Web3 that returns our predetermined response
        mock_w3 = MagicMock()

        if chain_id in block_timestamps:
            # Check if this is a block timestamp call by trying it
            mock_w3.eth.get_block.return_value = {
                "timestamp": block_timestamps[chain_id]
            }

        if chain_id in chain_responses:
            mock_w3.eth.call.return_value = chain_responses[chain_id]

        return fn(mock_w3)

    providers.exec_web3_call.side_effect = mock_exec_web3_call
    return providers


# ── ABI Encoding Helpers ────────────────────────────────────────────────


def _abi_encode_uint256(value: int) -> bytes:
    """Encode a uint256 as 32 big-endian bytes."""
    return value.to_bytes(32, byteorder="big")


def _abi_encode_address(address: str) -> bytes:
    """Encode an address as a left-padded 32-byte word."""
    addr = address.lower().replace("0x", "")
    return bytes(12) + bytes.fromhex(addr)


def _abi_encode_balance_of(address: str) -> bytes:
    """Encode balanceOf(address) calldata."""
    selector = bytes.fromhex("70a08231")
    return selector + _abi_encode_address(address)


def _abi_encode_owner_of(token_id: int) -> bytes:
    """Encode ownerOf(uint256) calldata."""
    selector = bytes.fromhex("6352211e")
    return selector + _abi_encode_uint256(token_id)


def _encode_execute_batch(targets, values, datas=None):
    """
    Encode executeBatch(address[], uint256[], bytes[]) calldata.

    This is a simplified encoder for testing — only handles the fields
    our fixture actually decodes (targets and values arrays).
    """
    # Function selector (arbitrary, fixture skips first 4 bytes)
    selector = bytes.fromhex("47e1da2a")

    # Dynamic array layout: 3 offsets + 3 arrays
    # Offset for targets: 96 (3 * 32)
    # Offset for values: 96 + 32 + len(targets) * 32
    # Offset for data: after values array

    n = len(targets)
    datas = datas or [b""] * n

    targets_offset = 96  # 3 words of offsets
    values_offset = targets_offset + 32 + n * 32
    data_offset = values_offset + 32 + n * 32

    parts = []
    # 3 offset words
    parts.append(_abi_encode_uint256(targets_offset))
    parts.append(_abi_encode_uint256(values_offset))
    parts.append(_abi_encode_uint256(data_offset))

    # targets array: length + addresses
    parts.append(_abi_encode_uint256(n))
    for t in targets:
        parts.append(_abi_encode_address(t))

    # values array: length + uint256s
    parts.append(_abi_encode_uint256(n))
    for v in values:
        parts.append(_abi_encode_uint256(v))

    # data array: length + offsets + data (simplified — empty for tests)
    parts.append(_abi_encode_uint256(n))
    # For simplicity, point all data entries to empty bytes
    data_base = n * 32
    for i in range(n):
        parts.append(_abi_encode_uint256(data_base + i * 64))
    for _ in range(n):
        parts.append(_abi_encode_uint256(0))  # length = 0
        parts.append(bytes(32))  # padding

    return selector + b"".join(parts)


# ── Test Classes ────────────────────────────────────────────────────────


class TestReadChainBalance:
    """Test the read_chain_balance fixture."""

    def test_successful_read(self):
        """read_chain returns data -> fixture returns true."""
        wasm = _load_fixture("read_chain_balance")

        # Mock provider returns a 32-byte uint256 (balance of 1000)
        balance_bytes = _abi_encode_uint256(1000)
        providers = _mock_providers(chain_responses={1: balance_bytes})

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            providers=providers,
            context={
                ":contractAddress": "0x0000000000000000000000000000000000000001",
                ":calldata": "0x70a08231" + "00" * 32,
                ":chainId": 1,
            },
        )
        assert result is True

    def test_no_provider_returns_false(self):
        """Without providers, read_chain returns 0 -> fixture returns false."""
        wasm = _load_fixture("read_chain_balance")
        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            context={
                ":contractAddress": "0x0000000000000000000000000000000000000001",
                ":calldata": "0x70a08231" + "00" * 32,
                ":chainId": 1,
            },
        )
        assert result is False


class TestCheckBlockTimestamp:
    """Test the check_block_timestamp fixture."""

    def test_timestamp_above_threshold(self):
        """Current timestamp >= minTimestamp -> true."""
        wasm = _load_fixture("check_block_timestamp")
        providers = _mock_providers(block_timestamps={1: 1700000000})

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            providers=providers,
            context={":chainId": 1, ":minTimestamp": 1600000000},
        )
        assert result is True

    def test_timestamp_below_threshold(self):
        """Current timestamp < minTimestamp -> false."""
        wasm = _load_fixture("check_block_timestamp")
        providers = _mock_providers(block_timestamps={1: 1500000000})

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            providers=providers,
            context={":chainId": 1, ":minTimestamp": 1600000000},
        )
        assert result is False

    def test_no_provider_returns_false(self):
        """Without providers, block_timestamp returns 0 -> false."""
        wasm = _load_fixture("check_block_timestamp")
        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            context={":chainId": 1, ":minTimestamp": 100},
        )
        assert result is False


class TestFetchHttps:
    """Test the fetch_https fixture."""

    @patch("requests.get")
    def test_allowed_response(self, mock_get):
        """API returns {"allowed": true} -> fixture returns true."""
        wasm = _load_fixture("fetch_https")

        mock_response = MagicMock()
        mock_response.content = json.dumps({"allowed": True}).encode()
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            context={":url": "https://api.example.com/check"},
        )
        assert result is True

    @patch("requests.get")
    def test_denied_response(self, mock_get):
        """API returns {"allowed": false} -> fixture returns false."""
        wasm = _load_fixture("fetch_https")

        mock_response = MagicMock()
        mock_response.content = json.dumps({"allowed": False}).encode()
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            context={":url": "https://api.example.com/check"},
        )
        assert result is False

    def test_no_url_returns_false(self):
        """No URL in context -> fixture returns false."""
        wasm = _load_fixture("fetch_https")
        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(wasm, context={})
        assert result is False


class TestVerifyEcdsaSig:
    """Test the verify_ecdsa_sig fixture."""

    def test_invalid_signature_returns_false(self):
        """Invalid/dummy signature -> false."""
        wasm = _load_fixture("verify_ecdsa_sig")
        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            context={
                ":message": "hello",
                ":signature": "0x" + "00" * 65,
                ":address": "0x0000000000000000000000000000000000000001",
            },
        )
        assert result is False

    @patch("nucypher.crypto.utils.verify_eip_191")
    def test_valid_signature_returns_true(self, mock_verify):
        """Mocked valid signature -> true."""
        mock_verify.return_value = True

        wasm = _load_fixture("verify_ecdsa_sig")
        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            context={
                ":message": "hello",
                ":signature": "0x" + "ab" * 65,
                ":address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            },
        )
        assert result is True


class TestVerifyJwtToken:
    """Test the verify_jwt_token fixture."""

    def test_no_token_returns_false(self):
        """No token in context -> false."""
        wasm = _load_fixture("verify_jwt_token")
        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(wasm, context={})
        assert result is False

    def test_no_issuer_returns_false(self):
        """Token without issuer -> false (host rejects)."""
        wasm = _load_fixture("verify_jwt_token")
        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            context={":token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig"},
        )
        assert result is False


class TestErc20TokenGate:
    """Test the erc20_token_gate fixture — the most common DeFi pattern."""

    def test_sufficient_balance(self):
        """User has enough tokens -> true."""
        wasm = _load_fixture("erc20_token_gate")

        # 500 tokens (with 18 decimals)
        balance = 500 * 10**18
        balance_bytes = _abi_encode_uint256(balance)
        providers = _mock_providers(chain_responses={1: balance_bytes})

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            providers=providers,
            context={
                ":tokenContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                ":userAddress": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
                ":minBalance": str(100 * 10**18),
                ":chainId": 1,
            },
        )
        assert result is True

    def test_insufficient_balance(self):
        """User doesn't have enough tokens -> false."""
        wasm = _load_fixture("erc20_token_gate")

        balance = 50 * 10**18
        balance_bytes = _abi_encode_uint256(balance)
        providers = _mock_providers(chain_responses={1: balance_bytes})

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            providers=providers,
            context={
                ":tokenContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                ":userAddress": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
                ":minBalance": str(100 * 10**18),
                ":chainId": 1,
            },
        )
        assert result is False

    def test_zero_balance(self):
        """User has zero balance -> false (unless min is also 0)."""
        wasm = _load_fixture("erc20_token_gate")

        balance_bytes = _abi_encode_uint256(0)
        providers = _mock_providers(chain_responses={1: balance_bytes})

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            providers=providers,
            context={
                ":tokenContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                ":userAddress": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
                ":minBalance": "1",
                ":chainId": 1,
            },
        )
        assert result is False

    def test_no_provider_returns_false(self):
        """Without a provider, read_chain fails -> false."""
        wasm = _load_fixture("erc20_token_gate")
        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            context={
                ":tokenContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                ":userAddress": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
                ":minBalance": "1",
                ":chainId": 1,
            },
        )
        assert result is False


class TestNftOwnership:
    """Test the nft_ownership fixture."""

    def test_owner_matches(self):
        """ownerOf returns the user's address -> true."""
        wasm = _load_fixture("nft_ownership")
        user = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

        # ownerOf returns ABI-encoded address
        owner_bytes = _abi_encode_address(user)
        providers = _mock_providers(chain_responses={1: owner_bytes})

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            providers=providers,
            context={
                ":nftContract": "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",
                ":tokenId": "42",
                ":userAddress": user,
                ":chainId": 1,
            },
        )
        assert result is True

    def test_owner_does_not_match(self):
        """ownerOf returns a different address -> false."""
        wasm = _load_fixture("nft_ownership")
        user = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        other = "0x1111111111111111111111111111111111111111"

        owner_bytes = _abi_encode_address(other)
        providers = _mock_providers(chain_responses={1: owner_bytes})

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            providers=providers,
            context={
                ":nftContract": "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",
                ":tokenId": "42",
                ":userAddress": user,
                ":chainId": 1,
            },
        )
        assert result is False


class TestTimeLocked:
    """Test the time_locked_access fixture."""

    def test_within_window(self):
        """Timestamp within [notBefore, notAfter] -> true."""
        wasm = _load_fixture("time_locked_access")
        providers = _mock_providers(block_timestamps={1: 1700000000})

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            providers=providers,
            context={
                ":notBefore": 1600000000,
                ":notAfter": 1800000000,
                ":chainId": 1,
            },
        )
        assert result is True

    def test_before_window(self):
        """Timestamp before notBefore -> false."""
        wasm = _load_fixture("time_locked_access")
        providers = _mock_providers(block_timestamps={1: 1500000000})

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            providers=providers,
            context={
                ":notBefore": 1600000000,
                ":notAfter": 1800000000,
                ":chainId": 1,
            },
        )
        assert result is False

    def test_after_window(self):
        """Timestamp after notAfter -> false."""
        wasm = _load_fixture("time_locked_access")
        providers = _mock_providers(block_timestamps={1: 1900000000})

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            providers=providers,
            context={
                ":notBefore": 1600000000,
                ":notAfter": 1800000000,
                ":chainId": 1,
            },
        )
        assert result is False

    def test_no_upper_bound(self):
        """notAfter = 0 means no upper bound."""
        wasm = _load_fixture("time_locked_access")
        providers = _mock_providers(block_timestamps={1: 9999999999})

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            providers=providers,
            context={
                ":notBefore": 1600000000,
                ":notAfter": 0,
                ":chainId": 1,
            },
        )
        assert result is True

    def test_no_provider_returns_false(self):
        """Without providers -> false."""
        wasm = _load_fixture("time_locked_access")
        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            context={":notBefore": 0, ":notAfter": 0, ":chainId": 1},
        )
        assert result is False


class TestUserOpBatchValidator:
    """
    Test the userop_batch_validator fixture.

    This is the key demonstration — complex batch transaction validation
    that was impossible with the old JSON DSL.
    """

    def test_all_targets_allowed(self):
        """All batch targets are on the allowlist -> true."""
        wasm = _load_fixture("userop_batch_validator")

        target_a = "0x1111111111111111111111111111111111111111"
        target_b = "0x2222222222222222222222222222222222222222"

        calldata = _encode_execute_batch(
            targets=[target_a, target_b],
            values=[0, 0],
        )

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            context={
                ":calldata": "0x" + calldata.hex(),
                ":allowedTargets": [target_a, target_b],
                ":maxTotalValue": "0",
            },
        )
        assert result is True

    def test_unauthorized_target_rejected(self):
        """A target NOT on the allowlist -> false."""
        wasm = _load_fixture("userop_batch_validator")

        target_a = "0x1111111111111111111111111111111111111111"
        target_b = "0x2222222222222222222222222222222222222222"
        evil = "0x6666666666666666666666666666666666666666"

        calldata = _encode_execute_batch(
            targets=[target_a, evil],
            values=[0, 0],
        )

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            context={
                ":calldata": "0x" + calldata.hex(),
                ":allowedTargets": [target_a, target_b],
                ":maxTotalValue": "0",
            },
        )
        assert result is False

    def test_value_cap_enforced(self):
        """Total value exceeds cap -> false."""
        wasm = _load_fixture("userop_batch_validator")

        target = "0x1111111111111111111111111111111111111111"

        calldata = _encode_execute_batch(
            targets=[target, target],
            values=[10**18, 10**18],  # 2 ETH total
        )

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            context={
                ":calldata": "0x" + calldata.hex(),
                ":allowedTargets": [target],
                ":maxTotalValue": str(10**18),  # Cap at 1 ETH
            },
        )
        assert result is False

    def test_value_within_cap(self):
        """Total value within cap -> true."""
        wasm = _load_fixture("userop_batch_validator")

        target = "0x1111111111111111111111111111111111111111"

        calldata = _encode_execute_batch(
            targets=[target],
            values=[5 * 10**17],  # 0.5 ETH
        )

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            context={
                ":calldata": "0x" + calldata.hex(),
                ":allowedTargets": [target],
                ":maxTotalValue": str(10**18),  # Cap at 1 ETH
            },
        )
        assert result is True

    def test_invalid_calldata_rejected(self):
        """Malformed calldata -> false."""
        wasm = _load_fixture("userop_batch_validator")

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            context={
                ":calldata": "0xdeadbeef",
                ":allowedTargets": [],
                ":maxTotalValue": "0",
            },
        )
        assert result is False

    def test_empty_batch_allowed(self):
        """Empty batch (no targets) -> true (nothing to reject)."""
        wasm = _load_fixture("userop_batch_validator")

        calldata = _encode_execute_batch(targets=[], values=[])

        evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)
        result = evaluator.evaluate(
            wasm,
            context={
                ":calldata": "0x" + calldata.hex(),
                ":allowedTargets": [],
                ":maxTotalValue": "0",
            },
        )
        assert result is True


class TestWasmConditionIntegration:
    """
    Integration tests: load .wasm fixtures through WasmCondition (the high-level API).
    """

    def test_erc20_via_condition(self):
        """Full pipeline: WasmCondition -> evaluate -> host function -> mock provider."""
        wasm = _load_fixture("erc20_token_gate")
        cond = WasmCondition(wasm_bytes=wasm, name="ERC-20 Token Gate")
        # Override the internal evaluator's memory limit for Rust modules
        cond._evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)

        balance = 1000 * 10**18
        providers = _mock_providers(chain_responses={1: _abi_encode_uint256(balance)})

        result, value = cond.verify(
            providers=providers,
            **{
                ":tokenContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                ":userAddress": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
                ":minBalance": str(100 * 10**18),
                ":chainId": 1,
            },
        )
        assert result is True

    def test_userop_via_condition(self):
        """UserOp batch validator through WasmCondition."""
        wasm = _load_fixture("userop_batch_validator")
        cond = WasmCondition(wasm_bytes=wasm, name="UserOp Batch Validator")
        cond._evaluator = WasmEvaluator(max_pages=RUST_MAX_PAGES)

        target = "0x1111111111111111111111111111111111111111"
        calldata = _encode_execute_batch(targets=[target], values=[0])

        result, value = cond.verify(
            **{
                ":calldata": "0x" + calldata.hex(),
                ":allowedTargets": [target],
                ":maxTotalValue": "0",
            },
        )
        assert result is True

    def test_serialization_roundtrip(self):
        """Serialize/deserialize a condition with a compiled fixture."""
        wasm = _load_fixture("erc20_token_gate")
        cond = WasmCondition(wasm_bytes=wasm, name="ERC-20 Token Gate")

        # to_dict -> from_dict
        d = cond.to_dict()
        cond2 = WasmCondition.from_dict(d)
        assert cond == cond2
        assert cond2.name == "ERC-20 Token Gate"

        # to_json -> from_json
        j = cond.to_json()
        cond3 = WasmCondition.from_json(j)
        assert cond == cond3
