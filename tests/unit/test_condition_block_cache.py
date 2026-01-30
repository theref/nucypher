"""
Tests for ConditionProviderManager latest block caching.

These tests verify that:
1. get_latest_block() caches the result per chain
2. Cache expires after short TTL (2 seconds default)
3. Multiple chains are cached independently
4. TTL is configurable via environment variable
5. Thread safety under concurrent access
"""

import time
from concurrent.futures import ThreadPoolExecutor, wait
from unittest.mock import MagicMock, patch

import pytest

from nucypher.policy.conditions.utils import ConditionProviderManager


@pytest.fixture
def mock_provider():
    """Create a mock HTTPProvider."""
    provider = MagicMock()
    provider.endpoint_uri = "https://mock-rpc.example.com"
    return provider


@pytest.fixture
def mock_web3(mock_provider):
    """Create a mock Web3 instance with block data."""
    w3 = MagicMock()
    w3.provider = mock_provider

    # Mock chain_id
    w3.eth.chain_id = 1

    # Mock get_block to return a block with timestamp
    block_data = MagicMock()
    block_data.__getitem__ = lambda self, key: {
        "number": 12345678,
        "timestamp": int(time.time()),
        "hash": b"0x" + b"a" * 64,
    }[key]
    block_data.timestamp = int(time.time())
    block_data.number = 12345678
    w3.eth.get_block = MagicMock(return_value=block_data)

    return w3


@pytest.fixture
def provider_manager(mock_provider, mock_web3):
    """Create a ConditionProviderManager with mocked providers."""
    providers = {
        1: [mock_provider],  # Ethereum mainnet
        137: [mock_provider],  # Polygon
    }

    manager = ConditionProviderManager(providers=providers)
    # Store the mock for assertion access
    manager._mock_web3 = mock_web3

    # Patch web3_endpoints to return our mock directly
    def mock_web3_endpoints(chain_id):
        yield mock_web3

    manager.web3_endpoints = mock_web3_endpoints
    return manager


class TestLatestBlockCacheBasics:
    """Test basic cache hit/miss behavior."""

    def test_get_latest_block_caches_result(self, provider_manager):
        """First call fetches from chain, second call uses cache."""
        chain_id = 1

        # First call - should hit the RPC
        block1 = provider_manager.get_latest_block(chain_id)
        assert provider_manager._mock_web3.eth.get_block.call_count == 1

        # Second call - should use cache, not hit RPC again
        block2 = provider_manager.get_latest_block(chain_id)
        assert provider_manager._mock_web3.eth.get_block.call_count == 1  # Still 1

        # Should return the same block data
        assert block1["number"] == block2["number"]

    def test_different_chains_cached_separately(self, provider_manager):
        """Each chain_id has its own cache entry."""
        # Fetch block for chain 1
        provider_manager.get_latest_block(1)
        call_count_after_chain_1 = provider_manager._mock_web3.eth.get_block.call_count

        # Fetch block for chain 137 - should hit RPC (different key)
        provider_manager.get_latest_block(137)
        assert (
            provider_manager._mock_web3.eth.get_block.call_count
            == call_count_after_chain_1 + 1
        )

        # Fetch chain 1 again - should use cache
        provider_manager.get_latest_block(1)
        assert (
            provider_manager._mock_web3.eth.get_block.call_count
            == call_count_after_chain_1 + 1
        )  # Still same


class TestLatestBlockCacheTTL:
    """Test cache TTL expiration behavior."""

    def test_cache_expires_after_ttl(self, provider_manager):
        """Cache entries should expire and trigger fresh fetch."""
        chain_id = 1

        # First call - cache miss
        provider_manager.get_latest_block(chain_id)
        assert provider_manager._mock_web3.eth.get_block.call_count == 1

        # Call within TTL (default 2s) - should hit cache
        time.sleep(0.5)
        provider_manager.get_latest_block(chain_id)
        assert provider_manager._mock_web3.eth.get_block.call_count == 1  # Still 1

        # Call after TTL - TTLCache uses second-level precision with maya.now(),
        # so need to wait TTL + 1 second to guarantee expiration (2 + 1 = 3s)
        time.sleep(3.1)
        provider_manager.get_latest_block(chain_id)
        assert provider_manager._mock_web3.eth.get_block.call_count == 2  # Now 2

    def test_ttl_configurable_via_environment(self):
        """Cache TTL should be configurable via environment variable."""
        # Create fresh mocks for this test to avoid state sharing
        fresh_mock_web3 = MagicMock()
        fresh_mock_web3.eth.chain_id = 1

        block_data = MagicMock()
        block_data.timestamp = int(time.time())
        block_data.number = 12345678
        fresh_mock_web3.eth.get_block = MagicMock(return_value=block_data)

        # Since _BLOCK_CACHE_TTL is evaluated at class definition time,
        # we need to patch the class attribute directly
        with patch.object(ConditionProviderManager, "_BLOCK_CACHE_TTL", 1):
            providers = {1: [MagicMock()]}
            manager = ConditionProviderManager(providers=providers)

            # Verify the cache was created with our patched TTL
            assert manager._block_cache.ttl == 1

            # Patch web3_endpoints to return our mock directly
            def mock_web3_endpoints(chain_id):
                yield fresh_mock_web3

            manager.web3_endpoints = mock_web3_endpoints

            chain_id = 1

            # First call
            manager.get_latest_block(chain_id)
            assert fresh_mock_web3.eth.get_block.call_count == 1

            # Call after 2.1 seconds - TTLCache uses second-level precision with
            # maya.now(), so need to wait TTL + 1 second to guarantee expiration
            time.sleep(2.1)
            manager.get_latest_block(chain_id)
            assert fresh_mock_web3.eth.get_block.call_count == 2


class TestLatestBlockCacheThreadSafety:
    """Test thread safety of cache operations."""

    def test_concurrent_reads_same_chain(self, provider_manager):
        """Multiple threads reading same chain should not cause issues."""
        chain_id = 1
        num_threads = 10
        num_reads_per_thread = 20

        def read_block():
            for _ in range(num_reads_per_thread):
                block = provider_manager.get_latest_block(chain_id)
                assert block is not None

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(read_block) for _ in range(num_threads)]
            wait(futures, timeout=10)

        # All reads should succeed
        for f in futures:
            f.result()  # Raises if any thread failed

        # Should have made only a few RPC calls (not 200)
        # Due to TTL being very short and real time passing, we may get more than 1
        # But should be far fewer than 200
        assert provider_manager._mock_web3.eth.get_block.call_count < 50


class TestTimeConditionIntegration:
    """Test that TimeCondition uses the cached block."""

    def test_time_condition_uses_cached_block(self, provider_manager, mock_web3):
        """TimeRPCCall should use get_latest_block for caching."""
        from nucypher.policy.conditions.time import TimeRPCCall

        # Create a TimeRPCCall
        time_call = TimeRPCCall(chain=1, method="blocktime")

        # First execution
        with patch.object(ConditionProviderManager, "web3_endpoints") as mock_endpoints:
            mock_endpoints.return_value = iter([mock_web3])

            # Execute the time call - should get block timestamp
            time_call.execute(providers=provider_manager)
            initial_call_count = mock_web3.eth.get_block.call_count

            # Execute again - should use cached block
            time_call.execute(providers=provider_manager)

            # Should not have made additional get_block calls if caching is working
            # Note: This test will fail until we implement the caching in TimeRPCCall
            assert mock_web3.eth.get_block.call_count == initial_call_count
