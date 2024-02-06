import unittest
from unittest.mock import MagicMock, patch

from nucypher.blockchain.eth.registry import GithubRegistrySource
from nucypher.utilities.events import EventScanner
from web3.datastructures import AttributeDict


class TestGithubRegistrySource(unittest.TestCase):

    @patch('requests.get')
    def test_get_publication_endpoint(self, mock_get):
        domain = 'mainnet'
        source = GithubRegistrySource(domain=domain)
        expected_url = 'https://raw.githubusercontent.com/nucypher/nucypher/main/nucypher/blockchain/eth/contract_registry/mainnet.json'
        self.assertEqual(source.get_publication_endpoint(), expected_url)

    @patch('requests.get')
    def test_decode_valid_json(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.return_value = {'data': 'valid'}
        source = GithubRegistrySource(domain='mainnet')
        decoded_data = source.decode(response=mock_response, endpoint='dummy_endpoint')
        self.assertEqual(decoded_data, {'data': 'valid'})

    @patch('requests.get')
    def test_decode_invalid_json(self, mock_get):
        mock_response = MagicMock()
        mock_response.json.side_effect = ValueError
        source = GithubRegistrySource(domain='mainnet')
        with self.assertRaises(GithubRegistrySource.Invalid):
            source.decode(response=mock_response, endpoint='dummy_endpoint')

class TestEventProcessing(unittest.TestCase):

    @patch('web3.Web3.eth.get_logs')
    def test_fetch_events(self, mock_get_logs):
        mock_get_logs.return_value = [AttributeDict({'event': 'TestEvent', 'blockNumber': 123})]
        scanner = EventScanner(web3=MagicMock(), contract=MagicMock(), state=MagicMock(), events=[], filters={})
        events = list(scanner.scan_chunk(0, 999))
        self.assertEqual(len(events[2]), 1)
        self.assertEqual(events[2][0]['event'], 'TestEvent')

    @patch('web3.Web3.eth.get_logs')
    def test_process_event(self, mock_get_logs):
        mock_get_logs.return_value = [AttributeDict({'event': 'TestEvent', 'blockNumber': 123})]
        state = MagicMock()
        scanner = EventScanner(web3=MagicMock(), contract=MagicMock(), state=state, events=[], filters={})
        scanner.scan_chunk(0, 999)
        state.process_event.assert_called()

if __name__ == '__main__':
    unittest.main()
