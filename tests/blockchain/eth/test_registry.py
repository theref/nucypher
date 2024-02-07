import unittest
from unittest.mock import Mock, patch

from nucypher.blockchain.eth.registry import GithubRegistrySource


class TestGithubRegistrySource(unittest.TestCase):

    def test_get_publication_endpoint_correct_url(self):
        domain = 'mainnet'
        expected_url = 'https://raw.githubusercontent.com/nucypher/nucypher/development/nucypher/blockchain/eth/contract_registry/mainnet.json'
        source = GithubRegistrySource(domain=domain)
        self.assertEqual(source.get_publication_endpoint(), expected_url)

    @patch('requests.Response.json')
    def test_decode_successful_json(self, mock_json):
        mock_json.return_value = {'data': 'valid'}
        response = Mock()
        source = GithubRegistrySource(domain='mainnet')
        self.assertEqual(source.decode(response, ''), {'data': 'valid'})

    @patch('requests.Response.json', side_effect=ValueError)
    def test_decode_invalid_json(self, mock_json):
        response = Mock()
        source = GithubRegistrySource(domain='mainnet')
        with self.assertRaises(GithubRegistrySource.Invalid):
            source.decode(response, '')

    def test_validate_response_success(self):
        response = Mock()
        response.status_code = 200
        source = GithubRegistrySource(domain='mainnet')
        try:
            source.validate_response(response)
        except GithubRegistrySource.Unavailable:
            self.fail("validate_response raised Unavailable unexpectedly!")

    def test_validate_response_failure(self):
        for status_code in [400, 404, 500]:
            with self.subTest(status_code=status_code):
                response = Mock()
                response.status_code = status_code
                source = GithubRegistrySource(domain='mainnet')
                with self.assertRaises(GithubRegistrySource.Unavailable):
                    source.validate_response(response)
