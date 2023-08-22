"""
This file is part of nucypher.

nucypher is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

nucypher is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with nucypher.  If not, see <https://www.gnu.org/licenses/>.
"""


from decimal import Decimal, DecimalException
from ipaddress import ip_address
from pathlib import Path

import click
from cryptography.exceptions import InternalError
from eth_utils import to_checksum_address
from nucypher_core.umbral import PublicKey

from nucypher.blockchain.economics import Economics
from nucypher.blockchain.eth.interfaces import BlockchainInterface
from nucypher.blockchain.eth.networks import NetworksInventory
from nucypher.blockchain.eth.token import NU, TToken
from nucypher.policy.payment import PAYMENT_METHODS
from nucypher.utilities.networking import validate_operator_ip, InvalidOperatorIP


class ChecksumAddress(click.ParamType):
    name = 'checksum_address'

    def convert(self, value, param, ctx):
        try:
            value = to_checksum_address(value=value)
        except ValueError as e:
            self.fail("Invalid ethereum address")
        else:
            return value


class IPv4Address(click.ParamType):
    name = 'ipv4_address'

    def convert(self, value, param, ctx):
        try:
            _address = ip_address(value)
        except ValueError:
            self.fail("Invalid IP Address")
        else:
            return value


class OperatorIPAddress(IPv4Address):
    name = 'operator_ip'

    def convert(self, value, param, ctx):
        _ip = super().convert(value, param, ctx)
        try:
            validate_operator_ip(ip=_ip)
        except InvalidOperatorIP as e:
            self.fail(str(e))
        return value


class DecimalType(click.ParamType):
    name = 'decimal'

    def convert(self, value, param, ctx):
        try:
            return Decimal(value)
        except DecimalException:
            self.fail(f"'{value}' is an invalid decimal number")


class DecimalRange(DecimalType):
    name = 'decimal_range'

    def __init__(self, min=None, max=None, clamp=False):
        self.min = min
        self.max = max
        self.clamp = clamp

    def convert(self, value, param, ctx):
        rv = DecimalType.convert(self, value, param, ctx)
        if self.clamp:
            if self.min is not None and rv < self.min:
                return self.min
            if self.max is not None and rv > self.max:
                return self.max
        if self.min is not None and rv < self.min or \
           self.max is not None and rv > self.max:
            if self.min is None:
                self.fail(f'{rv} is bigger than the maximum valid value {self.max}')
            elif self.max is None:
                self.fail(f'{rv} is smaller than the minimum valid value {self.min}')
            else:
                self.fail(f'{rv} is not in the valid range of {self.min} to {self.max}')
        return rv


class NuCypherNetworkName(click.ParamType):
    name = 'nucypher_network_name'

    def __init__(self, validate: bool = True):
        self.validate = validate

    def convert(self, value, param, ctx):
        if not self.validate:
            return value
        network = str(value).lower()
        if network not in NetworksInventory.NETWORKS:
            self.fail(f"'{value}' is not a NuCypher Network. Valid options are: {list(NetworksInventory.NETWORKS)}")
        else:
            return network


class UmbralPublicKeyHex(click.ParamType):
    name = 'nucypher_umbral_public_key'

    def __init__(self, validate: bool = True):
        self.validate = validate

    def convert(self, value, param, ctx):
        if self.validate:
            try:
                _key = PublicKey.from_bytes(bytes.fromhex(value))
            except (InternalError, ValueError):
                self.fail(f"'{value}' is not a valid nucypher public key.")
        return value


# Ethereum
EIP55_CHECKSUM_ADDRESS = ChecksumAddress()
WEI = click.IntRange(min=1, clamp=False)  # TODO: Better validation for ether and wei values?
GWEI = DecimalRange(min=0)

__min_authorization = TToken.from_units(Economics._default_min_authorization).to_tokens()
MIN_AUTHORIZATION = Decimal(__min_authorization)
STAKED_TOKENS_RANGE = DecimalRange(min=__min_authorization)

# Filesystem
EXISTING_WRITABLE_DIRECTORY = click.Path(exists=True, dir_okay=True, file_okay=False, writable=True, path_type=Path)
EXISTING_READABLE_FILE = click.Path(exists=True, dir_okay=False, file_okay=True, readable=True, path_type=Path)

# Network
NETWORK_PORT = click.IntRange(min=0, max=65535, clamp=False)
IPV4_ADDRESS = IPv4Address()
OPERATOR_IP = OperatorIPAddress()

GAS_STRATEGY_CHOICES = click.Choice(list(BlockchainInterface.GAS_STRATEGIES.keys()))
PAYMENT_METHOD_CHOICES = click.Choice(list(PAYMENT_METHODS))
UMBRAL_PUBLIC_KEY_HEX = UmbralPublicKeyHex()
