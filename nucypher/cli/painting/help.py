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


import click
from constant_sorrow.constants import NO_KEYSTORE_ATTACHED

from nucypher.blockchain.eth.sol.__conf__ import SOLIDITY_COMPILER_VERSION
from nucypher.characters.banners import NUCYPHER_BANNER
from nucypher.config.constants import (
    DEFAULT_CONFIG_ROOT,
    USER_LOG_DIR
)


def echo_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.secho(NUCYPHER_BANNER, bold=True)
    ctx.exit()


def echo_solidity_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.secho(f"Supported solidity version: {SOLIDITY_COMPILER_VERSION}", bold=True)
    ctx.exit()


def echo_config_root_path(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.secho(str(DEFAULT_CONFIG_ROOT.absolute()))
    ctx.exit()


def echo_logging_root_path(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.secho(str(USER_LOG_DIR.absolute()))
    ctx.exit()


def paint_new_installation_help(emitter, new_configuration, filepath):
    character_config_class = new_configuration.__class__
    character_name = character_config_class.NAME.lower()
    if new_configuration.keystore != NO_KEYSTORE_ATTACHED:
        maybe_public_key = new_configuration.keystore.id
    else:
        maybe_public_key = "(no keystore attached)"
    emitter.message(f"Generated keystore", color='green')
    emitter.message(f"""
    
Public Key:   {maybe_public_key}
Path to Keystore: {new_configuration.keystore_dir}

- You can share your public key with anyone. Others need it to interact with you.
- Never share secret keys with anyone! 
- Backup your keystore! Character keys are required to interact with the protocol!
- Remember your password! Without the password, it's impossible to decrypt the key!

""")

    default_config_filepath = True
    if new_configuration.default_filepath() != filepath:
        default_config_filepath = False
    emitter.message(f'Generated configuration file at {"default" if default_config_filepath else "non-default"} '
                    f'filepath {filepath}', color='green')

    # add hint about --config-file
    if not default_config_filepath:
        emitter.message(f'* NOTE: for a non-default configuration filepath use `--config-file "{filepath}"` '
                        f'with subsequent `{character_name}` CLI commands', color='yellow')

    # Ursula
    if character_name == 'ursula':
        hint = '''
* Review configuration  -> nucypher ursula config
* Start working         -> nucypher ursula run
'''

    else:
        raise ValueError(f'Unknown character type "{character_name}"')

    emitter.echo(hint, color='green')
