import os

import click
from constant_sorrow.constants import NO_PASSWORD

from nucypher.blockchain.eth.decorators import validate_checksum_address
from nucypher.cli.literature import (
    COLLECT_ETH_PASSWORD,
    COLLECT_NUCYPHER_PASSWORD,
    DECRYPTING_CHARACTER_KEYSTORE,
    GENERIC_PASSWORD_PROMPT,
    PASSWORD_COLLECTION_NOTICE,
)
from nucypher.config.constants import NUCYPHER_ENVVAR_KEYSTORE_PASSWORD
from nucypher.crypto.keystore import _WORD_COUNT, Keystore
from nucypher.utilities.emitters import StdoutEmitter


def get_password_from_prompt(prompt: str = GENERIC_PASSWORD_PROMPT, envvar: str = None, confirm: bool = False) -> str:
    """Collect a password interactively, preferring an env var is one is provided and set."""
    password = NO_PASSWORD
    if envvar:
        password = os.environ.get(envvar, NO_PASSWORD)
    if password is NO_PASSWORD:  # Collect password, prefer env var
        password = click.prompt(prompt, confirmation_prompt=confirm, hide_input=True)
    return password


@validate_checksum_address
def get_client_password(checksum_address: str, envvar: str = None, confirm: bool = False) -> str:
    """Interactively collect an ethereum client password"""
    client_password = get_password_from_prompt(prompt=COLLECT_ETH_PASSWORD.format(checksum_address=checksum_address),
                                               envvar=envvar,
                                               confirm=confirm)
    return client_password


def unlock_signer_account(config, json_ipc: bool) -> None:

    # TODO: Remove this block after deprecating 'operator_address'
    from nucypher.config.characters import UrsulaConfiguration
    if isinstance(config, UrsulaConfiguration):
        account = config.operator_address
    else:
        account = config.checksum_address

    eth_password_is_needed = (
        not config.signer.is_device(account=account) and not config.dev_mode
    )

    __password = None
    if eth_password_is_needed:
        if json_ipc and not os.environ.get(config.SIGNER_ENVVAR):
            raise ValueError(f'{config.SIGNER_ENVVAR} is required to use JSON IPC mode.')
        __password = get_client_password(checksum_address=account, envvar=config.SIGNER_ENVVAR)
    config.signer.unlock_account(account=config.checksum_address, password=__password)


def get_nucypher_password(emitter, confirm: bool = False, envvar=NUCYPHER_ENVVAR_KEYSTORE_PASSWORD) -> str:
    """Interactively collect a nucypher password"""
    prompt = COLLECT_NUCYPHER_PASSWORD
    if confirm:
        emitter.message(PASSWORD_COLLECTION_NOTICE)
        prompt += f" ({Keystore._MINIMUM_PASSWORD_LENGTH} character minimum)"
    keystore_password = get_password_from_prompt(prompt=prompt, confirm=confirm, envvar=envvar)
    return keystore_password


def unlock_nucypher_keystore(
    emitter: StdoutEmitter,
    password: str,
    character_configuration,
) -> bool:
    """Unlocks a nucypher keystore and attaches it to the supplied configuration if successful."""
    emitter.message(DECRYPTING_CHARACTER_KEYSTORE.format(name=character_configuration.NAME.capitalize()), color='yellow')

    # precondition
    if character_configuration.dev_mode:
        return True  # Dev accounts are always unlocked

    # unlock
    character_configuration.keystore.unlock(password=password)  # Takes ~3 seconds, ~1GB Ram
    return True


def collect_mnemonic(emitter: StdoutEmitter) -> str:
    """Collect nucypher mnemonic seed words interactively."""
    while True:
        __words = click.prompt("Enter nucypher keystore seed words")
        word_count = len(__words.split())
        if word_count != _WORD_COUNT:
            emitter.message(
                f"Invalid mnemonic - Number of words must be {str(_WORD_COUNT)}, but only got {word_count}"
            )
            continue
        break
    return __words


def recover_keystore(emitter) -> Keystore:
    emitter.message('This procedure will recover your nucypher keystore from mnemonic seed words. '
                    'You will need to provide the entire mnemonic (space seperated) in the correct '
                    'order and choose a new password.', color='cyan')
    click.confirm('Do you want to continue', abort=True)
    __words = collect_mnemonic(emitter)
    __password = get_nucypher_password(emitter=emitter, confirm=True)
    keystore = Keystore.restore(words=__words, password=__password)
    emitter.message(f'Recovered nucypher keystore {keystore.id} to \n {keystore.keystore_path}', color='green')
    return keystore
