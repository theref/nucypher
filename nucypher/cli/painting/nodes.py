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
import maya

from nucypher.config.constants import SEEDNODES
from nucypher.datastore.queries import get_reencryption_requests


def build_fleet_state_status(ursula) -> str:
    return str(ursula.known_nodes.current_state)


def paint_node_status(emitter, ursula, start_time):
    ursula.mature()  # Just to be sure

    # Build Learning status line
    learning_status = "Unknown"
    if ursula._learning_task.running:
        learning_status = f"Learning at {ursula._learning_task.interval}s Intervals"
    else:
        learning_status = "Not Learning"

    teacher = 'Current Teacher ..... No Teacher Connection'
    if ursula._current_teacher_node:
        teacher = f'Current Teacher ..... {ursula._current_teacher_node}'

    # Build FleetState status line
    fleet_state = build_fleet_state_status(ursula=ursula)

    reenc_requests = get_reencryption_requests(ursula.datastore)
    num_reenc_requests = len(reenc_requests)

    stats = [
        f'⇀URSULA {ursula.nickname.icon}↽',
        f'{ursula}',
        f'Uptime .............. {maya.now() - start_time}',
        f'Start Time .......... {start_time.slang_time()}',
        f'Fleet State.......... {fleet_state}',
        f'Learning Status ..... {learning_status}',
        f'Learning Round ...... Round #{ursula._learning_round}',
        f"Operating Mode ...... {'Federated' if ursula.federated_only else 'Decentralized'}",
        f'Rest Interface ...... {ursula.rest_url()}',
        f'Node Storage Type ... {ursula.node_storage._name.capitalize()}',
        f'Known Nodes ......... {len(ursula.known_nodes)}',
        f'Reencryption Requests {num_reenc_requests}',
        teacher,
    ]

    if not ursula.federated_only:
        operator_address = f'Operator Address ...... {ursula.operator_address}'
        current_period = f'Current Period ...... {ursula.application_agent.get_current_period()}'
        stats.extend([current_period, operator_address])

    if ursula._availability_tracker:
        if ursula._availability_tracker.running:
            score = f'Availability Score .. {ursula._availability_tracker.score} ({len(ursula._availability_tracker.responders)} responders)'
        else:
            score = 'Availability Score .. Disabled'

        stats.append(score)

    emitter.echo('\n' + '\n'.join(stats) + '\n')


def paint_known_nodes(emitter, ursula) -> None:
    # Gather Data
    known_nodes = ursula.known_nodes
    number_of_known_nodes = len(ursula.node_storage.all(federated_only=ursula.federated_only))
    seen_nodes = len(ursula.node_storage.all(federated_only=ursula.federated_only, certificates_only=True))

    if federated_only := ursula.federated_only:
        emitter.echo("Configured in Federated Only mode", color='green')

    # Heading
    label = f"Known Nodes (connected {number_of_known_nodes} / seen {seen_nodes})"
    heading = '\n' + label + " " * (45 - len(label))
    emitter.echo(heading, bold=True)

    # Build FleetState status line
    fleet_state = build_fleet_state_status(ursula=ursula)
    fleet_status_line = f'Fleet State {fleet_state}'
    emitter.echo(fleet_status_line, color='blue', bold=True)

    # Legend
    color_index = {
        'self': 'yellow',
        'known': 'white',
        'seednode': 'blue'
    }

    # Legend
    # for node_type, color in color_index.items():
    #     emitter.echo('{0:<6} | '.format(node_type), color=color, nl=False)
    # emitter.echo('\n')

    seednode_addresses = [bn.checksum_address for bn in SEEDNODES]

    for node in known_nodes:
        row_template = "{} | {}"
        node_type = 'known'
        if node.checksum_address == ursula.checksum_address:
            node_type = 'self'
            row_template += f' ({node_type})'
        elif node.checksum_address in seednode_addresses:
            node_type = 'seednode'
            row_template += f' ({node_type})'
        emitter.echo(row_template.format(node.rest_url().ljust(20), node), color=color_index[node_type])
