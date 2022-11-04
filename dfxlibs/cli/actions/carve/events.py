"""
    Copyright 2022 Markus D (mar.d@gmx.net)

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
"""

import logging

from dfxlibs.windows.events.evtxfile import evtx_carver
from dfxlibs.windows.events.event import Event
from dfxlibs.cli.arguments import register_argument
from dfxlibs.cli.environment import env


_logger = logging.getLogger(__name__)


@register_argument('-cevtx', '--carve_evtx', action='store_true', help='carve for windows evtx entries and stores them '
                                                                       'in the same database as for the --prepare_evtx '
                                                                       'argument', group_id='carve')
def carve_evtx() -> None:
    """
    carve all windows evtx logs in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only the data of this partition is scanned

    :return: None
    :raise AttributeError: if image is None
    """
    image = env['image']
    part = env['args'].part
    meta_folder = env['meta_folder']

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('start carving event (evtx) logs')

    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part):
        _logger.info(f'carving events in partition {partition.part_name}')

        sqlite_events_con, sqlite_events_cur = Event.db_open(meta_folder, partition.part_name)
        record_count = 0
        event: Event
        for event in partition.carve(evtx_carver):
            if event.db_insert(sqlite_events_cur):
                record_count += 1

        sqlite_events_con.commit()
        _logger.info(f'{record_count} event records carved for '
                     f'partition {partition.part_name}')
