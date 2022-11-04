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

from dfxlibs.cli.environment import env
from dfxlibs.windows.prefetch.prefetchfile import PrefetchFile, prefetch_carver
from dfxlibs.windows.prefetch.executes import Executes
from dfxlibs.cli.arguments import register_argument


_logger = logging.getLogger(__name__)


@register_argument('-cpf', '--carve_prefetch', action='store_true', help='carve for prefetch files and stores them in '
                                                                         'the same database as for the '
                                                                         '--prepare_prefetch argument',
                   group_id='carve')
def carve_prefetch() -> None:
    """
    carve for windows prefetch files in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only the prefetch files of this partition are scanned

    :return: None
    :raise AttributeError: if image is None
    :raise IOError: if image is not scanned for files
    """
    image = env['image']
    part = env['args'].part
    meta_folder = env['meta_folder']

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('start carving prefetch files')

    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part):
        _logger.info(f'carving prefetch files in partition {partition.part_name}')

        sqlite_pf_con, sqlite_pf_cur = PrefetchFile.db_open(meta_folder, partition.part_name)
        sqlite_execute_con, sqlite_execute_cur = Executes.db_open(meta_folder, partition.part_name)

        count = 0
        pf: PrefetchFile
        for pf in partition.carve(prefetch_carver):
            if pf.db_insert(sqlite_pf_cur):
                count += 1
            for execute in pf.get_executes():
                execute.db_insert(sqlite_execute_cur)

        _logger.info(f'{count} prefetch files carved')
        sqlite_pf_con.commit()
        sqlite_execute_con.commit()
