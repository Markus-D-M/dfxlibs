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
from dfxlibs.general.baseclasses.timeline import Timeline
from dfxlibs.windows.shortcuts.lnkfile import lnk_carver, LnkFile
from dfxlibs.cli.arguments import register_argument


_logger = logging.getLogger(__name__)


@register_argument('-clnk', '--carve_lnk', action='store_true', help='carve for lnk files and stores them in '
                                                                     'the same database as for the '
                                                                     '--prepare_lnk argument',
                   group_id='carve')
def carve_lnk() -> None:
    """
    carve for windows lnk files in a given Image and stores them in a sqlite database in the meta_folder.
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

    _logger.info('start carving lnk files')

    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part):
        _logger.info(f'carving lnk files in partition {partition.part_name}')

        sqlite_lnk_con, sqlite_lnk_cur = LnkFile.db_open(meta_folder, partition.part_name)
        sqlite_timeline_con, sqlite_timeline_cur = Timeline.db_open(meta_folder, partition.part_name)

        count = 0
        lnk: LnkFile
        for lnk in partition.carve(lnk_carver):
            if lnk.db_insert(sqlite_lnk_cur):
                count += 1
            if lnk.target_local_path:
                path: str = lnk.target_local_path.replace('\\', '/')
                try:
                    folder, file = path.rsplit('/', maxsplit=1)
                except ValueError:
                    folder = ''
                    file = path
                if folder[1] == ':':
                    folder = folder[2:]
                if lnk.target_crtime.timestamp() > 0:
                    tl = Timeline(timestamp=lnk.target_crtime, event_source='lnkfile',
                                  event_type='TARGET_CREATE',
                                  param1=file, param2=folder)
                    tl.db_insert(sqlite_timeline_cur)
                if lnk.target_atime.timestamp() > 0:
                    tl = Timeline(timestamp=lnk.target_atime, event_source='lnkfile',
                                  event_type='TARGET_ACCESSED',
                                  param1=file, param2=folder)
                    tl.db_insert(sqlite_timeline_cur)

        _logger.info(f'{count} lnk files carved')
        sqlite_lnk_con.commit()
        sqlite_timeline_con.commit()
