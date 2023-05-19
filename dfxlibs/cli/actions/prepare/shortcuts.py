# coding: utf-8
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
import struct

from dfxlibs.cli.environment import env
from dfxlibs.general.baseclasses.file import File
from dfxlibs.windows.shortcuts.lnkfile import LnkFile
from dfxlibs.general.helpers.db_filter import db_and, db_eq, db_gt
from dfxlibs.cli.arguments import register_argument


_logger = logging.getLogger(__name__)


@register_argument('-plnk', '--prepare_lnk', action='store_true', help='reading lnk files and stores the '
                                                                       'entries in a sqlite database in the '
                                                                       'meta_folder. You can specify a partition '
                                                                       'with --part.', group_id='prepare')
def prepare_lnk() -> None:
    """
    read windows lnk files in a given Image and stores them in a sqlite database in the meta_folder.
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

    _logger.info('start preparing lnk files')

    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part, only_with_filesystem=True):
        _logger.info(f'preparing lnk files in partition {partition.part_name}')

        try:
            sqlite_files_con, sqlite_files_cur = File.db_open(meta_folder, partition.part_name, False)
        except IOError:
            raise IOError('ERROR: No file database. Use --prepare_files first')

        sqlite_lnk_con, sqlite_lnk_cur = LnkFile.db_open(meta_folder, partition.part_name)

        count = 0
        for file in File.db_select(sqlite_files_cur, db_and(db_eq('extension', 'lnk'), db_gt('size', 0)),
                                   force_index_column='extension'):
            file.open(partition)
            try:
                lnk = LnkFile(lnk_file=file)
            except struct.error:
                continue

            if lnk.db_insert(sqlite_lnk_cur):
                count += 1

        _logger.info(f'{count} lnk files prepared')
        sqlite_lnk_con.commit()

