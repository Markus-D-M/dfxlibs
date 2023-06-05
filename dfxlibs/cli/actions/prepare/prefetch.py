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

from dfxlibs.cli.environment import env
from dfxlibs.general.baseclasses.file import File
from dfxlibs.general.baseclasses.timeline import Timeline
from dfxlibs.windows.prefetch.prefetchfile import PrefetchFile
from dfxlibs.windows.prefetch.executes import Executes
from dfxlibs.general.helpers.db_filter import db_and, db_eq, db_gt
from dfxlibs.cli.arguments import register_argument


_logger = logging.getLogger(__name__)


@register_argument('-ppf', '--prepare_prefetch', action='store_true', help='reading prefetch files and stores the '
                                                                           'entries in a sqlite database in the '
                                                                           'meta_folder. You can specify a partition '
                                                                           'with --part.', group_id='prepare')
def prepare_prefetch() -> None:
    """
    read windows prefetch files in a given Image and stores them in a sqlite database in the meta_folder.
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

    _logger.info('start preparing prefetch files')

    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part, only_with_filesystem=True):
        _logger.info(f'preparing prefetch files in partition {partition.part_name}')

        try:
            sqlite_files_con, sqlite_files_cur = File.db_open(meta_folder, partition.part_name, False)
        except IOError:
            raise IOError('ERROR: No file database. Use --prepare_files first')

        sqlite_pf_con, sqlite_pf_cur = PrefetchFile.db_open(meta_folder, partition.part_name)
        sqlite_execute_con, sqlite_execute_cur = Executes.db_open(meta_folder, partition.part_name)
        sqlite_timeline_con, sqlite_timeline_cur = Timeline.db_open(meta_folder, partition.part_name)

        count = 0
        for file in File.db_select(sqlite_files_cur, db_and(db_eq('extension', 'pf'), db_gt('size', 0)),
                                   force_index_column='extension'):
            file.open(partition)
            try:
                pf = PrefetchFile(prefetch_file=file)
            except OSError:
                _logger.warning(f'Invalid prefetch file: {file.source}:{file.name}')
                continue
            _logger.info(f'reading file {file.source}:{file.name}')

            if pf.db_insert(sqlite_pf_cur):
                count += 1
            for execute in pf.get_executes():
                execute.db_insert(sqlite_execute_cur)
                tl = Timeline(timestamp=execute.run_time, event_source='prefetch', event_type='EXECUTE',
                              message=f'{execute.executable_filename} executed',
                              param1=execute.executable_filename, param2=execute.parent_folder)
                tl.db_insert(sqlite_timeline_cur)

        _logger.info(f'{count} prefetch files prepared')
        sqlite_pf_con.commit()
        sqlite_execute_con.commit()
        sqlite_timeline_con.commit()

