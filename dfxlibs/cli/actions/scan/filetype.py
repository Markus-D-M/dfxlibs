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

from dfxlibs.general.baseclasses.file import File
from dfxlibs.general.helpers.db_filter import db_and, db_like, db_eq
from dfxlibs.cli.arguments import register_argument
from dfxlibs.cli.environment import env
from os.path import isfile

_logger = logging.getLogger(__name__)


@register_argument('-sft', '--scan_filetype',
                   help='scan for matches for given filetype', group_id='scan')
def scan_filetype():
    image = env['image']
    part = env['args'].part
    meta_folder = env['meta_folder']
    filetype = env['args'].scan_filetype

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('scanning for files')
    count = 0

    for partition in image.partitions(part_name=part, only_with_filesystem=True):
        try:
            sqlite_files_con, sqlite_files_cur = File.db_open(meta_folder, partition.part_name, False)
        except IOError:
            raise IOError(f'ERROR: No file database for {meta_folder}:{partition.part_name}. Use --prepare_files first')

        files = File.db_select(db_cur=sqlite_files_cur, db_filter=db_like('file_type', f'%{filetype}%'))
        for file in files:
            count += 1
            print(f'{meta_folder}|{partition.part_name}|{file.source}:{file.full_name}|{file.file_type}')
    _logger.info(f'{count} matches found')
