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


@register_argument('-shl', '--scan_hashlist',
                   help='scan for matches from given hashlist file (one hash per line)', group_id='scan')
def scan_hashlist():
    image = env['image']
    part = env['args'].part
    meta_folder = env['meta_folder']
    hashlist = env['args'].scan_hashlist
    if not isfile(hashlist):
        raise AttributeError(f'ERROR: Hashlist {hashlist} does not exist')

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    with open(hashlist, 'r') as f:
        hashes = [h.strip().lower() for h in f.readlines() if len(h.strip()) in [32, 40, 64]]

    _logger.info(f'loaded {len(hashes)} hashes')

    _logger.info('scanning for hashlist matches')
    count = 0

    for partition in image.partitions(part_name=part, only_with_filesystem=True):
        try:
            sqlite_files_con, sqlite_files_cur = File.db_open(meta_folder, partition.part_name, False)
        except IOError:
            raise IOError(f'ERROR: No file database for {meta_folder}:{partition.part_name}. Use --prepare_files first')

        for h in hashes:
            if len(h) == 32:
                field = 'md5'
            elif len(h) == 40:
                field = 'sha1'
            elif len(h) == 64:
                field = 'sha256'
            else:
                continue
            files = File.db_select(db_cur=sqlite_files_cur, db_filter=db_eq(field, h))
            for file in files:
                count += 1
                print(f'{h}|{meta_folder}|{partition.part_name}|{file.source}:{file.full_name}')
    _logger.info(f'{count} matches found')
