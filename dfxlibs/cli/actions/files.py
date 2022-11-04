# coding: utf-8
"""
    dfxlibs cli files

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
import re
import os
from datetime import datetime

from dfxlibs.general.helpers.db_filter import db_eq, db_and
from dfxlibs.general.baseclasses.file import File
from dfxlibs.cli.arguments import register_argument
from dfxlibs.cli.environment import env


_logger = logging.getLogger(__name__)


@register_argument('-e', '--extract', nargs='+', help='Extracts files from the image and stores them to the '
                                                      'meta_folder. You have to give the full path and filename (with '
                                                      'leading slash - even slashes instead of backslashes for windows '
                                                      'images) or a meta address. As default source "filesystem" for '
                                                      'regular files in the image will be used. You can give another '
                                                      'file-source (e.g. "vss#0" for shadow copy store 0) by just '
                                                      'adding it in front of your path and separate it with a colon '
                                                      '(e.g. "vss#0:/path/testfile.txt" for /path/testfile.txt from '
                                                      'vss#0). You can give multiple files at once', group_id='special')
def extract() -> None:
    """
    Extracts files from the image and stores them to the meta_folder.

    :return: None
    :raise AttributeError: if image is None
    :raise IOError: if image is not prepared (need to run --prepare_files first)
    """
    image = env['image']
    files = env['args'].extract
    part = env['args'].part
    meta_folder = env['meta_folder']
    if files is None:
        files = []
    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('start extracting files')

    # specified partitions only (if specified)
    extract_count = 0
    extract_folder = os.path.join('extracts', datetime.now().strftime('%Y%m%d_%H%M%S'))
    os.makedirs(os.path.join(meta_folder, extract_folder))
    for partition in image.partitions(part_name=part):

        # open database
        try:
            sqlite_con, sqlite_cur = File.db_open(meta_folder, partition.part_name, False)
        except IOError:
            raise IOError('ERROR: No file database. Use --prepare_files first')

        for file in files:
            fullname: str
            try:
                source, fullname = file.split(':', 1)
                if "/" in source:
                    # ':' as part of filename
                    source = 'filesystem'
                    fullname = file
            except ValueError:
                source = 'filesystem'
                fullname = file

            _logger.info(f'Try to extract file {fullname} from {source} on partition {partition.part_name}')

            if '/' in fullname:
                parent_folder, filename = fullname.rsplit('/', 1)
                if not parent_folder:
                    # if in root directory
                    parent_folder = '/'
                db_files = File.db_select(sqlite_cur, db_and(db_eq('source', source),
                                                             db_eq('name', filename),
                                                             db_eq('parent_folder', parent_folder)))
            else:
                # looking for meta_addr
                try:
                    db_files = File.db_select(sqlite_cur, db_and(db_eq('source', source),
                                                                 db_eq('meta_addr', int(fullname))))
                except ValueError:
                    raise ValueError('Given extract filename or meta addr is not correct - did you use slashes?')
            files_found = False
            for db_file in db_files:
                files_found = True
                extract_count += 1
                db_file: File
                db_file.open(partition)

                out_filename = f'{extract_count}_{partition.part_name}_{source}_{db_file.full_name.lstrip("/")}'

                # sanitize filename
                out_filename = re.sub(r'[^a-zA-Z0-9_-]', '_', out_filename)

                out_fullname = os.path.join(meta_folder, extract_folder, out_filename)
                _logger.info(f'Store extracted file as {out_filename}')
                with open(out_fullname, 'wb') as out_file:
                    while data := db_file.read(512):
                        out_file.write(data)
                if os.path.getsize(out_fullname) != db_file.size:
                    _logger.warning(f'Can only extract {os.path.getsize(out_fullname)} out of {db_file.size} bytes')

            if not files_found:
                _logger.info('No files found to extract')
