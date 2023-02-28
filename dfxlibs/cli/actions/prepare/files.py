"""
    dfxlibs cli preparing files

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
import sqlite3
from typing import List, Tuple
import hashlib
import tlsh
import time
import magic
import pytsk3

from dfxlibs.general.helpers.db_filter import db_eq, db_lt, db_ge, db_and, db_gt
from dfxlibs.general.baseclasses.file import File
from dfxlibs.cli.arguments import register_argument
from dfxlibs.cli.environment import env


_logger = logging.getLogger(__name__)


def scan_dir(to_scan: List[Tuple[File, List[str]]], sqlite_cur: sqlite3.Cursor) -> Tuple[int, int]:
    count_insert = 0
    count_skip = 0
    last_time = time.time()  # for showing progress
    while len(to_scan) > 0:
        item = to_scan.pop()
        dir_entry, parents = item
        for entry in dir_entry.entries:
            if entry.name == '.' or entry.name == '..':
                continue
            if time.time() > last_time + 1:
                # update progress
                print(f'\r{count_insert + count_skip} files/directories prepared '
                      f'(inserted: {count_insert} / skipped: {count_skip})...', end='')
                last_time = time.time()
            entry.parent_folder = '/' + '/'.join([*parents])
            if entry.db_insert(sqlite_cur):
                count_insert += 1
            else:
                count_skip += 1
            for ads in entry.ntfs_ads:
                if ads.db_insert(sqlite_cur):
                    count_insert += 1
                else:
                    count_skip += 1

            if entry.is_dir and entry.allocated:
                to_scan.append((entry, [*parents, entry.name]))

    return count_insert, count_skip


@register_argument('-pf', '--prepare_files', action='store_true', help='Scan files and directories of all partitions. '
                                                                       'You can specify a partition with --part. The '
                                                                       'file entries will be stored in the meta_folder '
                                                                       'in a sqlite database', group_id='prepare')
def prepare_files() -> None:
    """
    scan all files and directories in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only the files and directories of this partition are scanned

    :return: None
    :raise AttributeError: if image is None
    """
    image = env['image']
    part = env['args'].part
    meta_folder = env['meta_folder']

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('start preparing files')
    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part):
        try:
            _ = partition.filesystem
        except AttributeError:
            continue
        _logger.info(f'prepare partition {partition.part_name}')

        # prepare database
        sqlite_con, sqlite_cur = File.db_open(meta_folder, partition.part_name)

        # starting with /
        root = partition.get_file('/')
        root.name = '/'
        root.db_insert(sqlite_cur)

        to_scan: List[Tuple[File, List[str]]] = [(root, [])]  # dir_entry, parents
        count_insert, count_skip = scan_dir(to_scan, sqlite_cur)

        # finish
        print(f'\r{" "*60}\r', end='')  # delete progress line
        sqlite_con.commit()
        _logger.info(f'{count_insert} entries inserted; {count_skip} entries skipped')
        _logger.info(f'partition {partition.part_name} finished')

    _logger.info('prepare files finished')


@register_argument('-pvss', '--prepare_vss', action='store_true', help='Scan for files and directories in volume '
                                                                       'shadow copies of all partitions. You can '
                                                                       'specify a partition with --part. The file '
                                                                       'entries will be stored in the meta_folder '
                                                                       'in a sqlite database', group_id='prepare')
def prepare_vss_files() -> None:
    """
    scan for files and directories in Volume Shadow Copies in a given Image and stores them in a sqlite database.
    If partition is specified then only the files and directories of this partition are scanned

    :return: None
    :raise AttributeError: if image is None
    """
    image = env['image']
    part = env['args'].part
    meta_folder = env['meta_folder']

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('start scanning for volume shadow copies')
    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part, filesystem_typeid=pytsk3.TSK_FS_TYPE_NTFS):
        _logger.info(f'scan partition {partition.part_name}')
        # prepare database
        sqlite_con, sqlite_cur = File.db_open(meta_folder, partition.part_name)
        count_insert = 0
        count_skip = 0
        for vss_store_id, vss_store, filesystem in partition.get_volume_shadow_copy_filesystems():
            _logger.info(f'found vss store {vss_store.identifier} '
                         f'(Created: {vss_store.creation_time.strftime("%Y-%m-%d")})')
            root = File(filesystem.open('/'), partition)
            root.name = '/'
            root.source = f'vss#{vss_store_id}'
            root.db_insert(sqlite_cur)

            to_scan: List[Tuple[File, List[str]]] = [(root, [])]  # dir_entry, parents
            ci, cs = scan_dir(to_scan, sqlite_cur)
            count_insert += ci
            count_skip += cs

            # finish
            print(f'\r{" "*60}\r', end='')  # delete progress line
            sqlite_con.commit()

        _logger.info(f'{count_insert} entries inserted; {count_skip} entries skipped')
        _logger.info(f'partition {partition.part_name} finished')

    _logger.info('scanning for volume shadow copies finished')


@register_argument('--hash', nargs='+', help='Hash all files <256 MiB of all partitions. You can specify a partition '
                                             'with --part. Possible algorithms are md5, sha1, sha256 and tlsh. A '
                                             'minimum filesize of 50 bytes is required for tlsh. The result is stored '
                                             'in the file database.', group_id='prepare')
def hash_files() -> None:
    """
    Build hashes for all files <256MiB in a given Image and stores them to the sqlite file database in the meta_folder.
    If partition is specified then only the files and directories of this partition are scanned.

    :return: None
    :raise AttributeError: if image is None
    :raise IOError: if image is not prepared (need to run --prepare_files first)
    :raise ValueError: if no valid hash algorithms are specified
    """
    image = env['image']
    part = env['args'].part
    meta_folder = env['meta_folder']
    hash_algorithms = env['args'].hash

    if hash_algorithms is None:
        hash_algorithms = []
    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    # clean up hash_algorithms (delete unknowns and set to lowercase
    hash_algorithms = [algo.lower() for algo in hash_algorithms if algo.lower() in ['md5', 'sha1', 'sha256', 'tlsh']]

    if not hash_algorithms:
        raise ValueError('ERROR: No hash_algorithms given')

    _logger.info('start hashing files')

    _logger.info(f'using algorithms {", ".join(hash_algorithms)}')
    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part, only_with_filesystem=True):

        _logger.info(f'hashing files in partition {partition.part_name}')

        # open database
        try:
            sqlite_con, sqlite_cur, sqlite_upd_cur = File.db_open(meta_folder, partition.part_name, False,
                                                                  generate_cursors_num=2)
        except IOError:
            raise IOError('ERROR: No file database. Use --prepare_files first')

        # for showing progress
        last_time = time.time()
        count = 0
        for file in File.db_select(sqlite_cur, db_and(db_eq('is_dir', 0),  # no directies
                                                      db_gt('size', 0),  # no invalid filesizes (-1) and empty files
                                                      db_lt('size', 256 * 1024 * 1024)  # size less than 256 MiB
                                                      )):
            # build hashes
            file_data = ''
            if 'md5' in hash_algorithms and file.md5 == '':
                if not file_data:
                    try:
                        file.open(partition)
                    except OSError:
                        continue
                    file_data = file.read()
                file.md5 = hashlib.md5(file_data).hexdigest()
            if 'sha1' in hash_algorithms and file.sha1 == '':
                if not file_data:
                    try:
                        file.open(partition)
                    except OSError:
                        continue
                    file_data = file.read()
                file.sha1 = hashlib.sha1(file_data).hexdigest()
            if 'sha256' in hash_algorithms and file.sha256 == '':
                if not file_data:
                    try:
                        file.open(partition)
                    except OSError:
                        continue
                    file_data = file.read()
                file.sha256 = hashlib.sha256(file_data).hexdigest()
            if 'tlsh' in hash_algorithms and file.tlsh == '' and file.size >= 50:
                if not file_data:
                    try:
                        file.open(partition)
                    except OSError:
                        continue
                    file_data = file.read()
                file.tlsh = tlsh.hash(file_data)

            if file_data:
                # hash was build -> update db and count
                count += 1
                file.db_update(sqlite_upd_cur, hash_algorithms)

            if time.time() > last_time + 5:
                # update progress
                print(f'\r{count} files hashed...', end='')
                last_time = time.time()

        # finish
        print(f'\r{" "*60}\r', end='')  # delete progress line
        sqlite_con.commit()
        _logger.info(f'{count} files hashed')
        _logger.info(f'partition {partition.part_name} finished')

    _logger.info('hashing files finished')


@register_argument('--filetypes', action='store_true', help='turn on signature based detection of filetypes of all '
                                                            'files in all partitions. The result is stored in the file '
                                                            'database. You can specify a partition  with --part. ',
                   group_id='prepare')
def file_types() -> None:
    """
    Determine file types for all files in a given Image and stores them to the sqlite file database in the meta_folder.
    If partition is specified then only the files of this partition are scanned.

    :return: None
    :raise AttributeError: if image is None
    :raise IOError: if image is not prepared (need to run --prepare_files first)
    """
    image = env['image']
    part = env['args'].part
    meta_folder = env['meta_folder']

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('starting filetype detection')

    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part, only_with_filesystem=True):
        _logger.info(f'determine filetypes in partition {partition.part_name}')

        # open database
        try:
            sqlite_con, sqlite_cur, sqlite_upd_cur = File.db_open(meta_folder, partition.part_name, False,
                                                                  generate_cursors_num=2)
        except IOError:
            raise IOError('ERROR: No file database. Use --prepare_files first')

        # for showing progress
        last_time = time.time()
        count = 0

        for file in File.db_select(sqlite_cur, db_and(db_eq('is_dir', 0),  # no directies
                                                      db_ge('size', 0)  # no invalid filesizes (-1)m
                                                      )):

            # using magic to determine file type
            if file.file_type == '':
                try:
                    file.open(partition)
                except OSError:
                    continue
                try:
                    file.file_type = magic.from_buffer(file.read(2048))
                except magic.MagicException:
                    file.file_type = 'detection error'
                count += 1
                file.db_update(sqlite_upd_cur, ['file_type'])

            if time.time() > last_time + 5:
                # update progress
                print(f'\r{count} files analyzed...', end='')
                last_time = time.time()

        # finish
        print(f'\r{" "*60}\r', end='')  # delete progress line
        sqlite_con.commit()
        _logger.info(f'{count} files analyzed')
        _logger.info(f'partition {partition.part_name} finished')

    _logger.info('filetype detection finished')
