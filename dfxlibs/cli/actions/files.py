# coding: utf-8
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
import re
import pytsk3
import os
from datetime import datetime

from dfxlibs.general.helpers.db_filter import db_eq, db_lt, db_ge, db_and, db_gt
from dfxlibs.general.baseclasses.file import File
from dfxlibs.general.image import Image
from dfxlibs.cli.arguments import register_argument


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
            if time.time() > last_time + 5:
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


def prepare_files(image: Image, meta_folder: str, part: str = None) -> None:
    """
    scan all files and directories in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only the files and directories of this partition are scanned

    :param image: image file
    :type image: Image
    :param meta_folder: name of the meta information folder to store/read file database
    :type meta_folder: str
    :param part: partition name in the format "X_Y"
    :type part: str
    :return: None
    :raise AttributeError: if image is None
    """
    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('start preparing files')
    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part):
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
        _logger.info(f'partition {partition.table_num}_{partition.slot_num} finished')

    _logger.info('prepare files finished')


def prepare_vss_files(image: Image, meta_folder: str, part: str = None) -> None:
    """
    scan for files and directories in Volume Shadow Copies in a given Image and stores them in a sqlite database.
    If partition is specified then only the files and directories of this partition are scanned

    :param image: image file
    :type image: Image
    :param meta_folder: name of the meta information folder to store/read file database
    :type meta_folder: str
    :param part: partition name in the format "X_Y"
    :type part: str
    :return: None
    :raise AttributeError: if image is None
    """
    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('start scanning for volume shadow copies')
    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part):
        if partition.type_id != pytsk3.TSK_FS_TYPE_NTFS:
            # NTFS only
            continue
        _logger.info(f'scan partition {partition.part_name}')
        # prepare database
        sqlite_con, sqlite_cur = File.db_open(meta_folder, partition.part_name)
        count_insert = 0
        count_skip = 0
        for vss_store_id, vss_store, filesystem in partition.get_volume_shadow_copy_filesystems():
            _logger.info(f'found vss store {vss_store.identifier}')
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
        _logger.info(f'partition {partition.table_num}_{partition.slot_num} finished')

    _logger.info('scanning for volume shadow copies finished')


def hash_files(image: Image, meta_folder: str, part: str = None,
               hash_algorithms: List = None) -> None:
    """
    Build hashes for all files <256MiB in a given Image and stores them to the sqlite file database in the meta_folder.
    If partition is specified then only the files and directories of this partition are scanned.

    :param image: image file
    :type image: Image
    :param meta_folder: name of the meta information folder to store/read file database
    :type meta_folder: str
    :param part: partition name in the format "X_Y"
    :type part: str
    :param hash_algorithms: list hash algorithms to build. Possible list entries: md5, sha1, sha256, tlsh
    :type hash_algorithms: List
    :return: None
    :raise AttributeError: if image is None
    :raise IOError: if image is not prepared (need to run --prepare_files first)
    :raise ValueError: if no valid hash algorithms are specified
    """
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
    for partition in image.partitions(part_name=part):

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
                    file.open(partition)
                    file_data = file.read()
                file.md5 = hashlib.md5(file_data).hexdigest()
            if 'sha1' in hash_algorithms and file.sha1 == '':
                if not file_data:
                    file.open(partition)
                    file_data = file.read()
                file.sha1 = hashlib.sha1(file_data).hexdigest()
            if 'sha256' in hash_algorithms and file.sha256 == '':
                if not file_data:
                    file.open(partition)
                    file_data = file.read()
                file.sha256 = hashlib.sha256(file_data).hexdigest()
            if 'tlsh' in hash_algorithms and file.tlsh == '' and file.size >= 50:
                if not file_data:
                    file.open(partition)
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
        _logger.info(f'partition {partition.table_num}_{partition.slot_num} finished')

    _logger.info('hashing files finished')


def file_types(image: Image, meta_folder: str, part: str = None) -> None:
    """
    Determine file types for all files in a given Image and stores them to the sqlite file database in the meta_folder.
    If partition is specified then only the files of this partition are scanned.

    :param image: image file
    :type image: Image
    :param meta_folder: name of the meta information folder to store/read file database
    :type meta_folder: str
    :param part: partition name in the format "X_Y"
    :type part: str
    :return: None
    :raise AttributeError: if image is None
    :raise IOError: if image is not prepared (need to run --prepare_files first)
    """

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('starting filetype detection')

    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part):

        _logger.info(f'determine filetypes in partition {partition.table_num}_{partition.slot_num}')

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
                file.open(partition)
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
        _logger.info(f'partition {partition.table_num}_{partition.slot_num} finished')

    _logger.info('filetype detection finished')


@register_argument('-e', '--extract', nargs='+', help='Extracts files from the image and stores them to the '
                                                      'meta_folder. You have to give the full path and filename (with '
                                                      'leading slash - even slashes instead of backslashes for windows '
                                                      'images) or a meta address. As default source "filesystem" for '
                                                      'regular files in the image will be used. You can give another '
                                                      'file-source (e.g. "vss#0" for shadow copy store 0) by just '
                                                      'adding it in front of your path and separate it with a colon '
                                                      '(e.g. "vss#0:/path/testfile.txt" for /path/testfile.txt from '
                                                      'vss#0). You can give multiple files at once', group_id='special')
def extract(image: Image, meta_folder: str, part: str = None, files: List[str] = None) -> None:
    """
    Extracts files from the image and stores them to the meta_folder.

    :param image: image file
    :type image: Image
    :param meta_folder: name of the meta information folder to store/read file database
    :type meta_folder: str
    :param part: partition name in the format "X_Y"
    :type part: str
    :param files: list of files to extract in format 'source/path/file.ext'. source defaults to 'filesystem'
    :type files: List[str]
    :return: None
    :raise AttributeError: if image is None
    :raise IOError: if image is not prepared (need to run --prepare_files first)
    """
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
