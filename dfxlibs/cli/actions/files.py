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
from typing import List
import hashlib
import tlsh
import time
import magic

from dfxlibs.general.helpers.db_filter import db_eq, db_lt, db_ge, db_and
from dfxlibs.general.baseclasses.file import File
from dfxlibs.general.image import Image


_logger = logging.getLogger(__name__)


def recursive_dirlist(dir_entry: File, parents: List = None,
                      db_cur: sqlite3.Cursor = None) -> int:
    if parents is None:
        parents = []
    count = 0
    for entry in dir_entry.entries:
        if entry.name == '.' or entry.name == '..':
            continue
        entry.parent_folder = '/' + '/'.join([*parents])
        if entry.db_insert(db_cur):
            count += 1
        for ads in entry.ntfs_ads:
            if ads.db_insert(db_cur):
                count += 1

        if entry.is_dir and entry.allocated:
            count += recursive_dirlist(entry, [*parents, entry.name], db_cur=db_cur)
    return count


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
        count = 0
        root = partition.get_file('/')
        root.name = '/'
        if root.db_insert(sqlite_cur):
            count += 1

        # walk files and dirs
        count += recursive_dirlist(root, db_cur=sqlite_cur)

        # finish
        sqlite_con.commit()
        _logger.info(f'{count} entries inserted')
        _logger.info(f'partition {partition.table_num}_{partition.slot_num} finished')

    _logger.info('prepare files finished')


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
                                                      db_ge('size', 0),  # no invalid filesizes (-1)
                                                      db_lt('size', 256 * 1024 * 1024),  # size less than 256 MiB
                                                      db_eq('source', 'filesystem')  # only files from filesystem
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
                                                      db_ge('size', 0),  # no invalid filesizes (-1)
                                                      db_eq('source', 'filesystem')  # only files from filesystem
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
