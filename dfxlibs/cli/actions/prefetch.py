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
import datetime
import logging
import sqlite3

from dfxlibs.general.image import Image
from dfxlibs.general.baseclasses.file import File
from dfxlibs.windows.prefetch.prefetchfile import PrefetchFile, prefetch_carver
from dfxlibs.windows.prefetch.executes import Executes
from dfxlibs.general.helpers.db_filter import db_eq, db_and, db_like, db_gt


_logger = logging.getLogger(__name__)


def insert_prefetch_files(sqlite_pf_cur: sqlite3.Cursor, sqlite_execute_cur: sqlite3.Cursor, pf: PrefetchFile) -> int:
    result = 0
    if pf.db_insert(sqlite_pf_cur):
        result = 1
    for run_time in pf.get_run_times():
        if run_time > 0:
            execute = Executes(executable_filename=pf.executable_filename,
                               executable_addr=pf.executable_addr,
                               executable_seq=pf.executable_seq,
                               parent_folder=pf.parent_folder,
                               prefetch_hash=pf.prefetch_hash,
                               run_time=datetime.datetime.fromtimestamp(run_time, tz=datetime.timezone.utc),
                               carved=pf.carved)
            execute.db_insert(sqlite_execute_cur)
    return result


def prepare_prefetch(image: Image, meta_folder: str, part: str = None) -> None:
    """
    read windows prefetch files in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only the prefetch files of this partition are scanned

    :param image: image file
    :type image: Image
    :param meta_folder: name of the meta information folder to store/read file database
    :type meta_folder: str
    :param part: partition name in the format "X_Y"
    :type part: str
    :return: None
    :raise AttributeError: if image is None
    :raise IOError: if image is not scanned for files
    """
    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('start preparing usn journal')

    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part):
        _logger.info(f'preparing prefetch files in partition {partition.part_name}')

        try:
            sqlite_files_con, sqlite_files_cur = File.db_open(meta_folder, partition.part_name, False)
        except IOError:
            raise IOError('ERROR: No file database. Use --prepare_files first')

        sqlite_pf_con, sqlite_pf_cur = PrefetchFile.db_open(meta_folder, partition.part_name)
        sqlite_execute_con, sqlite_execute_cur = Executes.db_open(meta_folder, partition.part_name)

        count = 0
        for file in File.db_select(sqlite_files_cur, db_and(db_like('name', '%.pf'), db_gt('size', 0))):
            file.open(partition)
            try:
                pf = PrefetchFile(prefetch_file=file)
            except OSError:
                _logger.warning(f'Invalid prefetch file: {file.name}')
                continue
            _logger.info(f'reading file {file.name}')
            count += insert_prefetch_files(sqlite_pf_cur, sqlite_execute_cur, pf)

        _logger.info(f'{count} prefetch files prepared')
        sqlite_pf_con.commit()
        sqlite_execute_con.commit()


def carve_prefetch(image: Image, meta_folder: str, part: str = None) -> None:
    """
    carve for windows prefetch files in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only the prefetch files of this partition are scanned

    :param image: image file
    :type image: Image
    :param meta_folder: name of the meta information folder to store/read file database
    :type meta_folder: str
    :param part: partition name in the format "X_Y"
    :type part: str
    :return: None
    :raise AttributeError: if image is None
    :raise IOError: if image is not scanned for files
    """
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
            count += insert_prefetch_files(sqlite_pf_cur, sqlite_execute_cur, pf)

        _logger.info(f'{count} prefetch files carved')
        sqlite_pf_con.commit()
        sqlite_execute_con.commit()
