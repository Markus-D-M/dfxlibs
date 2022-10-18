# coding: utf-8
"""
    dfxlibs cli prepare usn journal


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

from typing import TYPE_CHECKING
from struct import unpack
import time

from dfxlibs.general.baseclasses.file import File
from dfxlibs.windows.usnjournal.usnrecordv2 import USNRecordV2, usn_carver
from dfxlibs.general.helpers.db_filter import db_eq, db_and
from dfxlibs.cli.arguments import register_argument

if TYPE_CHECKING:
    from dfxlibs.cli.environment import Environment


_logger = logging.getLogger(__name__)


@register_argument('-pusn', '--prepare_usn', action='store_true', help='reading ntfs usn journals and stores the '
                                                                       'entries in a sqlite database in the '
                                                                       'meta_folder. You can specify a partition with '
                                                                       '--part.', group_id='prepare')
def prepare_usnjournal(env: 'Environment') -> None:
    """
    read windows usn journal entries in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only the journal of this partition is scanned

    :param env: cli environment
    :type env: Environment
    :return: None
    :raise AttributeError: if image is None
    :raise IOError: if image is not scanned for files
    :raise ValueError: if USN journal is broken
    """
    image = env['image']
    part = env['args'].part
    meta_folder = env['meta_folder']

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('start preparing usn journal')

    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part):
        _logger.info(f'preparing usn journal in partition {partition.part_name}')

        try:
            sqlite_files_con, sqlite_files_cur = File.db_open(meta_folder, partition.part_name, False)
        except IOError:
            raise IOError('ERROR: No file database. Use --prepare_files first')

        sqlite_usn_con, sqlite_usn_cur = USNRecordV2.db_open(meta_folder, partition.part_name)

        journal: File = File.db_select_one(sqlite_files_cur,
                                           db_and(db_eq('name', '$UsnJrnl:$J'), db_eq('parent_folder', '/$Extend')))
        if journal is None:
            _logger.info(f'no usn journal on partition {partition.part_name} found')
            continue
        journal.open(partition)

        last_time = time.time()  # for showing progress
        parent_folders = {}  # cache parent_folder searches
        record_count = 0
        while True:
            # align to 8 byte boundary
            cur_pos = journal.tell()

            if cur_pos % 8 != 0:
                b = journal.read(8 - (cur_pos % 8)).strip(b'\0')
                if b:
                    raise ValueError(f'non-zero bytes while aligning: {b}')
            # skip zero bytes
            dword = b'\0\0\0\0'
            while dword == b'\0\0\0\0':
                dword = journal.read(4)
            if len(dword) < 4:
                break
            rec_len,  = unpack('<I', dword)
            ver = journal.read(4)
            ver_major, ver_minor = unpack('<HH', ver)
            if ver_major == 2 and ver_minor == 0:
                try:
                    usnrecord: USNRecordV2 = USNRecordV2.from_raw(dword + ver + journal.read(rec_len - 8))
                except AttributeError as e:
                    _logger.warning('Invalid USN Record: ' + str(e))
                    continue

                # valid record
                # try to find parent folder
                parent_addr_seq = f'{usnrecord.par_addr}-{usnrecord.par_seq}'
                if parent_addr_seq in parent_folders:
                    usnrecord.parent_folder = parent_folders[parent_addr_seq]
                else:
                    parent: File = File.db_select_one(sqlite_files_cur, db_and(db_eq('meta_addr', usnrecord.par_addr),
                                                                               db_eq('meta_seq', usnrecord.par_seq),
                                                                               db_eq('is_dir', 1)))
                    if parent:
                        parent_folders[parent_addr_seq] = parent.parent_folder + '/' + parent.name
                        usnrecord.parent_folder = parent.parent_folder + '/' + parent.name
                    else:
                        parent_folders[parent_addr_seq] = ''
                if usnrecord.db_insert(sqlite_usn_cur):
                    record_count += 1

            if time.time() > last_time + 5:
                # update progress
                print(f'\r{record_count} records found...', end='')
                last_time = time.time()

        print(f'\r{" "*60}\r', end='')  # delete progress line
        sqlite_usn_con.commit()
        _logger.info(f'{record_count} usn records added for partition {partition.part_name}')

    _logger.info('preparing usn records finished')


@register_argument('-cusn', '--carve_usn', action='store_true', help='carve for ntfs usn journal entries and stores '
                                                                     'them in the same database as for the '
                                                                     '--prepare_usn argument', group_id='carve')
def carve_usnjournal(env: 'Environment') -> None:
    """
    carve partitions for usn journal entries in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only this partition is scanned.

    :param env: cli environment
    :type env: Environment
    :return: None
    :raise AttributeError: if image is None
    :raise IOError: if image is not scanned for files
    :raise ValueError: if USN journal is broken
    """
    image = env['image']
    part = env['args'].part
    meta_folder = env['meta_folder']

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('start carving usn journal')

    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part):
        _logger.info(f'carving usn journal in partition {partition.part_name}')

        try:
            sqlite_files_con, sqlite_files_cur = File.db_open(meta_folder, partition.part_name, False)
        except IOError:
            raise IOError('ERROR: No file database. Use --prepare_files first')

        sqlite_usn_con, sqlite_usn_cur = USNRecordV2.db_open(meta_folder, partition.part_name)

        parent_folders = {}
        count = 0
        usnrecord: USNRecordV2
        for usnrecord in partition.carve(usn_carver):
            parent_addr_seq = f'{usnrecord.par_addr}-{usnrecord.par_seq}'
            if parent_addr_seq in parent_folders:
                usnrecord.parent_folder = parent_folders[parent_addr_seq]
            else:
                parent: File = File.db_select_one(sqlite_files_cur,
                                                  db_and(db_eq('meta_addr', usnrecord.par_addr),
                                                         db_eq('meta_seq', usnrecord.par_seq),
                                                         db_eq('is_dir', 1)))
                if parent:
                    parent_folders[parent_addr_seq] = parent.parent_folder + '/' + parent.name
                    usnrecord.parent_folder = parent.parent_folder + '/' + parent.name
                else:
                    parent_folders[parent_addr_seq] = ''
            if usnrecord.db_insert(sqlite_usn_cur):
                count += 1

        sqlite_usn_con.commit()
        _logger.info(f'{count} usn records added for partition {partition.part_name}')

    _logger.info('carving usn records finished')
