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
import sqlite3

from struct import unpack
import time
import pytsk3

from dfxlibs.general.baseclasses.file import File
from dfxlibs.windows.usnjournal.usnrecordv2 import USNRecordV2, usn_carver
from dfxlibs.general.helpers.db_filter import db_eq, db_and
from dfxlibs.cli.arguments import register_argument
from dfxlibs.cli.environment import env


_logger = logging.getLogger(__name__)


def _insert_usn_record(usnrecord: USNRecordV2, parent_folder_buffer: dict,
                       sqlite_files_cur: sqlite3.Cursor, sqlite_usn_cur: sqlite3.Cursor) -> int:
    """
    Supply parent folder to usnrecord an try to write it to the database.

    :param usnrecord: usnrecord to add to the database
    :type usnrecord: USNRecordV2
    :param parent_folder_buffer: list of parent folders already searched for (for performance)
    :type parent_folder_buffer: dict
    :param sqlite_files_cur: cursor to sqlite file database
    :type sqlite_files_cur: sqlite3.Cursor
    :param sqlite_usn_cur: cursor to sqlite usn database
    :type sqlite_usn_cur: sqlite3.Cursor
    :return: 1 if usnrecord was added to the database, 0 otherwise
    :rtype int:
    """
    if sqlite_files_cur is not None:
        # try to find parent folder
        parent_addr_seq = f'{usnrecord.par_addr}-{usnrecord.par_seq}'
        if parent_addr_seq in parent_folder_buffer:
            usnrecord.parent_folder = parent_folder_buffer[parent_addr_seq]
        else:
            # Optimize query (use only key column)
            parent: File
            for parent in File.db_select(sqlite_files_cur, db_and(db_eq('meta_addr', usnrecord.par_addr),
                                                                  db_eq('meta_seq', usnrecord.par_seq),
                                                                  db_eq('is_dir', 1)), force_index_column='meta_addr'):
                if parent.name == '/' and parent.parent_folder == '':
                    # root directory
                    parent_folder = parent.name
                else:
                    parent_folder = parent.parent_folder + '/' + parent.name
                parent_folder_buffer[parent_addr_seq] = parent_folder
                usnrecord.parent_folder = parent_folder
                break
            else:
                parent_folder_buffer[parent_addr_seq] = ''

    # insert to db
    if usnrecord.db_insert(sqlite_usn_cur):
        return 1
    else:
        return 0


@register_argument('-pusn', '--prepare_usn', action='store_true', help='reading ntfs usn journals and stores the '
                                                                       'entries in a sqlite database in the '
                                                                       'meta_folder. You can specify a partition with '
                                                                       '--part.', group_id='prepare')
def prepare_usnjournal() -> None:
    """
    read windows usn journal entries in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only the journal of this partition is scanned

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
    for partition in image.partitions(part_name=part, filesystem_typeid=pytsk3.TSK_FS_TYPE_NTFS):
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

        # find first usn entry
        # step 1: jump to the middle of the file and check for data, repeat for halfs to get starting area
        offset = journal.size // 2
        chunksize = 0
        for i in range(20):
            chunksize = journal.size // (2 ** (i + 1))
            journal.seek(offset)
            data = journal.read(512).lstrip(b'\0')
            if data:
                offset = offset - (chunksize // 2)
            else:
                offset = offset + (chunksize // 2)

        # step 2: fine search for beginning of usn records
        if offset > chunksize:
            journal.seek(offset - chunksize)
        else:
            journal.seek(0)
        while True:
            data = journal.read(65536).lstrip(b'\0')
            if data:
                if journal.tell() - len(data) - 8 < 0:
                    journal.seek(0)
                else:
                    journal.seek(journal.tell() - len(data) - 8)
                break

        last_time = time.time()  # for showing progress
        parent_folders = {}  # cache parent_folder searches
        record_count = 0
        cur_pos = journal.tell()
        # align to 8 byte boundary
        if cur_pos % 8 != 0:
            b = journal.read(8 - (cur_pos % 8)).strip(b'\0')
            if b:
                raise ValueError(f'non-zero bytes while aligning: {b}')
        read_buffer = journal.read(65536)
        read_buffer_offset = 0
        while True:
            if len(read_buffer) - read_buffer_offset < 65536:
                read_buffer = read_buffer[read_buffer_offset:] + journal.read(65536)
                read_buffer_offset = 0
            if len(read_buffer) < 8:
                break
            # skip zero bytes
            if read_buffer[read_buffer_offset:read_buffer_offset+4] == b'\0\0\0\0':
                read_buffer_offset += 4
                continue
            rec_len, = unpack('<I', read_buffer[read_buffer_offset:read_buffer_offset+4])
            ver = read_buffer[read_buffer_offset+4:read_buffer_offset+8]

            """# skip zero bytes
            dword = b'\0\0\0\0'
            while dword == b'\0\0\0\0':
                dword = journal.read(4)
            if len(dword) < 4:
                break
            rec_len,  = unpack('<I', dword)
            ver = journal.read(4)"""
            ver_major, ver_minor = unpack('<HH', ver)
            if ver_major == 2 and ver_minor == 0:
                try:
                    #usnrecord: USNRecordV2 = USNRecordV2.from_raw(dword + ver + journal.read(rec_len - 8))
                    usnrecord: USNRecordV2 = USNRecordV2.from_raw(
                        read_buffer[read_buffer_offset:read_buffer_offset+rec_len])
                    read_buffer_offset += rec_len
                    if rec_len % 4 != 0:
                        to_align = 4 - (rec_len % 4)
                        if read_buffer[read_buffer_offset: read_buffer_offset + to_align].strip(b'\0'):
                            raise ValueError(f'non-zero bytes while aligning: {b}')
                        read_buffer_offset += to_align
                    # read_buffer = read_buffer[rec_len:]
                except AttributeError as e:
                    _logger.warning('Invalid USN Record: ' + str(e))
                    read_buffer_offset += 4
                    continue

                # valid record
                record_count += _insert_usn_record(usnrecord, parent_folders, sqlite_files_cur, sqlite_usn_cur)
            else:
                read_buffer_offset += 4
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
def carve_usnjournal() -> None:
    """
    carve partitions for usn journal entries in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only this partition is scanned.

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
            # Don't find parents
            sqlite_files_con = None
            sqlite_files_cur = None

        sqlite_usn_con, sqlite_usn_cur = USNRecordV2.db_open(meta_folder, partition.part_name)

        parent_folders = {}
        count = 0
        usnrecord: USNRecordV2
        for usnrecord in partition.carve(usn_carver):
            count += _insert_usn_record(usnrecord, parent_folders, sqlite_files_cur, sqlite_usn_cur)

        sqlite_usn_con.commit()
        _logger.info(f'{count} usn records added for partition {partition.part_name}')

    _logger.info('carving usn records finished')
