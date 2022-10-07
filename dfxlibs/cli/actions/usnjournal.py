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

from struct import unpack
import time

from dfxlibs.general.image import Image
from dfxlibs.general.baseclasses.file import File
from dfxlibs.windows.usnjournal.usnrecordv2 import USNRecordV2
from dfxlibs.general.helpers.db_filter import db_eq, db_and


_logger = logging.getLogger(__name__)


def prepare_usnjournal(image: Image, meta_folder: str, part: str = None) -> None:
    """
    read windows usn journal entries in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only the journal of this partition is scanned

    :param image: image file
    :type image: Image
    :param meta_folder: name of the meta information folder to store/read file database
    :type meta_folder: str
    :param part: partition name in the format "X_Y"
    :type part: str
    :return: None
    :raise AttributeError: if image is None
    :raise IOError: if image is not scanned for files
    :raise ValueError: if USN journal is broken
    """
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
        # find first usn entry
        # step 1: jump to the middle of the file and check for data, repeat for halfs to get starting area
        offset = journal.size // 2
        chunksize = 0
        for i in range(20):
            chunksize = journal.size // (2 ** (i+1))
            journal.seek(offset)
            data = journal.read(1024).lstrip(b'\0')
            if data:
                offset = offset - (chunksize // 2)
            else:
                offset = offset + (chunksize // 2)

        # step 2: fine search for beginning of usn records
        if offset > chunksize:
            journal.seek(offset - chunksize)
        else:
            journal.seek(0)
        while journal.tell() < journal.size:
            data = journal.read(65536).lstrip(b'\0')
            if data:
                first_entry = journal.tell() - len(data)
                journal.seek(first_entry)
                break
        # step 3: parsing records
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


def carve_usnjournal(image: Image, meta_folder: str, part: str = None) -> None:
    """
    carve partitions for usn journal entries in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only this partition is scanned.

    :param image: image file
    :type image: Image
    :param meta_folder: name of the meta information folder to store/read file database
    :type meta_folder: str
    :param part: partition name in the format "X_Y"
    :type part: str
    :return: None
    :raise AttributeError: if image is None
    :raise IOError: if image is not scanned for files
    :raise ValueError: if USN journal is broken
    """
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

        data_count = 0
        partition_bytes_offset = 0
        chunk_size_mb = 50
        record_count = 0
        chunk_size = 1024 * 1024 * chunk_size_mb
        current_data = b''
        current_data_offset = 0
        last_round = False
        parent_folders = {}
        while not last_round:
            data_chunk = partition.read_buffer(chunk_size, partition_bytes_offset)
            partition_bytes_offset += len(data_chunk)
            data_count += 1
            if not data_chunk:
                data_chunk = b'\0' * chunk_size
                last_round = True
            current_data = current_data[current_data_offset:] + data_chunk
            current_data_offset = 0
            current_data_len = len(current_data)
            print(f'\r{data_count * chunk_size_mb}MiB...', end='')
            while current_data_len - current_data_offset > 0xffff:
                if current_data[current_data_offset:current_data_offset+2] == b'\0\0' or \
                        current_data[current_data_offset+2:current_data_offset+8] != b'\0\0\2\0\0\0':
                    # only check V2
                    current_data_offset += 8
                    continue

                file_pos = current_data_offset
                try:
                    rec_len = unpack('<I', current_data[current_data_offset:current_data_offset + 4])[0]
                    if rec_len < 60:
                        raise AttributeError
                    usnrecord: USNRecordV2 = USNRecordV2.from_raw(current_data[current_data_offset:current_data_offset + rec_len])
                    usnrecord.carved = True
                    current_data_offset += rec_len
                    # Adjust Offset
                    if current_data_offset % 8 != 0:
                        current_data_offset += 8 - (current_data_offset % 8)

                    # valid record found
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
                        record_count += 1
                except AttributeError:
                    current_data_offset = file_pos + 8

        print(f'\r{" "*60}\r', end='')  # delete progress line
        sqlite_usn_con.commit()
        _logger.info(f'{record_count} usn records added for partition {partition.part_name}')

    _logger.info('carving usn records finished')
