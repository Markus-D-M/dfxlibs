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
import pytsk3

from dfxlibs.general.baseclasses.file import File
from dfxlibs.general.baseclasses.timeline import Timeline
from dfxlibs.windows.usnjournal.usnrecordv2 import USNRecordV2
from dfxlibs.general.helpers.db_filter import db_eq, db_and
from dfxlibs.cli.arguments import register_argument
from dfxlibs.cli.environment import env


_logger = logging.getLogger(__name__)


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
        sqlite_timeline_con, sqlite_timeline_cur = Timeline.db_open(meta_folder, partition.part_name)

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
        renames_old = dict()
        states_old = dict()
        while True:
            data = journal.read(65536).lstrip(b'\0')
            if data:
                if journal.tell() - len(data) - 8 < 0:
                    journal.seek(0)
                else:
                    journal.seek(journal.tell() - len(data) - 8)
                break
            if offset == journal.tell():
                break
            else:
                offset = journal.tell()

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
                    usnrecord: USNRecordV2 = USNRecordV2.from_raw(
                        read_buffer[read_buffer_offset:read_buffer_offset+rec_len])
                    read_buffer_offset += rec_len
                    if rec_len % 4 != 0:
                        to_align = 4 - (rec_len % 4)
                        if read_buffer[read_buffer_offset: read_buffer_offset + to_align].strip(b'\0'):
                            raise ValueError(f'non-zero bytes while aligning')
                        read_buffer_offset += to_align
                    # read_buffer = read_buffer[rec_len:]
                except AttributeError as e:
                    _logger.warning('Invalid USN Record: ' + str(e))
                    read_buffer_offset += 4
                    continue

                # valid record
                usnrecord.retrieve_parent_folder(parent_folders, sqlite_files_cur)
                if usnrecord.db_insert(sqlite_usn_cur):
                    record_count += 1
                # State tracking for timeline
                file_meta = f'{usnrecord.file_addr}-{usnrecord.file_seq}'
                if file_meta not in states_old:
                    new_states = usnrecord.hr_reason_to_int(usnrecord.reason)
                else:
                    new_states = ~states_old[file_meta] & usnrecord.hr_reason_to_int(usnrecord.reason)
                states_old[file_meta] = usnrecord.hr_reason_to_int(usnrecord.reason)
                if new_states & usnrecord.USN_REASON_FILE_CREATE:
                    tl = Timeline(timestamp=usnrecord.timestamp, event_source='usnjournal',
                                  event_type='FILE_CREATE',
                                  message=f'{usnrecord.full_name} created',
                                  param1=usnrecord.name, param2=usnrecord.parent_folder)
                    tl.db_insert(sqlite_timeline_cur)
                if new_states & usnrecord.USN_REASON_FILE_DELETE:
                    tl = Timeline(timestamp=usnrecord.timestamp, event_source='usnjournal',
                                  event_type='FILE_DELETE',
                                  message=f'{usnrecord.full_name} deleted',
                                  param1=usnrecord.name, param2=usnrecord.parent_folder)
                    tl.db_insert(sqlite_timeline_cur)
                if new_states & usnrecord.USN_REASON_RENAME_OLD_NAME:
                    renames_old[file_meta] = (usnrecord.name, usnrecord.parent_folder, usnrecord.full_name)
                if new_states & usnrecord.USN_REASON_RENAME_NEW_NAME and file_meta in renames_old:
                    tl = Timeline(timestamp=usnrecord.timestamp, event_source='usnjournal',
                                  event_type='FILE_RENAME',
                                  message=f'{renames_old[file_meta][2]} renamed to {usnrecord.full_name}',
                                  param1=usnrecord.name, param2=usnrecord.parent_folder,
                                  param3=renames_old[file_meta][0], param4=renames_old[file_meta][1])
                    tl.db_insert(sqlite_timeline_cur)
                    del renames_old[file_meta]
                if new_states & usnrecord.USN_REASON_CLOSE:
                    del states_old[file_meta]

            else:
                read_buffer_offset += 4
            if time.time() > last_time + 5:
                # update progress
                print(f'\r{record_count} records found...', end='')
                last_time = time.time()

        print(f'\r{" "*60}\r', end='')  # delete progress line
        sqlite_usn_con.commit()
        sqlite_timeline_con.commit()
        _logger.info(f'{record_count} usn records added for partition {partition.part_name}')

    _logger.info('preparing usn records finished')
