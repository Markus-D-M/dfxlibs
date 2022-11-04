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

from typing import List, Iterator, Union, TYPE_CHECKING
from datetime import datetime, timezone
from struct import unpack


from dfxlibs.general.baseclasses.defaultclass import DefaultClass
from dfxlibs.general.baseclasses.file import File
from dfxlibs.general.baseclasses.databaseobject import DatabaseObject
from dfxlibs.general.helpers.db_filter import db_eq, db_and
from dfxlibs.windows.helpers import MAX_FILETIME, EPOCH_AS_FILETIME, filetime_to_dt, ALL_FILE_ATTRIBUTE, \
    hr_file_attribute

if TYPE_CHECKING:
    import sqlite3


USN_CARVER_OFFSET_STEP = 8


def usn_carver(current_data: bytes, current_offset: int) -> Iterator[Union[int, 'USNRecordV2']]:
    """
    Carving function for usn records in data buffers.

    :param current_data: data buffer
    :type current_data: bytes
    :param current_offset: current offset in the data buffer to analyse
    :type current_offset: int
    :return: Iterator for carved usn record or next offset to carve
    """
    try:
        candidate_offset = current_data.index(b'\0\0\2\0\0\0', current_offset, -512)
    except ValueError:
        yield len(current_data)-512 + USN_CARVER_OFFSET_STEP
        return

    if candidate_offset % 8 != 2:
        yield candidate_offset - candidate_offset % 8 + USN_CARVER_OFFSET_STEP
        return

    current_offset = candidate_offset-2
    if current_data[current_offset:current_offset + 2] == b'\0\0' or \
            current_data[current_offset + 2:current_offset + 8] != b'\0\0\2\0\0\0':
        # only check V2
        yield current_offset + USN_CARVER_OFFSET_STEP

    try:
        rec_len = unpack('<I', current_data[current_offset:current_offset + 4])[0]
        if rec_len < 60:
            raise AttributeError
        usnrecord: USNRecordV2 = USNRecordV2.from_raw(current_data[current_offset:current_offset + rec_len])
        usnrecord.carved = True
        yield usnrecord
        yield current_offset + USN_CARVER_OFFSET_STEP
        return
    except AttributeError:
        pass
    yield current_offset + USN_CARVER_OFFSET_STEP


class USNRecordV2(DatabaseObject, DefaultClass):
    USN_REASON_BASIC_INFO_CHANGE = 0x00008000
    USN_REASON_CLOSE = 0x80000000
    USN_REASON_COMPRESSION_CHANGE = 0x00020000
    USN_REASON_DATA_EXTEND = 0x00000002
    USN_REASON_DATA_OVERWRITE = 0x00000001
    USN_REASON_DATA_TRUNCATION = 0x00000004
    USN_REASON_EA_CHANGE = 0x00000400
    USN_REASON_ENCRYPTION_CHANGE = 0x00040000
    USN_REASON_FILE_CREATE = 0x00000100
    USN_REASON_FILE_DELETE = 0x00000200
    USN_REASON_HARD_LINK_CHANGE = 0x00010000
    USN_REASON_INDEXABLE_CHANGE = 0x00004000
    USN_REASON_INTEGRITY_CHANGE = 0x00800000
    USN_REASON_NAMED_DATA_EXTEND = 0x00000020
    USN_REASON_NAMED_DATA_OVERWRITE = 0x00000010
    USN_REASON_NAMED_DATA_TRUNCATION = 0x00000040
    USN_REASON_OBJECT_ID_CHANGE = 0x00080000
    USN_REASON_RENAME_NEW_NAME = 0x00002000
    USN_REASON_RENAME_OLD_NAME = 0x00001000
    USN_REASON_REPARSE_POINT_CHANGE = 0x00100000
    USN_REASON_SECURITY_CHANGE = 0x00000800
    USN_REASON_STREAM_CHANGE = 0x00200000
    USN_REASON_TRANSACTED_CHANGE = 0x00400000
    USN_REASON_DESIRED_STORAGE_CLASS_CHANGE = 0x01000000  # not well documented, found via fsutil - see
    # https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_desired_storage_class_information

    ALL_USN_REASON = 0x00008000 | 0x80000000 | 0x00020000 | 0x00000002 | 0x00000001 | 0x00000004 | 0x00000400 | \
        0x00040000 | 0x00000100 | 0x00000200 | 0x00010000 | 0x00004000 | 0x00800000 | 0x00000020 | 0x00000010 | \
        0x00000040 | 0x00080000 | 0x00002000 | 0x00001000 | 0x00100000 | 0x00000800 | 0x00200000 | 0x00400000 | \
        0x01000000

    USN_REASON_DESCRIPTION = {
        USN_REASON_BASIC_INFO_CHANGE: 'Attr_Changed',
        USN_REASON_CLOSE: 'File_Closed',
        USN_REASON_COMPRESSION_CHANGE: 'Compression_Changed',
        USN_REASON_DATA_EXTEND: 'Data_Added',
        USN_REASON_DATA_OVERWRITE: 'Data_Overwritten',
        USN_REASON_DATA_TRUNCATION: 'Data_Truncated',
        USN_REASON_EA_CHANGE: 'Extended_Attr_Changed',
        USN_REASON_ENCRYPTION_CHANGE: 'Encryption_Changed',
        USN_REASON_FILE_CREATE: 'File_Created',
        USN_REASON_FILE_DELETE: 'File_Deleted',
        USN_REASON_HARD_LINK_CHANGE: 'Hard_Link_Changed',
        USN_REASON_INDEXABLE_CHANGE: 'Content_Indexed_Attr_Changed',
        USN_REASON_INTEGRITY_CHANGE: 'Integrity_Changed',
        USN_REASON_NAMED_DATA_EXTEND: 'Named_Data_Stream_Added',
        USN_REASON_NAMED_DATA_OVERWRITE: 'Named_Data_Stream_Overwritten',
        USN_REASON_NAMED_DATA_TRUNCATION: 'Named_Stream_Truncated',
        USN_REASON_OBJECT_ID_CHANGE: 'Object_ID_Changed',
        USN_REASON_RENAME_NEW_NAME: 'File_Renamed_New',
        USN_REASON_RENAME_OLD_NAME: 'File_Renamed_Old',
        USN_REASON_REPARSE_POINT_CHANGE: 'Reparse_Point_Changed',
        USN_REASON_SECURITY_CHANGE: 'Access_Right_Changed',
        USN_REASON_STREAM_CHANGE: 'Named_Stream_Changed',
        USN_REASON_TRANSACTED_CHANGE: 'Transacted_Change',
        USN_REASON_DESIRED_STORAGE_CLASS_CHANGE: 'Desired_Storage_Class_Changed'
    }

    USN_SOURCE_AUXILIARY_DATA = 0x00000002
    USN_SOURCE_DATA_MANAGEMENT = 0x00000001
    USN_SOURCE_REPLICATION_MANAGEMENT = 0x00000004
    USN_SOURCE_CLIENT_REPLICATION_MANAGEMENT = 0x00000008

    ALL_USN_SOURCE = USN_SOURCE_AUXILIARY_DATA | USN_SOURCE_DATA_MANAGEMENT | USN_SOURCE_REPLICATION_MANAGEMENT | \
        USN_SOURCE_CLIENT_REPLICATION_MANAGEMENT

    USN_SOURCE_DESCRIPTION = {
        USN_SOURCE_AUXILIARY_DATA: 'Aux_Data',
        USN_SOURCE_DATA_MANAGEMENT: 'Data_Managment',
        USN_SOURCE_REPLICATION_MANAGEMENT: 'Replication_Managment',
        USN_SOURCE_CLIENT_REPLICATION_MANAGEMENT: 'Client_Replication_Managment'
    }

    def __init__(self, timestamp: datetime = datetime.fromtimestamp(0, tz=timezone.utc),
                 file_addr: int = -1, file_seq: int = -1, par_addr: int = -1, par_seq: int = -1, usn: int = -1,
                 reason: str = '', source_info: str = '', sec_id: int = -1, file_attr: str = '', name: str = '',
                 parent_folder: str = '', carved: bool = False):
        self.timestamp = timestamp
        self.file_addr = file_addr
        self.file_seq = file_seq
        self.par_addr = par_addr
        self.par_seq = par_seq
        self.usn = usn
        self.reason = reason
        self.source_info = source_info
        self.sec_id = sec_id
        self.file_attr = file_attr
        self.name = name
        self.parent_folder = parent_folder
        self.carved = carved

    @classmethod
    def from_raw(cls, raw: bytes):
        file_addr, file_seq, par_addr, par_seq, usn, filetime, reason, source_info, sec_id, file_attr, fn_len, \
            fn_offset = unpack('<LxxHLxxHQQIIIIHH', raw[8:60])
        if filetime < EPOCH_AS_FILETIME or filetime > MAX_FILETIME:
            raise AttributeError(f'Invalid Timestamp {filetime}')
        timestamp = filetime_to_dt(filetime)
        if usn == 0:
            raise AttributeError('Invalid USN')
        if usn > 0x7fffffffffffffff:
            # hack to store values to db (SIGNED BIGINT)
            usn = usn - 0x10000000000000000

        if reason == 0 or reason & ~cls.ALL_USN_REASON:
            raise AttributeError(f'Invalid Reason {reason} (USN: {usn}/file: {file_addr}:{file_seq})')
        if file_attr == 0 or file_attr & ~ALL_FILE_ATTRIBUTE:
            raise AttributeError(f'Invalid File Attribute {file_attr}')
        if source_info > 0x0000000f:
            raise AttributeError('Invalid SourceInfo')
        if fn_len % 2 != 0 or fn_len == 0:
            raise AttributeError('Invalid filename length')
        if fn_offset + fn_len > len(raw):
            raise AttributeError('Invalid filename length')
        try:
            fname = raw[fn_offset: fn_offset + fn_len].decode('utf-16')
        except UnicodeDecodeError:
            raise AttributeError('Invalid filename')
        if '\0' in fname:
            raise AttributeError('Invalid filename')
        return cls(timestamp=timestamp, file_addr=file_addr, file_seq=file_seq, par_addr=par_addr, par_seq=par_seq,
                   usn=usn, reason=cls._reason_to_hr(reason), source_info=cls._source_to_hr(source_info), sec_id=sec_id,
                   file_attr=hr_file_attribute(file_attr), name=fname)

    def retrieve_parent_folder(self, parent_folder_buffer: dict, sqlite_files_cur: 'sqlite3.Cursor'):
        """
        Try to retrieve parent folder from buffer dict or file database

        :param parent_folder_buffer: list of parent folders already searched for (for performance)
        :type parent_folder_buffer: dict
        :param sqlite_files_cur: cursor to sqlite file database
        :type sqlite_files_cur: sqlite3.Cursor
        """
        # try to find parent folder
        parent_addr_seq = f'{self.par_addr}-{self.par_seq}'
        if parent_addr_seq in parent_folder_buffer:
            self.parent_folder = parent_folder_buffer[parent_addr_seq]
        else:
            # Optimize query (use only key column)
            parent: File
            for parent in File.db_select(sqlite_files_cur, db_and(db_eq('meta_addr', self.par_addr),
                                                                  db_eq('meta_seq', self.par_seq),
                                                                  db_eq('is_dir', 1)),
                                         force_index_column='meta_addr'):
                if parent.name == '/' and parent.parent_folder == '':
                    # root directory
                    parent_folder = parent.name
                else:
                    parent_folder = parent.parent_folder + '/' + parent.name
                parent_folder_buffer[parent_addr_seq] = parent_folder
                self.parent_folder = parent_folder
                break
            else:
                parent_folder_buffer[parent_addr_seq] = ''

    @classmethod
    def _reason_to_hr(cls, reason: int):
        result = []
        for flag in cls.USN_REASON_DESCRIPTION:
            if flag & reason:
                result.append(cls.USN_REASON_DESCRIPTION[flag])
        return ' / '.join(result)

    @classmethod
    def _source_to_hr(cls, source: int):
        result = []
        for flag in cls.USN_SOURCE_DESCRIPTION:
            if flag & source:
                result.append(cls.USN_SOURCE_DESCRIPTION[flag])
        if result:
            return ' / '.join(result)
        else:
            return 'Normal'

    @staticmethod
    def db_index():
        return ['name', 'timestamp', 'parent_folder', 'file_addr', 'file_seq', 'par_addr', 'par_seq']

    @staticmethod
    def db_primary_key() -> List[str]:
        return ['usn']
