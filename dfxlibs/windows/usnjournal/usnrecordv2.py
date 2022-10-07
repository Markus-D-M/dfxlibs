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

from typing import List
from datetime import datetime, timezone
from struct import unpack


from dfxlibs.general.baseclasses.databaseobject import DatabaseObject
from dfxlibs.windows.helpers import MAX_FILETIME, EPOCH_AS_FILETIME, filetime_to_dt, ALL_FILE_ATTRIBUTE, \
    hr_file_attribute


class USNRecordV2(DatabaseObject):
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

    ALL_USN_REASON = 0x00008000 | 0x80000000 | 0x00020000 | 0x00000002 | 0x00000001 | 0x00000004 | 0x00000400 | \
        0x00040000 | 0x00000100 | 0x00000200 | 0x00010000 | 0x00004000 | 0x00800000 | 0x00000020 | 0x00000010 | \
        0x00000040 | 0x00080000 | 0x00002000 | 0x00001000 | 0x00100000 | 0x00000800 | 0x00200000 | 0x00400000

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
        USN_REASON_TRANSACTED_CHANGE: 'Transacted_Change'
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
            raise AttributeError(f'Invalid Reason {reason}')
        if file_attr == 0 or file_attr & ~ALL_FILE_ATTRIBUTE:
            raise AttributeError(f'Invalid File Attribute {file_attr}')
        if source_info > 0x0000000f:
            raise AttributeError('Invalid SourceInfo')
        if fn_len % 2 != 0 or fn_len == 0:
            raise AttributeError('Invalid filename length')
        if fn_offset + fn_len > len(raw):
            raise AttributeError('Invalid filename length')
        try:
            fname = raw[fn_offset: fn_offset + fn_len].decode('utf16')
        except UnicodeDecodeError:
            raise AttributeError('Invalid filename')
        if '\0' in fname:
            raise AttributeError('Invalid filename')
        return cls(timestamp=timestamp, file_addr=file_addr, file_seq=file_seq, par_addr=par_addr, par_seq=par_seq,
                   usn=usn, reason=cls._reason_to_hr(reason), source_info=cls._source_to_hr(source_info), sec_id=sec_id,
                   file_attr=hr_file_attribute(file_attr), name=fname)

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

    def __repr__(self):
        return (f'<{self.__class__.__name__} ' +
                ' '.join([f'{attr}={repr(self.__getattribute__(attr))}'
                          for attr in self.__dict__
                          if self.__getattribute__(attr) is not None and attr[0] != '_']) +
                ' />')