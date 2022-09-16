# coding: utf-8
"""
   windows helper functions and classes

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

from datetime import datetime, timezone

HUNDREDS_OF_NANOSECONDS = 10e6
EPOCH_AS_FILETIME = 116444736e9  # 1970-01-01
MAX_FILETIME = 151478208e9  # 2081-01-06 - use to check for valid date ranges (has to be updated in the future)


def filetime_to_dt(filetime: int) -> datetime:
    """
    Converts windows filetime to datetime object

    >>> filetime_to_dt(116444736000000000)
    datetime.datetime(1970, 1, 1, 0, 0)

    >>> filetime_to_dt(151478208000000000)
    datetime.datetime(2081, 1, 6, 0, 0)

    >>> filetime_to_dt(0)
    Traceback (most recent call last):
        ...
    ValueError: cannot convert filetime before 1970-01-01

    :param filetime: Windows filetime
    :type filetime: int
    :return: filetime as datetime
    :rtype: datetime.datetime
    :raise ValueError: if filetime is before unix epoch
    """
    if filetime < EPOCH_AS_FILETIME:
        raise ValueError('cannot convert filetime before 1970-01-01')
    return datetime.fromtimestamp((filetime-EPOCH_AS_FILETIME)/HUNDREDS_OF_NANOSECONDS, tz=timezone.utc)


FILE_ATTRIBUTE_ARCHIVE = 0x20
FILE_ATTRIBUTE_COMPRESSED = 0x800
FILE_ATTRIBUTE_DEVICE = 0x40
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_ENCRYPTED = 0x4000
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_INTEGRITY_STREAM = 0x8000
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
FILE_ATTRIBUTE_NO_SCRUB_DATA = 0x20000
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_READONLY = 0x1
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_ATTRIBUTE_SPARSE_FILE = 0x200
FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_TEMPORARY = 0x100
FILE_ATTRIBUTE_VIRTUAL = 0x10000

ALL_FILE_ATTRIBUTE = FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_DEVICE | \
                     FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_ENCRYPTED | FILE_ATTRIBUTE_HIDDEN | \
                     FILE_ATTRIBUTE_INTEGRITY_STREAM | FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | \
                     FILE_ATTRIBUTE_NO_SCRUB_DATA | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_READONLY | \
                     FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_RECALL_ON_OPEN | \
                     FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_SPARSE_FILE | FILE_ATTRIBUTE_SYSTEM | \
                     FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_VIRTUAL

FILE_ATTRIBUTE_DESCRIPTIONS = {
    FILE_ATTRIBUTE_ARCHIVE: 'Archive',
    FILE_ATTRIBUTE_COMPRESSED: 'Compressed',
    FILE_ATTRIBUTE_DEVICE: 'Device',
    FILE_ATTRIBUTE_DIRECTORY: 'Directory',
    FILE_ATTRIBUTE_ENCRYPTED: 'Encrypted',
    FILE_ATTRIBUTE_HIDDEN: 'Hidden',
    FILE_ATTRIBUTE_INTEGRITY_STREAM: 'Integrity_Stream',
    FILE_ATTRIBUTE_NORMAL: 'Normal',
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: 'Not_Content_Indexed',
    FILE_ATTRIBUTE_NO_SCRUB_DATA: 'No_Scrub_Data',
    FILE_ATTRIBUTE_OFFLINE: 'Offline',
    FILE_ATTRIBUTE_READONLY: 'ReadOnly',
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: 'Recall_On_Data_Access',
    FILE_ATTRIBUTE_RECALL_ON_OPEN: 'Recall_On_Open',
    FILE_ATTRIBUTE_REPARSE_POINT: 'Reparse_Point',
    FILE_ATTRIBUTE_SPARSE_FILE: 'Sparse',
    FILE_ATTRIBUTE_SYSTEM: 'System',
    FILE_ATTRIBUTE_TEMPORARY: 'Temporary',
    FILE_ATTRIBUTE_VIRTUAL: 'Virtual'
}


def hr_file_attribute(file_attribute: int) -> str:
    """
    Returns human readable descriptions for file attributes

    :param file_attribute: file attribute value
    :type file_attribute: int
    :return: human readable file attributes with ' / ' as separator
    :rtype str:
    """
    descr = []
    for flag in FILE_ATTRIBUTE_DESCRIPTIONS:
        if flag & file_attribute:
            descr.append(FILE_ATTRIBUTE_DESCRIPTIONS[flag])
    return ' / '.join(descr)
