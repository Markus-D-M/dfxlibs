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


import pyscca
from typing import TYPE_CHECKING, List, Union, Iterator
import json
from datetime import datetime, timezone
import struct
from io import BytesIO

from dfxlibs.general.baseclasses.databaseobject import DatabaseObject
from dfxlibs.general.baseclasses.defaultclass import DefaultClass
from dfxlibs.windows.helpers import filetime_to_dt

if TYPE_CHECKING:
    from dfxlibs.general.baseclasses.file import File

PREFETCH_CARVER_OFFSET_STEP = 512


def prefetch_carver(current_data: bytes, current_offset: int) -> Iterator[Union[int, 'PrefetchFile']]:
    """
    Carving function for windows prefetch files in data buffers.

    :param current_data: data buffer
    :type current_data: bytes
    :param current_offset: current offset in the data buffer to analyse
    :type current_offset: int
    :return: Iterator for carved prefetch files or next offset to carve
    """
    try:
        candidate_offset = current_data.index(b'MAM', current_offset, -5*1024*1024)
    except ValueError:
        yield len(current_data)-5*1024*1024 + PREFETCH_CARVER_OFFSET_STEP
        return

    if candidate_offset % PREFETCH_CARVER_OFFSET_STEP != 0:
        yield candidate_offset - candidate_offset % PREFETCH_CARVER_OFFSET_STEP + PREFETCH_CARVER_OFFSET_STEP
        return

    current_offset = candidate_offset

    zero_size = 8  # looking for 8 zerobytes as file ending
    if current_data[current_offset:current_offset + 3] != b'MAM' or \
            current_data[current_offset + 7] != 0:
        yield current_offset + PREFETCH_CARVER_OFFSET_STEP
        return

    # candidate check:
    uncompressed_size = struct.unpack('<L', current_data[current_offset + 4:current_offset + 8])[0]

    # check for zeros
    zero_check_start = 0
    while zero_check_start < uncompressed_size:
        try:
            index_end = current_data[current_offset:current_offset + uncompressed_size].index(
                b'\0' * zero_size,
                zero_check_start
            )
        except ValueError:
            break
        try:
            pf = PrefetchFile(
                prefetch_file=BytesIO(current_data[current_offset:current_offset + index_end + 2]),
                carved=True)
            yield pf
            yield current_offset + PREFETCH_CARVER_OFFSET_STEP
            return
        except OSError:
            zero_check_start = index_end + zero_size
            continue
    # check sector end
    for i in range(uncompressed_size // PREFETCH_CARVER_OFFSET_STEP):
        try:
            pf = PrefetchFile(
                prefetch_file=BytesIO(current_data[current_offset:current_offset + i * PREFETCH_CARVER_OFFSET_STEP]),
                carved=True)
            yield pf
            yield current_offset + PREFETCH_CARVER_OFFSET_STEP
            return
        except OSError:
            pass
    yield current_offset + PREFETCH_CARVER_OFFSET_STEP


class PrefetchFile(DatabaseObject, DefaultClass):
    def __init__(self, prefetch_file: Union['File', 'BytesIO'] = None, carved: bool = False):
        self._prefetch_file = prefetch_file
        self.executable_filename = ''
        self.executable_addr = -1
        self.executable_seq = -1
        self.parent_folder = ''
        self.prefetch_hash = ''
        self.run_count = -1
        self.metrics = ''
        self.run_times = ''
        self.last_run = datetime.fromtimestamp(0, tz=timezone.utc)
        self.carved = carved

        if prefetch_file is not None:
            self._scca_file = pyscca.file()
            self._scca_file.open_file_object(self._prefetch_file)
            self.executable_filename = self._scca_file.executable_filename
            self.prefetch_hash = self._scca_file.prefetch_hash
            self.run_count = self._scca_file.run_count
            tmp = []
            metric: pyscca.file_metrics
            for metric in self._scca_file.file_metrics_entries:
                tmp.append({'filename': metric.filename, 'file_ref': metric.file_reference})
                fullname = metric.filename.split('\\', 2)[2]
                try:
                    parent_folder, exe_name = fullname.rsplit('\\', 1)
                    parent_folder = '/' + parent_folder.replace('\\', '/')
                except ValueError:
                    parent_folder = '/'
                    exe_name = fullname
                if self.executable_filename == exe_name[:len(self.executable_filename)]:
                    self.parent_folder = parent_folder
                    self.executable_filename = exe_name
                    self.executable_addr = metric.file_reference & 0xffffffffffff
                    self.executable_seq = metric.file_reference >> 48
            self.metrics = json.dumps(tmp)

            tmp = []
            for i in range(8):
                try:
                    tmp.append(filetime_to_dt(self._scca_file.get_last_run_time_as_integer(i)).timestamp())
                except ValueError:
                    tmp.append(0)
            self.run_times = json.dumps(tmp)
            self.last_run = datetime.fromtimestamp(max(tmp), tz=timezone.utc)

    def get_run_times(self) -> List[int]:
        return json.loads(self.run_times)

    @staticmethod
    def db_index():
        return ['executable_addr', 'parent_folder']

    @staticmethod
    def db_primary_key():
        return ['executable_filename', 'prefetch_hash', 'last_run']
