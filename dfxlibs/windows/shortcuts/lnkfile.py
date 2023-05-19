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
import struct
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943
# https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc


from typing import Union, Iterator
import json
from datetime import datetime, timezone
from io import BytesIO
import re
import warnings

from dfxlibs.general.baseclasses.databaseobject import DatabaseObject
from dfxlibs.general.baseclasses.defaultclass import DefaultClass
from dfxlibs.windows.helpers import filetime_to_dt
from LnkParse3 import lnk_file as LnkParser

from dfxlibs.general.baseclasses.file import File


def json_convert(v):
    if type(v) is datetime:
        return v.isoformat()
    return v


def fileid_to_dt(file_id: str) -> datetime:
    h = '0' + file_id[15] + file_id[16:18] + file_id[9:13] + file_id[:8]
    d = int.from_bytes(bytes.fromhex(h), byteorder="big") - 5748192000000000
    return filetime_to_dt(d)


LNK_CARVER_OFFSET_STEP = 512
LNK_MAGIC = b'\x4c\0\0\0\x01\x14\x02\0\0\0\0\0\xc0\0\0\0\0\0\0\x46'


def lnk_carver(current_data: bytes, current_offset: int) -> Iterator[Union[int, 'LnkFile']]:
    """
    Carving function for windows lnk files in data buffers.

    :param current_data: data buffer
    :type current_data: bytes
    :param current_offset: current offset in the data buffer to analyse
    :type current_offset: int
    :return: Iterator for carved prefetch files or next offset to carve
    """
    try:
        candidate_offset = current_data.index(LNK_MAGIC, current_offset, -5*1024*1024)
    except ValueError:
        yield len(current_data)-5*1024*1024 + LNK_CARVER_OFFSET_STEP
        return

    if candidate_offset % LNK_CARVER_OFFSET_STEP != 0:
        yield candidate_offset - candidate_offset % LNK_CARVER_OFFSET_STEP + LNK_CARVER_OFFSET_STEP
        return

    current_offset = candidate_offset

    if current_data[current_offset:current_offset + 20] != LNK_MAGIC or \
            current_data[current_offset+66:current_offset + 76] != b'\0\0\0\0\0\0\0\0\0\0':
        yield current_offset + LNK_CARVER_OFFSET_STEP
        return

    try:
        lnk_file = LnkFile(BytesIO(current_data[current_offset:current_offset + 4096]), carved=True)
        yield lnk_file
        yield current_offset + LNK_CARVER_OFFSET_STEP
        return
    except (struct.error, ValueError):
        pass
    yield current_offset + LNK_CARVER_OFFSET_STEP


class LnkFile(DatabaseObject, DefaultClass):
    def __init__(self, lnk_file: Union['File', 'BytesIO'] = None, carved: bool = False):
        self._lnk_file = lnk_file
        self.lnk_filename = ''
        self.lnk_parent_folder = ''
        self.target_crtime = datetime.fromtimestamp(0, tz=timezone.utc)
        self.target_atime = datetime.fromtimestamp(0, tz=timezone.utc)
        self.target_ctime = datetime.fromtimestamp(0, tz=timezone.utc)
        self.target_size = -1

        self.target_local_path = ''
        self.target_relative_path = ''
        self.drive_serial_number = ''
        self.drive_label = ''
        self.drive_type = ''
        self.drive_label = ''

        self.working_directory = ''
        self.command_line_arguments = ''
        self.description = ''

        self.tracker_hostname = ''
        self.tracker_vol_id = ''
        self.tracker_file_id = ''
        self.tracker_birth_vol_id = ''
        self.tracker_birth_file_id = ''
        self.tracker_birth_mac = ''
        self.tracker_birth_time = datetime.fromtimestamp(0, tz=timezone.utc)

        self.raw_data = ''
        self.carved = carved

        if type(lnk_file) is File:
            self.lnk_filename = lnk_file.name
            self.lnk_parent_folder = lnk_file.parent_folder

        if lnk_file:
            data = lnk_file.read()
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=UserWarning)
                self._lnk_parser = LnkParser(indata=data)
                lnk_dict = self._lnk_parser.get_json()
            self.raw_data = json.dumps(lnk_dict, default=json_convert)

            if lnk_dict['header']['creation_time']:
                self.target_crtime = lnk_dict['header']['creation_time']
            if lnk_dict['header']['accessed_time']:
                self.target_atime = lnk_dict['header']['accessed_time']
            if lnk_dict['header']['modified_time']:
                self.target_ctime = lnk_dict['header']['modified_time']
            self.target_size = lnk_dict['header']['file_size']

            try:
                self.target_local_path = lnk_dict['link_info']['local_base_path']
            except KeyError:
                pass
            try:
                self.drive_serial_number = lnk_dict['link_info']['location_info']['drive_serial_number']
            except KeyError:
                pass
            try:
                self.drive_type = lnk_dict['link_info']['drive_type']
            except KeyError:
                pass
            try:
                self.drive_label = lnk_dict['link_info']['volume_label']
            except KeyError:
                pass
            try:
                self.working_directory = lnk_dict['data']['working_directory']
            except KeyError:
                pass
            try:
                self.target_relative_path = lnk_dict['data']['relative_path']
            except KeyError:
                pass
            try:
                self.command_line_arguments = lnk_dict['data']['command_line_arguments']
            except KeyError:
                pass
            try:
                self.description = lnk_dict['data']['description']
            except KeyError:
                pass

            try:
                self.tracker_hostname = lnk_dict['extra']['DISTRIBUTED_LINK_TRACKER_BLOCK']['machine_identifier']
            except KeyError:
                pass
            try:
                self.tracker_hostname = lnk_dict['extra']['DISTRIBUTED_LINK_TRACKER_BLOCK']['machine_identifier']
            except KeyError:
                pass
            try:
                self.tracker_vol_id = lnk_dict['extra']['DISTRIBUTED_LINK_TRACKER_BLOCK']['droid_volume_identifier']
            except KeyError:
                pass
            try:
                self.tracker_file_id = lnk_dict['extra']['DISTRIBUTED_LINK_TRACKER_BLOCK']['droid_file_identifier']
            except KeyError:
                pass
            try:
                self.tracker_birth_vol_id = \
                    lnk_dict['extra']['DISTRIBUTED_LINK_TRACKER_BLOCK']['birth_droid_volume_identifier']
            except KeyError:
                pass
            try:
                self.tracker_birth_file_id = \
                    lnk_dict['extra']['DISTRIBUTED_LINK_TRACKER_BLOCK']['birth_droid_file_identifier']
                self.tracker_birth_mac = ':'.join(re.findall('..', self.tracker_birth_file_id[-12:]))
                self.tracker_birth_time = fileid_to_dt(self.tracker_birth_file_id)
            except (KeyError, ValueError):
                pass

    @property
    def command_line(self):
        return (self.target_local_path + ' ' + self.command_line_arguments).strip()

    @staticmethod
    def db_index():
        return ['lnk_filename', 'lnk_parent_folder', 'target_local_path', 'target_relative_path', 'target_crtime',
                'target_ctime', 'target_atime', 'tracker_hostname', 'tracker_vol_id', 'tracker_file_id',
                'tracker_birth_vol_id', 'tracker_birth_file_id', 'tracker_birth_mac', 'tracker_birth_time']

    @staticmethod
    def db_primary_key():
        return ['target_local_path', 'target_relative_path', 'command_line_arguments',
                'target_atime', 'target_ctime', 'target_crtime', 'tracker_vol_id', 'tracker_file_id']
