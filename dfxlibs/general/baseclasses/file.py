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

import pytsk3
from typing import TYPE_CHECKING, Optional, Iterator, List
from datetime import datetime, timezone
import struct


from .databaseobject import DatabaseObject
from dfxlibs.windows.helpers import filetime_to_dt

if TYPE_CHECKING:
    from dfxlibs.general.baseclasses.partition import Partition


class NtfsAds:
    def __init__(self, file: 'File', name: str, size: int, attr_id: int):
        self.file = file
        self.name = name
        self.size = size
        self.attr_id = attr_id


class File(DatabaseObject):
    def __init__(self, tsk3_file: pytsk3.File = None, parent_partition: 'Partition' = None):
        # self._full_name = '/' + path.lstrip('/')
        self._tsk3_file = tsk3_file
        self._parent_partition = parent_partition
        self._as_directory: Optional[pytsk3.Directory] = None
        self._ntfs_ads: List[NtfsAds] = []

        # file reading
        self._offset = 0

        # fillable by sleuth kit
        self.meta_addr = -1
        self.meta_seq = -1
        self.par_addr = -1
        self.par_seq = -1
        self.is_dir = False
        self.allocated = False
        self.size = -1
        self.name = ''
        self.atime = datetime.fromtimestamp(0, tz=timezone.utc)
        self.crtime = datetime.fromtimestamp(0, tz=timezone.utc)
        self.ctime = datetime.fromtimestamp(0, tz=timezone.utc)
        self.mtime = datetime.fromtimestamp(0, tz=timezone.utc)
        self.fn_atime = datetime.fromtimestamp(0, tz=timezone.utc)
        self.fn_crtime = datetime.fromtimestamp(0, tz=timezone.utc)
        self.fn_ctime = datetime.fromtimestamp(0, tz=timezone.utc)
        self.fn_mtime = datetime.fromtimestamp(0, tz=timezone.utc)

        # external information
        self.parent_folder = ''
        self.md5 = ''
        self.sha1 = ''
        self.sha256 = ''
        self.ssdeep = ''
        self.tlsh = ''
        self.first_bytes = b''
        self.file_type = ''
        self.source = ''

        if tsk3_file is not None:
            self.source = 'filesystem'
            if tsk3_file.info.name is not None:
                self.meta_addr = tsk3_file.info.name.meta_addr
                self.meta_seq = tsk3_file.info.name.meta_seq
                self.par_addr = tsk3_file.info.name.par_addr
                self.par_seq = tsk3_file.info.name.par_seq
                self.name = self._tsk3_file.info.name.name.decode('utf8')
                self.is_dir = tsk3_file.info.name.type == pytsk3.TSK_FS_NAME_TYPE_ENUM.TSK_FS_NAME_TYPE_DIR
                self.allocated = tsk3_file.info.name.flags == pytsk3.TSK_FS_NAME_FLAG_ENUM.TSK_FS_NAME_FLAG_ALLOC

            if tsk3_file.info.meta is not None:
                self.size = tsk3_file.info.meta.size
                self.meta_addr = tsk3_file.info.meta.addr
                self.meta_seq = tsk3_file.info.meta.seq

                self.atime = datetime.fromtimestamp(tsk3_file.info.meta.atime + tsk3_file.info.meta.atime_nano / 1e9,
                                                    tz=timezone.utc)
                self.crtime = datetime.fromtimestamp(tsk3_file.info.meta.crtime + tsk3_file.info.meta.crtime_nano / 1e9,
                                                     tz=timezone.utc)
                self.ctime = datetime.fromtimestamp(tsk3_file.info.meta.ctime + tsk3_file.info.meta.ctime_nano / 1e9,
                                                    tz=timezone.utc)
                self.mtime = datetime.fromtimestamp(tsk3_file.info.meta.mtime + tsk3_file.info.meta.mtime_nano / 1e9,
                                                    tz=timezone.utc)
                if self._parent_partition.type_id == pytsk3.TSK_FS_TYPE_NTFS:
                    # If NTFS -> get FNAME timestamps
                    for attr in tsk3_file:
                        if attr.info.type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_FNAME:
                            time2 = struct.unpack('4Q', tsk3_file.read_random(8, 32, attr.info.type, attr.info.id))
                            self.fn_crtime = filetime_to_dt(time2[0])
                            self.fn_mtime = filetime_to_dt(time2[1])
                            self.fn_ctime = filetime_to_dt(time2[2])
                            self.fn_atime = filetime_to_dt(time2[3])
                        if attr.info.type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA and attr.info.name:
                            self._ntfs_ads.append(NtfsAds(self, attr.info.name.decode('utf8'),
                                                          attr.info.size, attr.info.id))

            if self.is_dir and self.allocated:
                self._as_directory = self._tsk3_file.as_directory()

    @property
    def entries(self) -> Iterator['File']:
        if not self.is_dir and self.allocated:
            return
        for entry in self._as_directory:
            yield File(entry, self._parent_partition)

    def open(self, partition: 'Partition'):
        """
        'Opens' a file. This connects the file entry from the database to the partition of the image for reading the
        contents

        :param partition: Partition where the file is located
        :type partition: 'Partition'
        :return:
        """
        self._parent_partition = partition
        self._tsk3_file = partition.filesystem.open(self.parent_folder + self.name
                                                    if self.parent_folder == '/'
                                                    else self.parent_folder + '/' + self.name)
        self._offset = 0

    def seek(self, offset):
        self._offset = offset

    def read(self, size=-1) -> bytes:
        """
        Reads content of the file

        :param size: Number of bytes to read
        :type size: int
        :return: data from file
        :rtype: bytes
        :raise IOError: if file object is not connected to image
        """
        if self._tsk3_file is None:
            raise IOError('File object not connected to image. Call open() first.')

        to_read = size
        if to_read == -1 or to_read + self._offset > self.size:
            to_read = self.size - self._offset
        if to_read == 0:
            return b''
        data = self._tsk3_file.read_random(self._offset, to_read)
        self._offset = self._offset + to_read
        return data

    def __repr__(self):
        return (f'<{self.__class__.__name__} ' +
                ' '.join([f'{attr}={repr(self.__getattribute__(attr))}'
                          for attr in self.__dict__
                          if self.__getattribute__(attr) is not None and attr[0] != '_']) +
                ' />')

    @property
    def ntfs_ads(self) -> Iterator['File']:
        for ads in self._ntfs_ads:
            new_attr = {attr: getattr(self, attr) for attr in ['parent_folder', 'meta_addr', 'meta_seq', 'source',
                                                               'par_addr', 'par_seq', 'allocated', 'ctime']}
            new_attr['size'] = ads.size
            new_attr['name'] = f'{self.name}:{ads.name}'
            file_ads = File.from_values(**new_attr)
            yield file_ads

    @classmethod
    def from_values(cls, **kwargs):
        self = cls()
        for arg in kwargs:
            self.__setattr__(arg, kwargs[arg])
        return self

    @staticmethod
    def db_index():
        return ['meta_addr', 'meta_seq', 'par_addr', 'par_seq', 'name', 'parent_folder', 'md5', 'sha1',
                'sha256', 'ssdeep', 'tlsh', 'atime', 'ctime', 'crtime', 'mtime']

    @staticmethod
    def db_primary_key() -> List[str]:
        return ['meta_addr', 'name', 'size', 'crtime', 'mtime', 'atime', 'ctime']
