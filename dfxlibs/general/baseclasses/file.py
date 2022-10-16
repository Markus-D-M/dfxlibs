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
import logging
import os

from dfxlibs.general.baseclasses.databaseobject import DatabaseObject
from dfxlibs.general.baseclasses.defaultclass import DefaultClass

from dfxlibs.general.filesystems.ntfs import NtfsAds, NTFSAttrFileName


if TYPE_CHECKING:
    from dfxlibs.general.baseclasses.partition import Partition

_logger = logging.getLogger(__name__)


class File(DatabaseObject, DefaultClass):
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
        self.is_link = False
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
        self.tlsh = ''
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
                self.is_link = tsk3_file.info.name.type == pytsk3.TSK_FS_NAME_TYPE_ENUM.TSK_FS_NAME_TYPE_LNK
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
                    # If NTFS -> get FNAME timestamps and ads
                    for attr in tsk3_file:
                        if attr.info.type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_FNAME:
                            try:
                                attr_fname = NTFSAttrFileName(tsk3_file.read_random(0, attr.info.size,
                                                                                    attr.info.type, attr.info.id))
                            except (struct.error, UnicodeDecodeError):
                                continue
                            self.fn_crtime = attr_fname.crtime
                            self.fn_mtime = attr_fname.mtime
                            self.fn_ctime = attr_fname.ctime
                            self.fn_atime = attr_fname.atime
                        if attr.info.type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA and attr.info.name:
                            self._ntfs_ads.append(NtfsAds(self, attr.info.name.decode('utf8'),
                                                          attr.info.size, attr.info.id))

    @property
    def entries(self) -> Iterator['File']:
        """
        Retrieve the child entries for a directory

        :return: Iterator over File objects
        :rtype Iterator['File']:
        :raise IOError: if file object is not connected to an image
        """
        if self._parent_partition is None:
            raise IOError('File object not connected to image. Call open() first.')
        if not self.is_dir or not self.allocated:
            return

        if self._as_directory is None:
            self._as_directory = self._tsk3_file.as_directory()
        for entry in self._as_directory:
            #if entry.info.name.name.decode('utf8') in ['.', '..']:
            #    continue
            file = File(entry, self._parent_partition)
            file.source = self.source
            yield file

    def open(self, partition: 'Partition'):
        """
        'Opens' a file. This connects the file entry from the database to the partition of the image for reading the
        contents

        :param partition: Partition where the file is located
        :type partition: 'Partition'
        :return:
        """
        self._parent_partition = partition
        if self.source == 'filesystem':
            self._tsk3_file = partition.filesystem.open_meta(self.meta_addr)
        elif self.source.startswith('vss#'):
            _, store_id = self.source.split('#', 1)
            store_id = int(store_id)
            self._tsk3_file = partition.get_volume_shadow_copy_filesystem(store_id).open_meta(self.meta_addr)
        self._offset = 0

    def seek(self, offset: int, whence: int = os.SEEK_SET):
        """
        Sets the current position in the file.

        :param offset: number of bytes from the beginning of the file
        :type offset: int
        :param whence: This is optional and defaults to 0 which means absolute file positioning, other values are 1
        which means seek relative to the current position and 2 means seek relative to the file's end.
        :type whence: int
        :return:
        """
        if offset < 0 or offset > self.size:
            raise IOError('offset out of bounds')
        if whence == os.SEEK_SET:
            self._offset = min(offset, self.size)
        elif whence == os.SEEK_CUR:
            self._offset = min(self._offset + offset, self.size)
        elif whence == os.SEEK_END:
            self._offset = max(0, self.size - offset)
        else:
            raise RuntimeError('unknown whence value %s' % whence)

    def tell(self) -> int:
        """
        Returns the current position in the file.

        :return: current position in the file as number of bytes from the beginning
        :rtype int:
        """
        return self._offset

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

        attr_type = pytsk3.TSK_FS_ATTR_TYPE_DEFAULT
        attr_id = -1
        if ':' in self.name:
            # reading NTFS ADS
            name, ads = self.name.split(':', maxsplit=1)
            for attr in self._tsk3_file:
                if attr.info.type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA and attr.info.name and \
                        attr.info.name.decode('utf8') == ads:
                    attr_type = attr.info.type
                    attr_id = attr.info.id
                    break

        try:
            data = self._tsk3_file.read_random(self._offset, to_read, attr_type, attr_id)
        except OSError as e:
            # unable to extract data from image
            # reading sector by sector as far as it works
            data = b''
            read = 0
            while read < to_read:
                read_now = min(512, to_read - read)
                try:
                    data += self._tsk3_file.read_random(self._offset+read, read_now, attr_type, attr_id)
                except OSError:
                    _logger.warning(f'Error while reading {self.full_name}: '
                                    f'Can only extract {read} of {to_read} bytes')
                    to_read = read
                    break
                read += read_now

        self._offset = self._offset + to_read
        return data

    @property
    def full_name(self):
        if self.parent_folder == '/':
            return f'/{self.name}'
        else:
            return f'{self.parent_folder}/{self.name}'

    @property
    def ntfs_ads(self) -> Iterator['File']:
        for ads in self._ntfs_ads:
            new_attr = {attr: getattr(self, attr) for attr in ['parent_folder', 'meta_addr', 'meta_seq', 'source',
                                                               'par_addr', 'par_seq', 'allocated',
                                                               '_tsk3_file', '_parent_partition']}
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
                'sha256', 'tlsh', 'atime', 'ctime', 'crtime', 'mtime']

    @staticmethod
    def db_primary_key() -> List[str]:
        return ['meta_addr', 'name', 'parent_folder', 'size', 'crtime', 'mtime', 'atime', 'ctime']
