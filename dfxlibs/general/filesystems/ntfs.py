# coding: utf-8
"""
   ntfs classes

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
import pytsk3
from datetime import datetime, timezone
from dfxlibs.windows.helpers import filetime_to_dt

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from dfxlibs.general.baseclasses.file import File


class VSSStore(pytsk3.Img_Info):
    def __init__(self, store):
        self._store = store
        super().__init__()

    def read(self, offset, size):
        self._store.seek(offset)
        return self._store.read(size)

    def get_size(self):
        return self._store.get_size()


class NtfsAds:
    def __init__(self, parent_file: 'File', name: str, size: int, attr_id: int):
        self.parent_file = parent_file
        self.name = name
        self.size = size
        self.attr_id = attr_id


class NTFSAttrFileName:
    def __init__(self, raw: bytes):
        parent_ref, crtime, mtime, ctime, atime, self.asize, self.size, self.flags, \
            self.ea_reparse, self.fname_len, self.fname_ns = struct.unpack('<7Q2I2B', raw[:66])
        self.par_seq = parent_ref >> 48
        self.par_addr = parent_ref & 0xffffff
        self.fname = struct.unpack(f'{self.fname_len*2}s', raw[66:66+self.fname_len*2])[0].decode('utf16')
        try:
            self.crtime = filetime_to_dt(crtime)
        except ValueError:
            self.crtime = datetime.fromtimestamp(0, tz=timezone.utc)

        try:
            self.mtime = filetime_to_dt(mtime)
        except ValueError:
            self.mtime = datetime.fromtimestamp(0, tz=timezone.utc)

        try:
            self.ctime = filetime_to_dt(ctime)
        except ValueError:
            self.ctime = datetime.fromtimestamp(0, tz=timezone.utc)

        try:
            self.atime = filetime_to_dt(atime)
        except ValueError:
            self.atime = datetime.fromtimestamp(0, tz=timezone.utc)

    def __repr__(self):
        return (f'<{self.__class__.__name__} ' +
                ' '.join([f'{attr}={repr(self.__getattribute__(attr))}'
                          for attr in self.__dict__
                          if self.__getattribute__(attr) is not None and attr[0] != '_']) +
                ' />')
