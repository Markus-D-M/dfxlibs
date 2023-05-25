# coding: utf-8
"""
   support qcow2 file format

   Copyright 2022 Markus D (mar.d@gmx.net)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

import pytsk3
import pyvmdk


class Vmdk(pytsk3.Img_Info):
    magic = b'KDMV'

    def __init__(self, filenames):
        self._vmdk_handle = pyvmdk.handle()
        self._vmdk_handle.open(filenames[0])
        self._vmdk_handle.open_extent_data_files()
        super().__init__()

    def close(self):
        self._vmdk_handle.close()

    def read(self, offset, size):
        self._vmdk_handle.seek(offset)
        return self._vmdk_handle.read(size)

    def get_size(self):
        return self._vmdk_handle.get_media_size()
