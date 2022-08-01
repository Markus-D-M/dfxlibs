# coding: utf-8
"""
   Image class for dfxlibs

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

from typing import List, Union
from os.path import isfile
import pytsk3
from dfxlibs.general.imageformats.ewf import Ewf
from dfxlibs.general.imageformats.qcow import QCow
from dfxlibs.general.baseclasses.partition import Partition
from dfxlibs.general.helpers import bytes_to_hr


class Image:
    """
    process a supported image format

    :param filenames: Image filenames
    :type filenames: Union[str, List[str]]
    :raise ValueError: No input files given
    :raise FileNotFoundError: Input file not found
    :raise IOError: Unknown file format
    """

    VS_TYPES = {0x00: 'autodetect', 0x01: 'DOS', 0x02: 'BSD', 0x08: 'Mac', 0x10: 'GPT', 0xffff: 'unsupported'}

    def __init__(self, filenames: Union[str, List[str]]):
        # convert input parameter to list if necessary
        if type(filenames) is str:
            filenames = [filenames]
        if len(filenames) == 0 or filenames[0] == '':
            raise ValueError('no input files given')
        # check if all files exists
        for filename in filenames:
            if not isfile(filename):
                raise FileNotFoundError('Input file not found: ' + filename)

        # determine input file format
        with open(filenames[0], 'rb') as fh:
            first8bytes = fh.read(8)
        if first8bytes == Ewf.magic:
            self._img_info = Ewf(filenames)
        elif first8bytes[:4] == QCow.magic:
            self._img_info = QCow(filenames)
        else:
            self._img_info = pytsk3.Img_Info(filenames[0])
            # raise IOError('Unknown file format')
        self.filenames: List[str] = filenames
        self.size = self._img_info.get_size()
        self._vol_info = None
        self.sector_size = 512  # Set to 512 as default value. Will be updated with new information if available
        try:
            self._vol_info = pytsk3.Volume_Info(self._img_info)
            self.vstype = self.VS_TYPES[self._vol_info.info.vstype]
            self.sector_size = self._vol_info.info.block_size
        except OSError:
            self.vstype = 'single partition'

    @property
    def partitions(self, part_flag=pytsk3.TSK_VS_PART_FLAG_ALLOC) -> List[Partition]:
        """
        shows partitions in an image

        :param part_flag: sleuthkit TSK_VS_PART_FLAG_ENUM, which partition types should be returned
        :type part_flag: int
        :return: partitions in the loaded source
        :rtype: List[Partition]
        """
        if self._vol_info:
            return [a for a in [Partition(self, p) for p in self._vol_info] if a.flags & part_flag]
        else:
            return [Partition(self)]

    @property
    def handle(self) -> pytsk3.Img_Info:
        return self._img_info

    def __str__(self):
        return (
            f'Image size: {bytes_to_hr(self.size)}\n'
            f'Partiton table format: {self.vstype}'
        )

    def __repr__(self):
        return (f'<{self.__class__.__name__} ' +
                ' '.join([f'{attr}={repr(self.__getattribute__(attr))}'
                          for attr in self.__dict__
                          if self.__getattribute__(attr) is not None and attr[0] != '_']) +
                ' />')
