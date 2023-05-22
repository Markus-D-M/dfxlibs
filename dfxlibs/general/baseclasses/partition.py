# coding: utf-8
"""
   generic partition class

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
import re
import os
import pyvshadow
import pybde
from typing import TYPE_CHECKING, Optional, Iterator, Tuple, Dict, Callable
from dfxlibs.general.baseclasses.file import File
from dfxlibs.general.baseclasses.defaultclass import DefaultClass
from dfxlibs.general.filesystems.ntfs import VSSStore, BitlockerVolume
from dfxlibs.general.helpers import bytes_to_hr
import logging
from time import time

if TYPE_CHECKING:
    from dfxlibs.general.image import Image

_logger = logging.getLogger(__name__)

MBR_PARTITION_TYPES = {
    0x01: 'FAT12',
    0x02: 'XENIX root',
    0x03: 'XENIX usr',
    0x04: 'FAT16 <32M',
    0x05: 'Extended',
    0x06: 'FAT16',
    0x07: 'HPFS/NTFS/exFAT',
    0x08: 'AIX',
    0x09: 'AIX bootable',
    0x0a: 'OS/2 Boot Manager',
    0x0b: 'W95 FAT32',
    0x0c: 'W95 FAT32 (LBA)',
    0x0e: 'W95 FAT16 (LBA)',
    0x0f: 'W95 Ext\'d(LBA)',
    0x10: 'OPUS',
    0x11: 'Hidden FAT12',
    0x12: 'Compaq diagnostics',
    0x14: 'Hidden FAT16 <32M',
    0x16: 'Hidden FAT16',
    0x17: 'Hidden HPFS/NTFS',
    0x18: 'AST SmartSleep',
    0x1b: 'Hidden W95 FAT32',
    0x1c: 'Hidden W95 FAT32 (LBA)',
    0x1e: 'Hidden W95 FAT16 (LBA)',
    0x24: 'NEC DOS',
    0x27: 'Hidden NTFS WinRE',
    0x39: 'Plan 9',
    0x3c: 'PartitionMagic recovery',
    0x40: 'Venix 80286',
    0x41: 'PPC PReP Boot',
    0x42: 'SFS',
    0x4d: 'QNX4.x',
    0x4e: 'QNX4.x 2nd part',
    0x4f: 'QNX4.x 3rd part',
    0x50: 'OnTrack DM',
    0x51: 'OnTrack DM6 Aux1',
    0x52: 'CP/M',
    0x53: 'OnTrack DM6 Aux3',
    0x54: 'OnTrackDM6',
    0x55: 'EZ-Drive',
    0x56: 'Golden Bow',
    0x5c: 'Priam Edisk',
    0x61: 'SpeedStor',
    0x63: 'GNU HURD or SysV',
    0x64: 'Novell Netware 286',
    0x65: 'Novell Netware 386',
    0x70: 'DiskSecure Multi-Boot',
    0x75: 'PC/IX',
    0x80: 'Old Minix',
    0x81: 'Minix / old Linux',
    0x82: 'Linux swap / Solaris',
    0x83: 'Linux',
    0x84: 'OS/2 hidden or Intel hibernation',
    0x85: 'Linux extended',
    0x86: 'NTFS volume set',
    0x87: 'NTFS volume set',
    0x88: 'Linux plaintext',
    0x8e: 'Linux LVM',
    0x93: 'Amoeba',
    0x94: 'Amoeba BBT',
    0x9f: 'BSD/OS',
    0xa0: 'IBM Thinkpad hibernation',
    0xa5: 'FreeBSD',
    0xa6: 'OpenBSD',
    0xa7: 'NeXTSTEP',
    0xa8: 'Darwin UFS',
    0xa9: 'NetBSD',
    0xab: 'Darwin boot',
    0xaf: 'HFS / HFS+',
    0xb7: 'BSDI fs',
    0xb8: 'BSDI swap',
    0xbb: 'Boot Wizard hidden',
    0xbc: 'Acronis FAT32 LBA',
    0xbe: 'Solaris boot',
    0xbf: 'Solaris',
    0xc1: 'DRDOS/sec (FAT-12)',
    0xc4: 'DRDOS/sec (FAT-16 < 32M)',
    0xc6: 'DRDOS/sec (FAT-16)',
    0xc7: 'Syrinx',
    0xda: 'Non-FS data',
    0xdb: 'CP/M / CTOS / ...',
    0xde: 'Dell Utility',
    0xdf: 'BootIt',
    0xe1: 'DOS access',
    0xe3: 'DOS R/O',
    0xe4: 'SpeedStor',
    0xea: 'Linux extended boot',
    0xeb: 'BeOS fs',
    0xee: 'GPT',
    0xef: 'EFI (FAT-12/16/32)',
    0xf0: 'Linux/PA-RISC boot',
    0xf1: 'SpeedStor',
    0xf4: 'SpeedStor',
    0xf2: 'DOS secondary',
    0xf8: 'EBBR protective',
    0xfb: 'VMware VMFS',
    0xfc: 'VMware VMKCORE',
    0xfd: 'Linux raid autodetect',
    0xfe: 'LANstep',
    0xff: 'BBT'}

TSK_FS_TYPE = {
    0x0001: 'NTFS',
    0x0002: 'FAT12',
    0x0004: 'FAT16',
    0x0008: 'FAT32',
    0x000a: 'EXFAT',
    0x0080: 'EXT2',
    0x0100: 'EXT3',
    0x0200: 'SWAP',
    0x0800: 'ISO9660',
    0x1000: 'HFS',
    0x2000: 'EXT4'
}


class PartitionWrapper:
    def __init__(self, source: 'Image', partition_info: pytsk3.TSK_VS_PART_INFO = None):
        self._source = source
        self.sector_size = self._source.sector_size
        self.sector_offset = 0
        self.sector_size = source.sector_size
        self.sector_count = source.size // self.sector_size

        if partition_info is not None:
            self.sector_offset = partition_info.start
            self.sector_count = partition_info.len
        self._last_byte_offset = (self.sector_offset + self.sector_count) * self.sector_size
        self._read_byte_offset = 0

    @property
    def bytes_size(self) -> int:
        return self.sector_count * self.sector_size

    def read(self, size: int = None):
        # checking partition boundaries
        if size is None:
            read_size = self.bytes_size - self._read_byte_offset
        else:
            read_size = min(size, self.bytes_size - self._read_byte_offset)

        if read_size == 0:
            return b''

        offset = min(self.sector_offset * self.sector_size + self._read_byte_offset, self._last_byte_offset)
        self._read_byte_offset += read_size
        data = self._source.handle.read(offset, read_size)
        return data

    def seek(self, offset, whence=os.SEEK_SET):
        if offset < 0 or offset > self.bytes_size:
            raise IOError('offset out of bounds')
        if whence == os.SEEK_SET:
            self._read_byte_offset = min(offset, self.bytes_size)
        elif whence == os.SEEK_CUR:
            self._read_byte_offset = min(self._read_byte_offset + offset, self.bytes_size)
        elif whence == os.SEEK_END:
            self._read_byte_offset = max(0, self.bytes_size - offset)
        else:
            raise RuntimeError('unknown whence value %s' % whence)

    def tell(self):
        return self._read_byte_offset


class Partition(DefaultClass):
    def __init__(self, source: 'Image', partition_info: pytsk3.TSK_VS_PART_INFO = None, bde_recovery: str = ''):
        self._source = source
        self._vss_volume = None
        self._vss_store_cache: Dict[int, Tuple[pyvshadow.store, pytsk3.FS_Info]] = {}
        self._decrypted: Optional[pybde.volume] = None
        self.sector_offset = 0
        self.sector_size = source.sector_size
        self.sector_count = source.size // self.sector_size
        self.flags = pytsk3.TSK_VS_PART_FLAG_ALLOC
        self.descr = ''
        self.type_id = 0
        self._filesystem: Optional[pytsk3.FS_Info]
        self.addr = 0
        self.slot_num = 0
        self.tag = 0
        self.table_num = 0
        self.last_inum = 0
        self.first_inum = 0
        self._read_byte_offset = 0
        self._add_info = []

        if partition_info is not None:
            self.sector_offset = partition_info.start
            self.sector_count = partition_info.len
            self.flags = partition_info.flags
            self.addr = partition_info.addr
            self.slot_num = partition_info.slot_num
            self.tag = partition_info.tag
            self.table_num = partition_info.table_num
            self.descr = partition_info.desc.decode('utf8')
            self._last_byte_offset = (self.sector_offset + self.sector_count) * self.sector_size
            if self.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC:
                try:
                    self.type_id = int(re.search(r'\(0x(.+)\)', self.descr).group(1), 16)
                    self.descr = MBR_PARTITION_TYPES[self.type_id]
                except (AttributeError, ValueError, KeyError):
                    pass

        if self.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
            self._decrypted = PartitionWrapper(source, partition_info)
            if pybde.check_volume_signature_file_object(self):
                self._decrypted = pybde.volume()
                if bde_recovery:
                    self._decrypted.set_recovery_password(bde_recovery)
                self._decrypted.open_file_object(PartitionWrapper(source, partition_info))
                self._decrypted.unlock()
                self._add_info.append('bitlocker')
                try:
                    self._filesystem = pytsk3.FS_Info(BitlockerVolume(self._decrypted))
                except OSError:
                    self._filesystem = None
                except RuntimeError:
                    self._filesystem = None
                    self._add_info.append('locked')
            else:
                try:
                    self._filesystem = pytsk3.FS_Info(source.handle, offset=self.sector_offset * self.sector_size)
                except OSError:
                    self._filesystem = None
            if self._filesystem is not None:
                self.last_inum = self._filesystem.info.last_inum
                self.first_inum = self._filesystem.info.first_inum
                self.sector_size = self._filesystem.info.dev_bsize
                self._last_byte_offset = (self.sector_offset + self.sector_count) * self.sector_size
                self.type_id = self._filesystem.info.ftype
                try:
                    self.descr = TSK_FS_TYPE[self.type_id]
                except KeyError:
                    pass
        else:
            self._filesystem = None

    @property
    def is_crypted(self) -> bool:
        return 'bitlocker' in self._add_info

    @property
    def part_name(self) -> str:
        return f'{self.slot_num}'

    @property
    def bytes_offset(self) -> int:
        return self.sector_offset * self.sector_size

    @property
    def bytes_size(self) -> int:
        return self.sector_count * self.sector_size

    @property
    def filesystem(self) -> pytsk3.FS_Info:
        if self._filesystem is not None:
            return self._filesystem
        else:
            raise AttributeError('Partition not allocated or filesystem unknown')

    def carve(self, carve_func: Callable[[bytes, int], Iterator[any]]) -> Iterator:
        data_count = 0
        chunk_size_mb = 50
        chunk_size = 1024 * 1024 * chunk_size_mb
        current_data = b''
        current_offset = 0
        last_round = False
        element_count = 0
        last_print = 0
        while not last_round:
            data_chunk = self.read(chunk_size)
            data_count += 1
            if not data_chunk:
                data_chunk = b'\0' * chunk_size
                last_round = True
            current_data = current_data[current_offset:] + data_chunk
            current_offset = 0
            current_data_len = len(current_data)

            while current_data_len - current_offset > 0xffffff:
                if last_print + 2 < time():
                    print(f'\r{bytes_to_hr(data_count * chunk_size)} '
                          f'({data_count*chunk_size/self.bytes_size*100:.2f}%)/'
                          f'{element_count} potential findings...          ', end='')
                    last_print = time()
                for element in carve_func(current_data, current_offset):
                    if type(element) is int:
                        current_offset = element
                        break
                    else:
                        element_count += 1
                        yield element
        print(f'\r{" " * 70}\r', end='')  # delete progress line

    def get_volume_shadow_copy_filesystems(self) -> Tuple[int, pyvshadow.store, Iterator[pytsk3.FS_Info]]:
        if self.type_id != pytsk3.TSK_FS_TYPE_NTFS:
            # NTFS only
            return
        if self._vss_volume is None:
            self._vss_volume = pyvshadow.volume()
            try:
                self._vss_volume.open_file_object(self)
            except IOError:
                self._vss_volume = None
                _logger.warning(f'Unable to parse volume shadow copies in partition {self.part_name}')
                return
        for i in range(self._vss_volume.number_of_stores):
            if i in self._vss_store_cache:
                return i, self._vss_store_cache[i][0], self._vss_store_cache[i][1]
            store: pyvshadow.store = self._vss_volume.get_store(i)
            filesystem = pytsk3.FS_Info(VSSStore(store))
            self._vss_store_cache[i] = (store, filesystem)
            yield i, store, filesystem

    def get_volume_shadow_copy_filesystem(self, store_id: int) -> pytsk3.FS_Info:
        if self.type_id != pytsk3.TSK_FS_TYPE_NTFS:
            # NTFS only
            raise TypeError('partition has no ntfs filesystem')
        if self._vss_volume is None:
            self._vss_volume = pyvshadow.volume()
            try:
                self._vss_volume.open_file_object(self)
            except IOError:
                self._vss_volume = None
                raise ValueError('unable to parse volume shadow copy')
        if store_id in self._vss_store_cache:
            return self._vss_store_cache[store_id][1]

        store: pyvshadow.store = self._vss_volume.get_store(store_id)
        filesystem = pytsk3.FS_Info(VSSStore(store))
        self._vss_store_cache[store_id] = (store, filesystem)
        return filesystem

    def read(self, size: int = None):
        # special case:
        # for decrypted and dumped bitlocker ntfs partitions there seems to be no backup volume header. Without it,
        # there is no possibility to parse shadow copies with the used lib. so if there is an attempt on a ntfs volume
        # to read the 512 bytes after the partition size in a single partition image, this function returns a copy of
        # the first sector
        if self.tell() == self.bytes_size and self._source.vstype == 'single partition' and size == 512 and \
                self.type_id == pytsk3.TSK_FS_TYPE_NTFS:
            return self._source.handle.read(self.sector_offset * self.sector_size, size)
        return self._decrypted.read(size)

    def seek(self, offset, whence=os.SEEK_SET):
        self._decrypted.seek(offset, whence)

    def tell(self):
        return self._decrypted.tell()

    def get_file(self, path: str = None, meta_addr: int = None) -> File:
        if self.filesystem is None:
            raise IOError('unknown filesystem')
        if path is None and meta_addr is None:
            raise AttributeError('neither path nor meta_addr given')
        if path is not None:
            try:
                return File(self._filesystem.open(path), self)
            except OSError:
                raise OSError('path not found')
        if meta_addr is not None:
            try:
                return File(self._filesystem.open_meta(meta_addr), self)
            except OSError:
                raise OSError('invalid meta addr')

    def __str__(self):
        return (
            f'Partition {self.addr}:\n'
            f'  {self.descr}\n'
        )
