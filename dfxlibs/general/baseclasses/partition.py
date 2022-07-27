# coding: utf-8
"""
   generic partition class

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
import re
from typing import TYPE_CHECKING, Optional
from dfxlibs.general.baseclasses.file import File

if TYPE_CHECKING:
    from dfxlibs.general.image import Image

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


class Partition:
    def __init__(self, source: 'Image', partition_info: pytsk3.TSK_VS_PART_INFO = None):
        self._source = source
        self.sector_offset = 0
        self.sector_count = source.size // source.sector_size
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

        if partition_info is not None:
            self.sector_offset = partition_info.start
            self.sector_count = partition_info.len
            self.flags = partition_info.flags
            self.addr = partition_info.addr
            self.slot_num = partition_info.slot_num
            self.tag = partition_info.tag
            self.table_num = partition_info.table_num
            self.descr = partition_info.desc.decode('utf8')
            if self.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC:
                try:
                    self.type_id = int(re.search(r'\(0x(.+)\)', self.descr).group(1), 16)
                    self.descr = MBR_PARTITION_TYPES[self.type_id]
                except (AttributeError, ValueError, KeyError):
                    pass

        if self.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
            self._filesystem = pytsk3.FS_Info(source.handle, offset=self.sector_offset * source.sector_size)
            self.last_inum = self._filesystem.info.last_inum
            self.first_inum = self._filesystem.info.first_inum
            source.sector_size = self._filesystem.info.dev_bsize
            self.type_id = self._filesystem.info.ftype
            try:
                self.descr = TSK_FS_TYPE[self.type_id]
            except KeyError:
                pass
        else:
            self._filesystem = None

    @property
    def bytes_offset(self) -> int:
        return self.sector_offset * self._source.sector_size

    @property
    def bytes_size(self) -> int:
        return self.sector_count * self._source.sector_size

    @property
    def filesystem(self) -> pytsk3.FS_Info:
        if self._filesystem is not None:
            return self._filesystem
        else:
            raise AttributeError('Partition not allocated or filesystem unknown')

    def get_file(self, path: str) -> File:
        if self.filesystem is None:
            raise IOError('unknown filesystem')
        try:
            return File(self._filesystem.open(path), self)
        except OSError:
            raise OSError('path not found')

    def __str__(self):
        return (
            f'Partition {self.addr}:\n'
            f'  {self.descr.decode("utf8")}\n'
        )

    def __repr__(self):
        return (f'<{self.__class__.__name__} ' +
                ' '.join([f'{attr}={repr(self.__getattribute__(attr))}'
                          for attr in self.__dict__
                          if self.__getattribute__(attr) is not None and attr[0] != '_']) +
                ' />')
