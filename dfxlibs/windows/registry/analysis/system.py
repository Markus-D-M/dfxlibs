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

import sqlite3
from typing import Optional, List, Generator
import logging

from dfxlibs.general.baseclasses.defaultclass import DefaultClass
from dfxlibs.windows.registry.registryentry import RegistryEntry
from dfxlibs.general.helpers.db_filter import db_and, db_eq
from dfxlibs.windows.autoruns import Autorun

_logger = logging.getLogger(__name__)


class SYSTEM(DefaultClass):
    def __init__(self, db_reg_cur: 'sqlite3.Cursor'):
        check_key = RegistryEntry.db_select_one(db_reg_cur, db_eq('parent_key', 'HKLM\\SYSTEM'))
        if check_key is None:
            raise ValueError('no system hive found')
        self._db_reg_cur = db_reg_cur
        self._boot_key: Optional[bytes] = None
        self._current_control_set: Optional[int] = None

    @property
    def current_control_set(self) -> int:
        if self._current_control_set is None:
            self._get_current_control_set()
        return self._current_control_set

    @property
    def boot_key(self) -> bytes:
        if self._boot_key is None:
            self._get_boot_key()
        return self._boot_key

    def _get_current_control_set(self):
        reg_entry: RegistryEntry = RegistryEntry.db_select_one(self._db_reg_cur,
                                                               db_filter=db_and(
                                                                   db_eq('parent_key', 'HKLM\\SYSTEM\\Select'),
                                                                   db_eq('name', 'Current')))
        if reg_entry:
            self._current_control_set = reg_entry.get_real_value()
        else:
            _logger.warning('unable to retrieve current control set')
            self._current_control_set = -1

    def _get_boot_key(self):
        if self.current_control_set == -1:
            _logger.warning('unable to retrieve boot key')
            self._boot_key = b''
            return

        bootkey_scrambled = ''
        for key_name in ['JD', 'Skew1', 'GBG', 'Data']:
            key_entry: RegistryEntry = RegistryEntry.db_select_one(self._db_reg_cur,
                                                                   db_filter=db_and(
                                                                       db_eq('parent_key',
                                                                             'HKLM\\SYSTEM\\ControlSet'
                                                                             f'{self.current_control_set:03d}'
                                                                             '\\Control\\Lsa'),
                                                                       db_eq('name', key_name)))
            bootkey_scrambled += key_entry.classname

        bootkey_scrambled = bytes.fromhex(bootkey_scrambled)
        bootkey_perm_matrix = [0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7]
        self._boot_key = bytes([bootkey_scrambled[bootkey_perm_matrix[i]] for i in range(len(bootkey_scrambled))])

    def get_autoruns(self, autoruns=None):
        if autoruns is None:
            autoruns = list()

        srv_key = f'HKLM\\SYSTEM\\ControlSet{self.current_control_set:03d}\\Services'
        reg_services: List[RegistryEntry] = [s for s in
                                             RegistryEntry.db_select(self._db_reg_cur,
                                                                     db_filter=db_eq('parent_key', srv_key))
                                             ]
        for reg_service in reg_services:
            srv = {'name': reg_service.name,
                   'Description': '',
                   'DisplayName': '',
                   'ImagePath': '',
                   'Start': -1,
                   'Type': -1}
            service_entry: Generator[RegistryEntry] = \
                RegistryEntry.db_select(self._db_reg_cur, db_filter=db_and(db_eq('parent_key',
                                                                                 f'{srv_key}\\{srv["name"]}')))
            for params in service_entry:
                for k in srv:
                    if k == params.name:
                        srv[k] = params.get_real_value()

            if srv['ImagePath'].startswith('\\??\\'):
                srv['ImagePath'] = srv['ImagePath'][4:]
            if srv['ImagePath'].lower().startswith('system32\\drivers'):
                srv['ImagePath'] = '%SystemRoot%\\' + srv['ImagePath']
            if srv['ImagePath'].lower().startswith('\\systemroot'):
                srv['ImagePath'] = '%SystemRoot%' + srv['ImagePath'][11:]

            if '\\svchost.exe ' in srv['ImagePath']:
                service_dll = RegistryEntry.db_select_one(self._db_reg_cur, db_filter=db_and(
                    db_eq('parent_key', f'{srv_key}\\{srv["name"]}\\Parameters'),
                    db_eq('name', 'ServiceDll')))
                if service_dll:
                    srv['ServiceDll'] = service_dll.get_real_value()
            if srv['Start'] in [0, 1, 2]:
                ar = Autorun(description=srv['name'],
                             commandline=srv['ServiceDll'] if 'ServiceDll' in srv else srv['ImagePath'],
                             source=f'{srv_key}\\{srv["name"]}',
                             ar_type='Registry Service')
                ar.add_info = f'Service Type: 0x{srv["Type"]:02x}'
                autoruns.append(ar)
        return autoruns
