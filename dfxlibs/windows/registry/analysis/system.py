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
from typing import Optional
import logging

from dfxlibs.general.baseclasses.defaultclass import DefaultClass
from dfxlibs.windows.registry.registryentry import RegistryEntry
from dfxlibs.general.helpers.db_filter import db_and, db_eq

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
