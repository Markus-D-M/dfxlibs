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
from typing import Generator
import logging

from dfxlibs.general.baseclasses.defaultclass import DefaultClass
from dfxlibs.windows.registry.registryentry import RegistryEntry
from dfxlibs.general.helpers.db_filter import db_and, db_eq, db_like, db_or
from dfxlibs.windows.registry.registryinfo import Autorun

_logger = logging.getLogger(__name__)


class USER(DefaultClass):
    def __init__(self, db_reg_cur: 'sqlite3.Cursor'):
        check_key = RegistryEntry.db_select_one(db_reg_cur, db_eq('parent_key', 'HKU'))
        if check_key is None:
            raise ValueError('no user hive found')
        self._db_reg_cur = db_reg_cur

    def get_autoruns(self, autoruns=None):
        if autoruns is None:
            autoruns = list()

        reg_runkey: Generator[RegistryEntry] = RegistryEntry.db_select(self._db_reg_cur,
                                                                       db_filter=db_or(db_like('parent_key',
                                                                                               'HKU\\%\\Software\\'
                                                                                               'Microsoft\\Windows\\'
                                                                                               'CurrentVersion'
                                                                                               '\\Run'),
                                                                                       db_like('parent_key',
                                                                                               'HKU\\%\\Software\\'
                                                                                               'Microsoft\\Windows\\'
                                                                                               'CurrentVersion\\RunOnce'
                                                                                               ),
                                                                                       db_eq('parent_key',
                                                                                             'HKU\\%\\Software\\'
                                                                                             'Microsoft\\Windows\\'
                                                                                             'CurrentVersion\\Policies'
                                                                                             '\\Explorer\\Run')
                                                                                       ))
        for run in reg_runkey:
            _, user, _ = run.parent_key.split('\\', maxsplit=2)
            ar = Autorun(description=run.name, commandline=run.get_real_value(),
                         source=run.parent_key + '\\' + run.name, ar_type='Registry RunKey', user=user)
            autoruns.append(ar)
        return autoruns

    def get_user_infos(self, user_list=None):
        if user_list is None:
            user_list = dict()
        reg_mounts: Generator[RegistryEntry] = RegistryEntry.db_select(self._db_reg_cur,
                                                                       db_filter=db_and(
                                                                             db_like('parent_key',
                                                                                     'HKU\\%\\Network\\%'),
                                                                             db_eq('name', 'RemotePath'),
                                                                         ))

        for reg_mount in reg_mounts:
            parts = reg_mount.parent_key.split('\\')
            if len(parts) != 4:
                continue
            sid = parts[1]
            driveletter = parts[3]
            if sid not in user_list:
                user_list[sid] = dict()
            try:
                user_list[sid]['Network Mounts'].append(f'{driveletter}: {reg_mount.get_real_value()}')
            except KeyError:
                user_list[sid]['Network Mounts'] = [f'{driveletter}: {reg_mount.get_real_value()}']
        return user_list
