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
from typing import Optional, Generator
from Crypto.Hash import SHA256, MD5, HMAC
from Crypto.Cipher import AES, ARC4, DES
import struct
import logging
from datetime import datetime, timezone

from dfxlibs.windows.helpers import filetime_to_dt
from dfxlibs.general.baseclasses.defaultclass import DefaultClass
from dfxlibs.windows.registry.registryentry import RegistryEntry
from dfxlibs.general.helpers.db_filter import db_and, db_eq, db_like, db_in

_logger = logging.getLogger(__name__)


class SOFTWARE(DefaultClass):
    def __init__(self, db_reg_cur: 'sqlite3.Cursor'):
        check_key = RegistryEntry.db_select_one(db_reg_cur, db_eq('parent_key', 'HKLM\\SOFTWARE'))
        if check_key is None:
            raise ValueError('no software hive found')
        self._db_reg_cur = db_reg_cur

    def get_user_infos(self, user_list=None):
        if user_list is None:
            user_list = dict()
        reg_profiles: Generator[RegistryEntry] = RegistryEntry.db_select(self._db_reg_cur,
                                                                         db_filter=db_and(
                                                                             db_like('parent_key',
                                                                                     'HKLM\\SOFTWARE\\Microsoft\\'
                                                                                     'Windows NT\\CurrentVersion\\'
                                                                                     'ProfileList\\S-1-5-21-%'),
                                                                             db_eq('name', 'ProfileImagePath'),
                                                                         ))
        for reg_profile in reg_profiles:
            _, sid = reg_profile.parent_key.rsplit('\\', 1)
            user_list[sid] = {'Profile Path': reg_profile.get_real_value()}
        return user_list