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
import datetime
from typing import TYPE_CHECKING, List
from struct import unpack
from dfxlibs.windows.helpers import filetime_to_dt
from Registry import Registry

if TYPE_CHECKING:
    from dfxlibs.windows.registry import WindowsRegistry


class User:
    SPECIAL_SIDS = {
        'S-1-5-18': 'LocalSystem',
        'S-1-5-19': 'NT Authority (LocalService)',
        'S-1-5-20': 'Network Service'}

    def __init__(self,
                 sid: str = None,
                 rid: int = None,
                 name: str = None,
                 login_count: int = None,
                 lockout: datetime.datetime = None,
                 created: datetime.datetime = None,
                 lastlogin: datetime.datetime = None,
                 profile_path: str = None):
        self.sid = sid
        self.rid = rid
        if name is None and sid in self.SPECIAL_SIDS:
            self.name = self.SPECIAL_SIDS[sid]
        else:
            self.name = name
        self.login_count = login_count
        self.lockout = lockout
        self.created = created
        self.last_login = lastlogin
        self.profile_path = profile_path

    def __repr__(self):
        return (f'<{self.__class__.__name__} ' +
                ' '.join([f'{attr}={repr(self.__getattribute__(attr))}'
                          for attr in self.__dict__
                          if self.__getattribute__(attr) is not None and attr[0] != '_']) +
                ' />')


def users(self: 'WindowsRegistry') -> List[User]:
    key_profiles = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList'
    key_users = 'SAM\\SAM\\Domains\\Account\\Users'
    user_list = {}
    user_prefix = 'S-1-5-21'
    for key_sid in self._open(key_profiles).subkeys():
        sid: str = key_sid.name()
        user_list[sid] = {'profile_path': key_sid.value('ProfileImagePath').value(), 'sid': sid}
        if sid.startswith('S-1-5-21-'):
            user_prefix, rid = sid.rsplit('-', 1)
            user_list[sid]['rid'] = int(rid)
        try:
            user_list[key_sid.name()] = {'Guid': key_sid.value('Guid').value()}
        except Registry.RegistryValueNotFoundException:
            pass
    for name in self._open(key_users + '\\Names').subkeys():
        rid = name.value('(default)').value_type()
        sid = f'{user_prefix}-{rid}'
        if sid not in user_list:
            user_list[sid] = {'rid': rid, 'sid': sid}
        user_list[sid]['name'] = name.name()
    for user in self._open(key_users).subkeys():
        if user.name() == 'Names':
            continue
        rid = int(user.name(), 16)
        sid = f'{user_prefix}-{rid}'
        f = user.value('F').value()
        t_lockout, t_creation, t_lastlogin, logins = unpack('8xQ8xQ8xQ18xH', f[:6 * 8 + 18 + 2])
        user_list[sid]['login_count'] = logins
        try:
            user_list[sid]['lockout'] = filetime_to_dt(t_lockout)
        except ValueError:
            pass
        try:
            user_list[sid]['created'] = filetime_to_dt(t_creation)
        except ValueError:
            pass
        try:
            user_list[sid]['last_login'] = filetime_to_dt(t_lastlogin)
        except ValueError:
            pass
    return [User(**users[sid]) for sid in user_list]
