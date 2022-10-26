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

from typing import List
from datetime import datetime, timezone
from json import loads, dumps


from dfxlibs.general.baseclasses.databaseobject import DatabaseObject
from dfxlibs.general.baseclasses.defaultclass import DefaultClass


class RegistryEntry(DatabaseObject, DefaultClass):
    @staticmethod
    def _value_to_json(value) -> str:
        if type(value) is bytes:
            value = value.hex()
        elif type(value) is datetime:
            try:
                value = value.timestamp()
            except OSError:
                value = 0
        return dumps(value)

    @staticmethod
    def _json_to_value(value, value_type) -> any:
        value = loads(value)
        if value_type == 'RegBin':
            value = bytes.fromhex(value)
        elif value_type == 'RegFileTime':
            value = datetime.fromtimestamp(value, tz=timezone.utc)
        return value

    def __init__(self, timestamp: datetime = datetime.fromtimestamp(0, tz=timezone.utc),
                 parent_key: str = '', name: str = '',
                 rtype: str = '', content: any = '', is_key: bool = False):
        self.timestamp = timestamp
        self.parent_key = parent_key
        self.is_key = is_key
        self.name = name
        self.rtype = rtype
        self.content = self._value_to_json(content)

    def get_real_value(self):
        return self._json_to_value(self.content, self.rtype)

    @staticmethod
    def db_primary_key() -> List[str]:
        return ['parent_key', 'name']
