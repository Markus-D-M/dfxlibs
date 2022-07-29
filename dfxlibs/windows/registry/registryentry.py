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

from typing import List, Any
from datetime import datetime
from json import loads


from dfxlibs.general.baseclasses.databaseobject import DatabaseObject


class RegistryEntry(DatabaseObject):
    def __init__(self, timestamp: datetime, key: str, value_name: str,
                 value_type: str, value_content: str):
        self.timestamp = timestamp
        self.key = key
        self.value_name = value_name
        self.value_type = value_type
        self.value_content = value_content

    def get_real_value(self):
        return loads(self.value_content)

    @staticmethod
    def db_primary_key() -> List[str]:
        return ['key', 'value_name']

    def __repr__(self):
        return (f'<{self.__class__.__name__} ' +
                ' '.join([f'{attr}={repr(self.__getattribute__(attr))}'
                          for attr in self.__dict__
                          if self.__getattribute__(attr) is not None and attr[0] != '_']) +
                ' />')
