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
from datetime import datetime
from json import dumps


from dfxlibs.general.baseclasses.databaseobject import DatabaseObject


class Event(DatabaseObject):
    def __init__(self, timestamp: datetime, event_id: int, channel: str,
                 event_record_id: int, opcode: int, level: int, computer: str, user_id: str,
                 provider: str, data: dict, carved: bool = False):
        self.timestamp = timestamp
        self.event_id = event_id
        self.channel = channel
        self.event_record_id = event_record_id
        self.opcode = opcode
        self.level = level
        self.computer = computer
        self.user_id = user_id
        self.provider = provider
        self.data = dumps(data)
        self.carved = carved

    @staticmethod
    def db_index():
        return ['event_id', 'timestamp']

    @staticmethod
    def db_primary_key() -> List[str]:
        return ['channel', 'computer', 'event_record_id']

    def __repr__(self):
        return (f'<{self.__class__.__name__} ' +
                ' '.join([f'{attr}={repr(self.__getattribute__(attr))}'
                          for attr in self.__dict__
                          if self.__getattribute__(attr) is not None and attr[0] != '_']) +
                ' />')
