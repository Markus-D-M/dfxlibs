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
from json import dumps, loads


from dfxlibs.general.baseclasses.databaseobject import DatabaseObject
from dfxlibs.general.baseclasses.defaultclass import DefaultClass


class Timeline(DatabaseObject, DefaultClass):
    def __init__(self, timestamp: datetime = datetime.fromtimestamp(0, tz=timezone.utc),
                 event_source: str = '', event_type: str = '', message: str = '',
                 param1: str = '', param2: str = '', param3: str = '', param4: str = ''):
        self.timestamp = timestamp
        self.event_source = event_source
        self.event_type = event_type
        self.message = message
        self.param1 = param1
        self.param2 = param2
        self.param3 = param3
        self.param4 = param4

    @staticmethod
    def db_index():
        return ['timestamp', 'event_source', 'event_type', 'param1', 'param2', 'param3', 'param4']

    @staticmethod
    def db_primary_key() -> List[str]:
        return ['timestamp', 'event_source', 'event_type', 'param1', 'param2', 'param3', 'param4']
