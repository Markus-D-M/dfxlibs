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

from datetime import datetime, timezone

from dfxlibs.general.baseclasses.databaseobject import DatabaseObject
from dfxlibs.general.baseclasses.defaultclass import DefaultClass


class Executes(DatabaseObject, DefaultClass):
    def __init__(self, executable_filename: str = '', executable_addr: int = -1, executable_seq: int = -1,
                 parent_folder: str = '', prefetch_hash: str = '',
                 run_time: datetime = datetime.fromtimestamp(0, tz=timezone.utc), carved: bool = False):
        self.executable_filename = executable_filename
        self.executable_addr = executable_addr
        self.executable_seq = executable_seq
        self.parent_folder = parent_folder
        self.prefetch_hash = prefetch_hash
        self.run_time = run_time
        self.carved = carved

    @staticmethod
    def db_index():
        return ['executable_addr', 'parent_folder']

    @staticmethod
    def db_primary_key():
        return ['executable_filename', 'prefetch_hash', 'run_time']
