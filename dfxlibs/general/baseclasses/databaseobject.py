# coding: utf-8
"""
    dfxlibs: Metaclass for objects to store in databases

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

from typing import Dict, List, Any
from datetime import datetime
import sqlite3


class DatabaseObject:
    def db_fields(self) -> dict[str, Any]:
        return ({attr: self.__getattribute__(attr)
                 for attr in self.__dict__
                 if attr[0] != '_'})

    def db_types(self) -> Dict[str, type]:
        return ({attr: type(self.__getattribute__(attr))
                 for attr in self.__dict__
                 if attr[0] != '_'})

    @staticmethod
    def db_primary_key() -> List[str]:
        return []

    @staticmethod
    def db_index() -> List[str]:
        return []

    def db_create_insert(self):
        db_types = self.db_types()
        db_values = self.db_fields()
        insert_pre = f'INSERT INTO {self.__class__.__name__}'
        insert_fields = []
        insert_values = []
        for attr in db_types:
            if db_types[attr] is datetime:
                insert_fields.append(attr)
                insert_values.append(db_values[attr].isoformat())
                insert_fields.append(f'{attr}_unix')
                insert_values.append(db_values[attr].timestamp())
            elif db_types[attr] is bool:
                insert_fields.append(attr)
                insert_values.append(int(db_values[attr]))
            else:
                insert_fields.append(attr)
                insert_values.append(db_values[attr])

        return [f'{insert_pre} (' + ', '.join(insert_fields) + ') VALUES ('+', '.join(['?']*len(insert_values)) + ')',
                tuple(insert_values)]

    def db_create_update(self):
        db_types = self.db_types()
        db_values = self.db_fields()
        db_pk_fields = self.db_primary_key()
        update_pre = f'UPDATE {self.__class__.__name__} SET'
        where_fields = []
        where_values = []
        update_fields = []
        update_values = []
        for attr in db_types:
            if db_types[attr] is datetime:
                value = db_values[attr].isoformat()
                field = f'{attr}_unix'
                if field in db_pk_fields:
                    where_fields.append(field)
                    where_values.append(db_values[attr].timestamp())
                else:
                    update_fields.append(field)
                    update_values.append(db_values[attr].timestamp())
            elif db_types[attr] is bool:
                value = int(db_values[attr])
            else:
                value = db_values[attr]

            if attr in db_pk_fields:
                where_fields.append(attr)
                where_values.append(value)
            else:
                update_fields.append(attr)
                update_values.append(value)

        return [f'{update_pre} ' +
                ', '.join([f'{col} = ?' for col in update_fields]) +
                ' WHERE ' + ' AND '.join([f'{col} = ?' for col in where_fields]),
                tuple(update_values + where_values)]

    def db_create_table(self):
        static_mapping_python_to_sqlite = {'str': 'TEXT', 'int': 'BIGINT', 'float': 'REAL', 'bool': 'INT',
                                           'bytes': 'BLOB'}
        db_types = self.db_types()

        column_definitions = []
        for attribute in db_types:
            if db_types[attribute].__name__ in static_mapping_python_to_sqlite:
                column_definitions.append(f'{attribute} '
                                          f'{static_mapping_python_to_sqlite[db_types[attribute].__name__]}')
            elif db_types[attribute] is datetime:
                # special case: create unix timestamp and human readable timestamp
                column_definitions.append(f'{attribute}_unix REAL')
                column_definitions.append(f'{attribute} TEXT')
            else:
                raise AttributeError('Unexpected datatype: ' + db_types[attribute].__name__)
        if self.db_primary_key():
            pks = []
            for pk in self.db_primary_key():
                if db_types[pk] is datetime:
                    pks.append(pk)
                    pks.append(f'{pk}_unix')
                else:
                    pks.append(pk)
            column_definitions.append(f'PRIMARY KEY (' + ', '.join(pks) + ')')
        create_table = (f'CREATE TABLE IF NOT EXISTS {self.__class__.__name__} (' +
                        ', '.join(column_definitions) +
                        ')')

        create_index = []
        create_index_pre = f'CREATE INDEX IF NOT EXISTS {self.__class__.__name__}'
        for index in self.db_index():
            if db_types[index] is datetime:
                create_index.append(f'{create_index_pre}_{index} ON {self.__class__.__name__} ({index} COLLATE NOCASE)')
                create_index.append(f'{create_index_pre}_{index}_unix ON {self.__class__.__name__} ({index}_unix)')
            elif db_types[index] is str:
                create_index.append(f'{create_index_pre}_{index} ON {self.__class__.__name__} ({index} COLLATE NOCASE)')
            else:
                create_index.append(f'{create_index_pre}_{index} ON {self.__class__.__name__} ({index})')

        return [create_table, *create_index]

    @classmethod
    def db_factory(cls, cursor: sqlite3.Cursor, row: List):
        self = cls()
        db_types = self.db_types()
        for idx, col in enumerate(cursor.description):
            attr = col[0]
            try:
                if db_types[attr] is datetime:
                    value = datetime.fromisoformat(row[idx])
                elif db_types[attr] is bool:
                    value = row[idx] == 1
                else:
                    value = row[idx]
                setattr(self, attr, value)
            except KeyError:
                pass
        return self
