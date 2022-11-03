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

from typing import Dict, List, Any, Tuple, Generator, Union
from datetime import datetime
import os
import sqlite3
import logging

_logger = logging.getLogger(__name__)


classes_type_cache = dict()


class DatabaseObject:
    def db_fields(self) -> dict[str, Any]:
        return ({attr: self.__getattribute__(attr)
                 for attr in self.__dict__
                 if attr[0] != '_'})

    def db_types(self) -> Dict[str, type]:
        if self.__class__.__name__ not in classes_type_cache:
            classes_type_cache[self.__class__.__name__] = ({attr: type(self.__getattribute__(attr))
                                                            for attr in self.__dict__
                                                            if attr[0] != '_'})
        return classes_type_cache[self.__class__.__name__]

    @staticmethod
    def db_primary_key() -> List[str]:
        return []

    @staticmethod
    def db_index() -> List[str]:
        return []

    def _db_create_insert(self):
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

    def _db_create_update(self, update_attrs=None):
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
                elif update_attrs is None or attr in update_attrs:
                    update_fields.append(field)
                    update_values.append(db_values[attr].timestamp())
            elif db_types[attr] is bool:
                value = int(db_values[attr])
            else:
                value = db_values[attr]

            if attr in db_pk_fields:
                where_fields.append(attr)
                where_values.append(value)
            elif update_attrs is None or attr in update_attrs:
                update_fields.append(attr)
                update_values.append(value)

        return [f'{update_pre} ' +
                ', '.join([f'{col} = ?' for col in update_fields]) +
                ' WHERE ' + ' AND '.join([f'{col} = ?' for col in where_fields]),
                tuple(update_values + where_values)]

    def _db_create_table(self):
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
                create_index.append(f'{create_index_pre}_{index}_nc ON {self.__class__.__name__} '
                                    f'({index} COLLATE NOCASE)')
                create_index.append(f'{create_index_pre}_{index} ON {self.__class__.__name__} ({index})')
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

    def db_update(self, db_cur: sqlite3.Cursor, update_attrs: List[str] = None):
        """
        Updates database for this item

        :param db_cur: database cursor
        :type db_cur: sqlite3.Cursor
        :param update_attrs: optional list of fields to update (else update all fields)
        :type update_attrs: List[str]
        :return:
        """
        db_cur.execute(*self._db_create_update(update_attrs))

    def db_insert(self, db_cur: sqlite3.Cursor) -> bool:
        """
        insert item to database

        :param db_cur: database cursor
        :type db_cur: sqlite3.Cursor
        :return: False if insert failed (e.g. duplicate primary keys)
        """
        try:
            db_cur.execute(*self._db_create_insert())
            return True
        except sqlite3.IntegrityError:
            return False

    @classmethod
    def db_open(cls, meta_folder: str, part: str, create_if_not_exists: bool = True, generate_cursors_num: int = 1) \
            -> Tuple[Union[sqlite3.Connection, sqlite3.Cursor], ...]:
        """
        Opens database for objects and returns database connection and cursors as tuple

        :param meta_folder: name of the meta information folder to store/read databases
        :type meta_folder: str
        :param part: partition name in the format "X_Y"
        :type part: str
        :param create_if_not_exists: if False, check db existence first
        :type create_if_not_exists: bool
        :param generate_cursors_num: generate given number of db cursors and return them
        :type generate_cursors_num: int
        :return: database connection (first element) and generate_cursors_num cursors
        :rtype: Tuple[Union[sqlite3.Connection, sqlite3.Cursor], ...]
        :raise IOError: if database not exists and create_if_not_exists is False
        """
        file_db = os.path.join(meta_folder, f'{cls.__name__.lower()}_{part}.db')
        exists = os.path.isfile(file_db)
        if not create_if_not_exists and not exists:
            # database required
            raise IOError()

        # open database
        sqlite_con = sqlite3.connect(file_db)
        sqlite_con.row_factory = cls.db_factory
        if not exists:
            cursor = sqlite_con.cursor()
            for create_command in cls()._db_create_table():
                cursor.execute(create_command)
            sqlite_con.commit()
            _logger.info(f"create database {file_db}")

        cursors = [sqlite_con.cursor() for _ in range(generate_cursors_num)]
        return sqlite_con, *cursors

    @classmethod
    def _db_select(cls, db_cur: sqlite3.Cursor, db_filter: Tuple[str, Tuple] = None, force_index_column = None):
        query = f'SELECT * FROM {cls.__name__}'
        if force_index_column:
            if force_index_column not in cls.db_index():
                raise AttributeError('Attribute not indexed')
            query = f'{query} INDEXED BY {cls.__name__}_{force_index_column}'
        if db_filter is None:
            db_cur.execute(query)
        else:
            db_cur.execute(f'{query} WHERE {db_filter[0]}', db_filter[1])

    @classmethod
    def db_select(cls, db_cur: sqlite3.Cursor, db_filter: Tuple[str, Tuple] = None,
                  force_index_column: str = None) -> Generator:
        """
        Select objects from database and returns a generator to iterate over

        :param db_cur: database cursor
        :type db_cur: sqlite3.Cursor
        :param db_filter: Optional filter to use as where clause
        :type db_filter: Tuple[str, Tuple]
        :param force_index_column: Force to use the given column as index - otherwise let sqlite choose the index
        :type force_index_column: str
        :return: returns items from database to iterate over
        :raise AttributeError: if force_index_column is not indexed
        """
        cls._db_select(db_cur, db_filter, force_index_column)
        while (item := db_cur.fetchone()) is not None:
            yield item

    @classmethod
    def db_select_one(cls, db_cur: sqlite3.Cursor, db_filter: Tuple[str, Tuple] = None,
                      force_index_column: str = None) -> Any:
        """
        Select objects from database and returns the first

        :param db_cur: database cursor
        :type db_cur: sqlite3.Cursor
        :param db_filter: Optional filter to use as where clause
        :type db_filter: Tuple[str, Tuple]
        :param force_index_column: Force to use the given column as index - otherwise let sqlite choose the index
        :type force_index_column: str
        :return: returns the first item from database
        :raise AttributeError: if force_index_column is not indexed
        """
        cls._db_select(db_cur, db_filter, force_index_column)
        return db_cur.fetchone()
