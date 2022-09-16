# coding: utf-8
"""
    filter functions to use on databaseobjects select and select_one function

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

from typing import Tuple, List


def db_and(*args: Tuple[str, Tuple[any]]) -> Tuple[str, Tuple]:
    """
    creates "and" concatenation to use in databaseoobjects select and select_one function

    Takes multiple Tuple[str, Tuple] parameters from comparisons as input

    :return: filter value to use in databaseoobjects select and select_one function
    :rtype: Tuple[str, Tuple]
    """
    filter_strings = []
    filter_values = ()
    for param in args:
        filter_strings.append(param[0])
        filter_values += param[1]
    return '(' + ' and '.join(filter_strings) + ')', filter_values


def db_or(*args: Tuple[str, Tuple[any]]) -> Tuple[str, Tuple]:
    """
    creates "or" concatenation to use in databaseoobjects select and select_one function

    Takes multiple Tuple[str, Tuple] parameters from comparisons as input

    :return: filter value to use in databaseoobjects select and select_one function
    :rtype: Tuple[str, Tuple]
    """
    filter_strings = []
    filter_values = ()
    for param in args:
        filter_strings.append(param[0])
        filter_values += param[1]
    return '(' + ' or '.join(filter_strings) + ')', filter_values


def db_in(field: str, value: List) -> Tuple[str, Tuple]:
    """
    creates " in " comparison to use in databaseoobjects select and select_one function

    :param field: name of database field
    :type field: str
    :param value: list of values to filter
    :type value: List
    :return: filter value to use in databaseoobjects select and select_one function
    :rtype: Tuple[str, Tuple]
    """
    return f'{field} IN ({", ".join("?"*len(value))})', (*value,)


def db_eq(field: str, value: any) -> Tuple[str, Tuple]:
    """
    creates "=" comparison to use in databaseoobjects select and select_one function

    :param field: name of database field
    :type field: str
    :param value: value to filter
    :type value: any
    :return: filter value to use in databaseoobjects select and select_one function
    :rtype: Tuple[str, Tuple]
    """
    return f'{field} = ?', (value, )


def db_ne(field: str, value: any) -> Tuple[str, Tuple]:
    """
    creates "!=" comparison to use in databaseoobjects select and select_one function

    :param field: name of database field
    :type field: str
    :param value: value to filter
    :type value: any
    :return: filter value to use in databaseoobjects select and select_one function
    :rtype: Tuple[str, Tuple]
    """
    return f'{field} != ?', (value, )


def db_gt(field: str, value: any) -> Tuple[str, Tuple]:
    """
    creates ">" comparison to use in databaseoobjects select and select_one function

    :param field: name of database field
    :type field: str
    :param value: value to filter
    :type value: any
    :return: filter value to use in databaseoobjects select and select_one function
    :rtype: Tuple[str, Tuple]
    """
    return f'{field} > ?', (value, )


def db_ge(field: str, value: any) -> Tuple[str, Tuple]:
    """
    creates ">=" comparison to use in databaseoobjects select and select_one function

    :param field: name of database field
    :type field: str
    :param value: value to filter
    :type value: any
    :return: filter value to use in databaseoobjects select and select_one function
    :rtype: Tuple[str, Tuple]
    """
    return f'{field} >= ?', (value, )


def db_lt(field: str, value: any) -> Tuple[str, Tuple]:
    """
    creates "<" comparison to use in databaseoobjects select and select_one function

    :param field: name of database field
    :type field: str
    :param value: value to filter
    :type value: any
    :return: filter value to use in databaseoobjects select and select_one function
    :rtype: Tuple[str, Tuple]
    """
    return f'{field} < ?', (value, )


def db_le(field: str, value: any) -> Tuple[str, Tuple]:
    """
    creates "<=" comparison to use in databaseoobjects select and select_one function

    :param field: name of database field
    :type field: str
    :param value: value to filter
    :type value: any
    :return: filter value to use in databaseoobjects select and select_one function
    :rtype: Tuple[str, Tuple]
    """
    return f'{field} <= ?', (value, )


def db_like(field: str, value: any) -> Tuple[str, Tuple]:
    """
    creates "like" comparison to use in databaseoobjects select and select_one function

    :param field: name of database field
    :type field: str
    :param value: value to filter
    :type value: any
    :return: filter value to use in databaseoobjects select and select_one function
    :rtype: Tuple[str, Tuple]
    """
    return f'{field} like ?', (value, )


def db_nlike(field: str, value: any) -> Tuple[str, Tuple]:
    """
    creates "not like" comparison to use in databaseoobjects select and select_one function

    :param field: name of database field
    :type field: str
    :param value: value to filter
    :type value: any
    :return: filter value to use in databaseoobjects select and select_one function
    :rtype: Tuple[str, Tuple]
    """
    return f'{field} not like ?', (value, )
