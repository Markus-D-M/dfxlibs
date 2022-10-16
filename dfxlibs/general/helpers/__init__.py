# coding: utf-8
"""
    general helper functions and classes

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

from .excelwriter import ExcelWriter

__all__ = ['ExcelWriter', 'bytes_to_hr']


def bytes_to_hr(b: int) -> str:
    """
    Converts a given size in bytes to a human-readable string

    >>> bytes_to_hr(3)
    '3.0B'

    >>> bytes_to_hr(1024)
    '1.0KiB'

    >>> bytes_to_hr(1e15)
    '909.5TiB'


    :param b: size in bytes
    :type b: int
    :return: human readable string
    :rtype: str
    """
    labels = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB']
    n = 0
    while b >= 1024 and n < len(labels) - 1:
        b /= 1024
        n += 1
    return '%.1f%s' % (b, labels[n])
