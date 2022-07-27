# coding: utf-8
"""
   windows helper functions and classes

   Copyright 2022 Markus D (mar.d@gmx.net)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

from datetime import datetime, timezone

HUNDREDS_OF_NANOSECONDS = 10e6
EPOCH_AS_FILETIME = 116444736e9

MAX_FILETIME = 151478208000000000


def filetime_to_dt(filetime: int) -> datetime:
    """
    Converts windows filetime to datetime object

    >>> filetime_to_dt(116444736000000000)
    datetime.datetime(1970, 1, 1, 0, 0)

    >>> filetime_to_dt(151478208000000000)
    datetime.datetime(2081, 1, 6, 0, 0)

    >>> filetime_to_dt(0)
    Traceback (most recent call last):
        ...
    ValueError: cannot convert filetime before 1970-01-01

    :param filetime: Windows filetime
    :type filetime: int
    :return: filetime as datetime
    :rtype: datetime.datetime
    :raise ValueError: if filetime is before unix epoch
    """
    if filetime < EPOCH_AS_FILETIME:
        raise ValueError('cannot convert filetime before 1970-01-01')
    return datetime.fromtimestamp((filetime-EPOCH_AS_FILETIME)/HUNDREDS_OF_NANOSECONDS, tz=timezone.utc)
